#!/usr/bin/env python3
"""Packet capture (pcap/pcapng) to Timesketch timeline converter.

Parses raw network captures produced by Wireshark/tcpdump — both the
classic libpcap format and the newer block-based pcapng format — into one
Timesketch row per packet, decoded down to the Ethernet/Linux-SLL/raw-IP,
IPv4/IPv6, and TCP/UDP/ICMP/ARP headers. No TCP stream reassembly and no
multi-packet application-layer decoding is performed.
"""

from __future__ import annotations

import datetime
import heapq
import ipaddress
import json
import struct
import tempfile
from pathlib import Path
from typing import Any, Iterator

from .common import (
    AuditReport,
    ConverterError,
    OutputWriter,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal

# ---------------------------------------------------------------------------
# Format sniffing
# ---------------------------------------------------------------------------

_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".dmp"}

_MAGIC_US_BE = b"\xa1\xb2\xc3\xd4"  # classic pcap, big-endian, microsecond ts
_MAGIC_US_LE = b"\xd4\xc3\xb2\xa1"  # classic pcap, little-endian, microsecond ts
_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"  # classic pcap, big-endian, nanosecond ts
_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"  # classic pcap, little-endian, nanosecond ts
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # pcapng Section Header Block type (palindrome)

_ALL_MAGICS = {_MAGIC_US_BE, _MAGIC_US_LE, _MAGIC_NS_BE, _MAGIC_NS_LE, _PCAPNG_MAGIC}

# Link types we decode. Anything else is skipped per-packet with a warning.
_LINK_TYPE_NAMES = {1: "ethernet", 101: "raw_ip", 113: "linux_sll"}

_IP_PROTO_NAMES = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "icmpv6",
    132: "sctp",
}

# IPv6 extension header types walked to reach the real transport header.
_IPV6_EXT_HEADERS = {0, 43, 44, 60, 51}

_TCP_FLAG_BITS = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]

# Maximum number of capture files (or intermediate merge temp files) kept open
# at once by the k-way merge.  This caps the number of file descriptors the
# converter uses, preventing "Too many open files" errors on large captures.
_MAX_MERGE_STREAMS = 200


class PcapParseError(ConverterError):
    """Raised for a file/block-level capture corruption (caught per-file)."""


class _MalformedPacket(Exception):
    """Internal: a single packet's L2/L3 header could not be decoded."""


def _mac_str(data: bytes) -> str:
    return ":".join(f"{b:02x}" for b in data)


def _protocol_name(protocol_id: int) -> str:
    return _IP_PROTO_NAMES.get(protocol_id, "other")


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _looks_like_capture(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) in _ALL_MAGICS
    except OSError:
        return False


def _find_pcap_files(input_path: str) -> list[Path]:
    """Resolve the input path into a list of pcap/pcapng files.

    A single file is returned as-is. A directory is walked recursively;
    files are matched by extension, or by sniffing the magic bytes when the
    file has no recognized extension.
    """
    path = Path(input_path)

    if path.is_file():
        return [path]

    if path.is_dir():
        files: set[Path] = set()
        for candidate in path.rglob("*"):
            if not candidate.is_file():
                continue
            if candidate.suffix.lower() in _PCAP_EXTENSIONS:
                files.add(candidate)
            elif not candidate.suffix and _looks_like_capture(candidate):
                files.add(candidate)
        return sorted(files)

    raise ConverterError(f"Input path not found: {input_path}")


# ---------------------------------------------------------------------------
# Classic pcap parsing
# ---------------------------------------------------------------------------

def _iter_pcap_classic(
    fh: Any, byte_order: str, nanosecond: bool, link_type_name: str | None
) -> Iterator[tuple[int, str | None, str, int, int, bytes]]:
    """Yield ``(ts_us, link_type_name, interface, captured_len, packet_len, data)``."""
    while True:
        hdr = fh.read(16)
        if len(hdr) == 0:
            return
        if len(hdr) < 16:
            raise PcapParseError("truncated pcap packet record header")

        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(byte_order + "IIII", hdr)
        data = fh.read(incl_len)
        if len(data) < incl_len:
            raise PcapParseError("truncated pcap packet data")

        ts_us = ts_sec * 1_000_000 + (ts_frac // 1000 if nanosecond else ts_frac)
        yield ts_us, link_type_name, "", incl_len, orig_len, data


# ---------------------------------------------------------------------------
# pcapng parsing
# ---------------------------------------------------------------------------

def _parse_pcapng_options(data: bytes, byte_order: str) -> dict[int, bytes]:
    """Parse a pcapng options TLV list into ``{option_code: raw_value}``."""
    opts: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack(byte_order + "HH", data[offset : offset + 4])
        offset += 4
        if code == 0:  # opt_endofopt
            break
        value = data[offset : offset + length]
        opts.setdefault(code, value)
        offset += (length + 3) & ~3  # pad to 4-byte boundary
    return opts


def _tsresol_seconds(value: bytes | None) -> float:
    """Convert an ``if_tsresol`` option value to seconds-per-tick. Default: 1us."""
    if not value:
        return 1e-6
    b = value[0]
    if b & 0x80:
        return 2.0 ** (-(b & 0x7F))
    return 10.0 ** (-b)


def _iter_pcap_ng(fh: Any) -> Iterator[tuple[int, str | None, str, int, int, bytes]]:
    """Yield ``(ts_us, link_type_name, interface, captured_len, packet_len, data)``.

    Interfaces (link type + timestamp resolution + name) are tracked per
    section, reset at each new Section Header Block, and referenced by
    Enhanced Packet Blocks via ``interface_id``.
    """
    byte_order: str | None = None
    interfaces: list[dict[str, Any]] = []

    while True:
        block_type_raw = fh.read(4)
        if len(block_type_raw) == 0:
            return
        if len(block_type_raw) < 4:
            raise PcapParseError("truncated pcapng block type")

        if block_type_raw == _PCAPNG_MAGIC:
            rest = fh.read(8)
            if len(rest) < 8:
                raise PcapParseError("truncated pcapng section header block")
            block_total_length_raw, bom_raw = rest[0:4], rest[4:8]
            if bom_raw == b"\x1a\x2b\x3c\x4d":
                byte_order = ">"
            elif bom_raw == b"\x4d\x3c\x2b\x1a":
                byte_order = "<"
            else:
                raise PcapParseError("bad pcapng byte-order magic")

            block_total_length = struct.unpack(byte_order + "I", block_total_length_raw)[0]
            if block_total_length < 16:
                raise PcapParseError("bad pcapng section header block length")
            remaining = block_total_length - 16
            if len(fh.read(remaining)) < remaining:
                raise PcapParseError("truncated pcapng section header block body")
            if len(fh.read(4)) < 4:
                raise PcapParseError("truncated pcapng section header block trailer")

            interfaces = []
            continue

        if byte_order is None:
            raise PcapParseError("pcapng block encountered before a section header")

        block_total_length_raw = fh.read(4)
        if len(block_total_length_raw) < 4:
            raise PcapParseError("truncated pcapng block length")
        block_total_length = struct.unpack(byte_order + "I", block_total_length_raw)[0]
        if block_total_length < 12:
            raise PcapParseError("bad pcapng block length")

        body_len = block_total_length - 12
        body = fh.read(body_len)
        if len(body) < body_len:
            raise PcapParseError("truncated pcapng block body")
        if len(fh.read(4)) < 4:
            raise PcapParseError("truncated pcapng block trailer")

        block_type = struct.unpack(byte_order + "I", block_type_raw)[0]

        if block_type == 1:  # Interface Description Block
            if len(body) < 8:
                raise PcapParseError("truncated pcapng interface description block")
            linktype_num, _reserved, _snaplen = struct.unpack(byte_order + "HHI", body[0:8])
            opts = _parse_pcapng_options(body[8:], byte_order)
            interfaces.append({
                "link_type": _LINK_TYPE_NAMES.get(linktype_num),
                "tsresol_seconds": _tsresol_seconds(opts.get(9)),
                "name": opts.get(2, b"").decode("utf-8", errors="replace"),
            })

        elif block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                raise PcapParseError("truncated pcapng enhanced packet block")
            interface_id, ts_high, ts_low, captured_len, packet_len = struct.unpack(
                byte_order + "IIIII", body[0:20]
            )
            packet_data = body[20 : 20 + captured_len]
            if interface_id < len(interfaces):
                iface = interfaces[interface_id]
            else:
                iface = {"link_type": None, "tsresol_seconds": 1e-6, "name": ""}
            ticks = (ts_high << 32) | ts_low
            ts_us = round(ticks * iface["tsresol_seconds"] * 1_000_000)
            yield ts_us, iface["link_type"], iface["name"], captured_len, packet_len, packet_data

        elif block_type == 3:  # Simple Packet Block (no interface ref, no timestamp)
            if len(body) < 4:
                raise PcapParseError("truncated pcapng simple packet block")
            packet_len = struct.unpack(byte_order + "I", body[0:4])[0]
            packet_data = body[4 : 4 + packet_len]
            iface = interfaces[0] if interfaces else {"link_type": None, "name": ""}
            yield 0, iface["link_type"], iface.get("name", ""), len(packet_data), packet_len, packet_data

        # Any other block type (obsolete Packet Block, Name Resolution Block,
        # Interface Statistics Block, ...) is already consumed above and
        # simply skipped — it carries no packet to emit.


# ---------------------------------------------------------------------------
# L2 decoders
# ---------------------------------------------------------------------------

def _decode_ethernet(data: bytes) -> tuple[int, bytes, str, str] | None:
    """Return ``(ethertype, payload, src_mac, dst_mac)``, walking VLAN tags."""
    if len(data) < 14:
        return None
    dst_mac, src_mac = data[0:6], data[6:12]
    ethertype = struct.unpack(">H", data[12:14])[0]
    offset = 14
    while ethertype in (0x8100, 0x88A8) and len(data) >= offset + 4:
        ethertype = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
        offset += 4
    return ethertype, data[offset:], _mac_str(src_mac), _mac_str(dst_mac)


def _decode_linux_sll(data: bytes) -> tuple[int, bytes, str, str] | None:
    """Return ``(ethertype, payload, src_mac, dst_mac)`` for Linux cooked capture."""
    if len(data) < 16:
        return None
    addr_len = struct.unpack(">H", data[4:6])[0]
    addr = data[6 : 6 + min(addr_len, 8)]
    ethertype = struct.unpack(">H", data[14:16])[0]
    src_mac = _mac_str(addr) if addr_len == 6 else ""
    return ethertype, data[16:], src_mac, ""


def _decode_raw_ip(data: bytes) -> tuple[int, bytes, str, str] | None:
    """Return ``(ethertype, payload, src_mac, dst_mac)`` inferred from IP version."""
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        ethertype = 0x0800
    elif version == 6:
        ethertype = 0x86DD
    else:
        return None
    return ethertype, data, "", ""


# ---------------------------------------------------------------------------
# L3 decoders
# ---------------------------------------------------------------------------

def _decode_ipv4(data: bytes) -> dict[str, Any] | None:
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None

    total_length = struct.unpack(">H", data[2:4])[0]
    ip_id = struct.unpack(">H", data[4:6])[0]
    flags_frag = struct.unpack(">H", data[6:8])[0]
    fragment_offset = (flags_frag & 0x1FFF) * 8
    ttl = data[8]
    protocol_id = data[9]
    src_ip = str(ipaddress.IPv4Address(data[12:16]))
    dst_ip = str(ipaddress.IPv4Address(data[16:20]))

    payload_end = min(total_length, len(data)) if total_length >= ihl else len(data)
    payload = data[ihl:payload_end]

    return {
        "ttl": ttl,
        "ip_id": ip_id,
        "fragment_offset": fragment_offset,
        "protocol_id": protocol_id,
        "protocol_name": _protocol_name(protocol_id),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "payload": payload,
    }


def _decode_ipv6(data: bytes) -> dict[str, Any] | None:
    if len(data) < 40:
        return None
    payload_length = struct.unpack(">H", data[4:6])[0]
    next_header = data[6]
    hop_limit = data[7]
    src_ip = str(ipaddress.IPv6Address(data[8:24]))
    dst_ip = str(ipaddress.IPv6Address(data[24:40]))

    remaining = data[40 : 40 + payload_length] if payload_length else data[40:]

    # Walk common extension headers to reach the real transport header.
    for _ in range(8):
        if next_header not in _IPV6_EXT_HEADERS or len(remaining) < 2:
            break
        if next_header == 44:  # Fragment header: fixed 8 bytes
            hdr_len_bytes = 8
        else:
            hdr_ext_len = remaining[1]
            hdr_len_bytes = (hdr_ext_len + 1) * 8
        if len(remaining) < hdr_len_bytes:
            break
        next_header = remaining[0]
        remaining = remaining[hdr_len_bytes:]

    return {
        "hop_limit": hop_limit,
        "protocol_id": next_header,
        "protocol_name": _protocol_name(next_header),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "payload": remaining,
    }


def _decode_arp(data: bytes) -> dict[str, Any] | None:
    if len(data) < 8:
        return None
    _htype, ptype = struct.unpack(">HH", data[0:4])
    hlen, plen = data[4], data[5]
    opcode = struct.unpack(">H", data[6:8])[0]

    result: dict[str, Any] = {"arp_opcode": opcode}
    offset = 8
    if ptype == 0x0800 and plen == 4 and len(data) >= offset + 2 * hlen + 2 * plen:
        sha = data[offset : offset + hlen]
        offset += hlen
        spa = data[offset : offset + plen]
        offset += plen
        tha = data[offset : offset + hlen]
        offset += hlen
        tpa = data[offset : offset + plen]
        result["arp_sender_ip"] = str(ipaddress.IPv4Address(spa))
        result["arp_target_ip"] = str(ipaddress.IPv4Address(tpa))
        if hlen == 6:
            result["src_mac"] = _mac_str(sha)
            result["dst_mac"] = _mac_str(tha)
    return result


# ---------------------------------------------------------------------------
# L4 decoders
# ---------------------------------------------------------------------------

def _decode_tcp(data: bytes) -> dict[str, Any] | None:
    if len(data) < 20:
        return None
    src_port, dst_port = struct.unpack(">HH", data[0:4])
    seq = struct.unpack(">I", data[4:8])[0]
    ack = struct.unpack(">I", data[8:12])[0]
    flags_byte = data[13]
    window = struct.unpack(">H", data[14:16])[0]
    flags = "".join(name for bit, name in _TCP_FLAG_BITS if flags_byte & bit)
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_sequence": seq,
        "tcp_ack": ack,
        "tcp_window": window,
        "tcp_flags": flags,
    }


def _decode_udp(data: bytes) -> dict[str, Any] | None:
    if len(data) < 8:
        return None
    src_port, dst_port, length = struct.unpack(">HHH", data[0:6])
    return {"src_port": src_port, "dst_port": dst_port, "udp_length": length}


def _decode_icmp(data: bytes) -> dict[str, Any] | None:
    if len(data) < 4:
        return None
    return {"icmp_type": data[0], "icmp_code": data[1]}


def _decode_l4(protocol_name: str, payload: bytes) -> dict[str, Any] | None:
    if protocol_name == "tcp":
        return _decode_tcp(payload)
    if protocol_name == "udp":
        return _decode_udp(payload)
    if protocol_name in ("icmp", "icmpv6"):
        return _decode_icmp(payload)
    return None


# ---------------------------------------------------------------------------
# Row assembly
# ---------------------------------------------------------------------------

def _data_type_for(protocol: str) -> str:
    if protocol in ("tcp", "udp", "icmp", "icmpv6", "arp"):
        return f"network:packet:{protocol}"
    return "network:packet:other"


def _addr(ip: str, port: Any) -> str:
    return f"{ip}:{port}" if port not in (None, "") else ip


def _build_message(row: dict[str, Any]) -> str:
    protocol = row.get("protocol", "other")
    src_ip, dst_ip = row.get("src_ip", ""), row.get("dst_ip", "")
    length = row.get("packet_length") or row.get("captured_length") or 0

    if protocol == "tcp":
        flags = row.get("tcp_flags", "")
        return f"TCP {_addr(src_ip, row.get('src_port'))} -> {_addr(dst_ip, row.get('dst_port'))} [{flags}] len={length}"
    if protocol == "udp":
        return f"UDP {_addr(src_ip, row.get('src_port'))} -> {_addr(dst_ip, row.get('dst_port'))} len={length}"
    if protocol in ("icmp", "icmpv6"):
        label = "ICMPv6" if protocol == "icmpv6" else "ICMPv4"
        return f"{label} {src_ip} -> {dst_ip} type={row.get('icmp_type', '')} code={row.get('icmp_code', '')} len={length}"
    if protocol == "arp":
        opcode = row.get("arp_opcode")
        if opcode == 1:
            return f"ARP who-has {row.get('arp_target_ip', '')} tell {row.get('arp_sender_ip', '')}"
        if opcode == 2:
            return f"ARP {row.get('arp_sender_ip', '')} is-at {row.get('src_mac', '')}"
        return f"ARP opcode={opcode}"
    if src_ip or dst_ip:
        return f"IP proto={row.get('protocol_id', '')} {src_ip} -> {dst_ip} len={length}"
    ethertype = row.get("ethertype", "")
    return f"Non-IP frame ethertype={ethertype} len={length}"


def _build_row(
    ts_us: int,
    link_type: str,
    interface: str,
    captured_length: int,
    packet_length: int,
    raw_bytes: bytes,
    source_file: str,
) -> dict[str, Any]:
    """Decode one packet into a Timesketch row. Raises ``_MalformedPacket``
    when the L2/L3 headers cannot be decoded at all."""
    if link_type == "ethernet":
        decoded = _decode_ethernet(raw_bytes)
    elif link_type == "linux_sll":
        decoded = _decode_linux_sll(raw_bytes)
    elif link_type == "raw_ip":
        decoded = _decode_raw_ip(raw_bytes)
    else:
        raise _MalformedPacket(f"unsupported link type: {link_type}")

    if decoded is None:
        raise _MalformedPacket("short/truncated link-layer frame")
    ethertype, payload, src_mac, dst_mac = decoded

    row: dict[str, Any] = {
        "link_type": link_type,
        "interface": interface,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "captured_length": captured_length,
        "packet_length": packet_length,
    }

    protocol = "other"
    src_ip = dst_ip = ""

    if ethertype == 0x0806:
        arp = _decode_arp(payload)
        if arp is not None:
            row.update(arp)
        protocol = "arp"
    elif ethertype == 0x0800:
        ip = _decode_ipv4(payload)
        if ip is None:
            raise _MalformedPacket("bad IPv4 header")
        row["ip_version"] = 4
        row["ttl"] = ip["ttl"]
        row["ip_id"] = ip["ip_id"]
        row["fragment_offset"] = ip["fragment_offset"]
        row["protocol_id"] = ip["protocol_id"]
        src_ip, dst_ip = ip["src_ip"], ip["dst_ip"]
        protocol = ip["protocol_name"]
        if ip["fragment_offset"] == 0:
            l4 = _decode_l4(protocol, ip["payload"])
            if l4:
                row.update(l4)
    elif ethertype == 0x86DD:
        ip = _decode_ipv6(payload)
        if ip is None:
            raise _MalformedPacket("bad IPv6 header")
        row["ip_version"] = 6
        row["hop_limit"] = ip["hop_limit"]
        row["protocol_id"] = ip["protocol_id"]
        src_ip, dst_ip = ip["src_ip"], ip["dst_ip"]
        protocol = ip["protocol_name"]
        l4 = _decode_l4(protocol, ip["payload"])
        if l4:
            row.update(l4)
    else:
        row["ethertype"] = f"0x{ethertype:04x}"

    row["protocol"] = protocol
    row["src_ip"] = normalize_ip(src_ip)
    row["dst_ip"] = normalize_ip(dst_ip)

    timesketch_row: dict[str, Any] = {
        "datetime": to_iso8601(ts_us, unit="us"),
        "timestamp_desc": "Packet Capture Time",
        "message": _build_message(row),
        "data_type": _data_type_for(protocol),
        "timestamp": ts_us,
        "source": source_file,
        "src_ip": row["src_ip"],
        "dst_ip": row["dst_ip"],
    }
    timesketch_row.update(row)
    return timesketch_row


# ---------------------------------------------------------------------------
# Per-file streaming + orchestration
# ---------------------------------------------------------------------------

def _parse_since_until(value: str | None) -> datetime.datetime | None:
    """Parse an ISO 8601 ``--since``/``--until`` value to a UTC datetime."""
    if not value:
        return None
    dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _iter_rows_from_file(
    path: Path, since_us: int | None, until_us: int | None, stats: dict[str, Any]
) -> Iterator[dict[str, Any]]:
    """Yield Timesketch rows for one capture file, in file order.

    Never raises for corrupt/truncated data — it is counted in ``stats`` and
    a warning is printed instead, so one bad file doesn't abort the run. This
    relies on each file's own packet stream already being time-ordered (true
    for real captures); the global merge across files assumes the same.
    """
    ui = get_terminal()
    source_str = str(path.resolve())

    try:
        fh = open(path, "rb")
    except OSError as exc:
        stats["files_skipped_unsupported"] += 1
        ui.warning(f"Cannot open {path}: {exc}")
        return

    try:
        magic = fh.read(4)
        if magic in (_MAGIC_US_BE, _MAGIC_US_LE, _MAGIC_NS_BE, _MAGIC_NS_LE):
            byte_order = ">" if magic in (_MAGIC_US_BE, _MAGIC_NS_BE) else "<"
            nanosecond = magic in (_MAGIC_NS_BE, _MAGIC_NS_LE)
            header_rest = fh.read(20)
            if len(header_rest) < 20:
                stats["files_skipped_unsupported"] += 1
                ui.warning(f"Truncated pcap global header, skipping: {path}")
                return
            _, _, _, _, _, network = struct.unpack(byte_order + "HHiIII", header_rest)
            link_type = _LINK_TYPE_NAMES.get(network)
            packet_source = _iter_pcap_classic(fh, byte_order, nanosecond, link_type)
        elif magic == _PCAPNG_MAGIC:
            fh.seek(0)
            packet_source = _iter_pcap_ng(fh)
        else:
            stats["files_skipped_unsupported"] += 1
            ui.warning(f"Unrecognized capture format, skipping: {path}")
            return

        for ts_us, link_type_name, interface, captured_length, packet_length, raw_bytes in packet_source:
            if since_us is not None and ts_us < since_us:
                stats["packets_skipped_by_time"] += 1
                continue
            if until_us is not None and ts_us > until_us:
                stats["packets_skipped_by_time"] += 1
                continue
            if link_type_name is None:
                stats["packets_skipped_unsupported_linktype"] += 1
                continue

            try:
                row = _build_row(
                    ts_us, link_type_name, interface, captured_length, packet_length, raw_bytes, source_str
                )
            except _MalformedPacket:
                stats["packets_malformed"] += 1
                continue

            protocol = row["protocol"]
            stats["rows_by_protocol"][protocol] = stats["rows_by_protocol"].get(protocol, 0) + 1
            yield row

    except (struct.error, PcapParseError) as exc:
        stats["files_skipped_unsupported"] += 1
        ui.warning(f"Corrupt or truncated capture, stopping at the failure point: {path} ({exc})")
    finally:
        fh.close()


def _iter_jsonl_rows(path: Path) -> Iterator[dict[str, Any]]:
    """Yield rows from a spilled JSONL file, closing it when exhausted."""
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            yield json.loads(line)


def _merge_file_streams(
    files: list[Path],
    since_us: int | None,
    until_us: int | None,
    stats: dict[str, Any],
    spill_dir: Path | None,
) -> Iterator[dict[str, Any]]:
    """Merge rows from many capture files into one chronological stream.

    ``heapq.merge`` over thousands of files would hold one file descriptor per
    file, quickly exhausting the process limit.  This implementation merges in
    chunks of :data:`_MAX_MERGE_STREAMS` files and spills intermediate results
    to temporary JSONL files, so the number of simultaneously open descriptors
    stays bounded.
    """
    streams: list[Iterator[dict[str, Any]]] = [
        _iter_rows_from_file(f, since_us, until_us, stats) for f in files
    ]

    all_spill_paths: list[Path] = []
    try:
        while len(streams) > _MAX_MERGE_STREAMS:
            next_streams: list[Iterator[dict[str, Any]]] = []
            for i in range(0, len(streams), _MAX_MERGE_STREAMS):
                chunk = streams[i : i + _MAX_MERGE_STREAMS]
                merged = heapq.merge(*chunk, key=lambda r: r["timestamp"])
                spill = tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    suffix=".pcapmerge.jsonl",
                    dir=spill_dir,
                    delete=False,
                )
                spill_path = Path(spill.name)
                for row in merged:
                    spill.write(json.dumps(row, ensure_ascii=False) + "\n")
                spill.close()
                all_spill_paths.append(spill_path)
                next_streams.append(_iter_jsonl_rows(spill_path))
            streams = next_streams

        yield from heapq.merge(*streams, key=lambda r: r["timestamp"])
    finally:
        for p in all_spill_paths:
            p.unlink(missing_ok=True)


def convert_pcap(
    input_path: str,
    output: str,
    output_format: str,
    since: str | None = None,
    until: str | None = None,
    verbose: bool = True,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, Any]:
    """Convert pcap/pcapng captures under ``input_path`` to a Timesketch timeline.

    Every discovered file is decoded lazily and merged into one globally
    chronological output via a k-way merge (stdlib ``heapq.merge``), rather
    than buffering every row in memory.  The merge is performed in chunks so
    the number of simultaneously open capture files is bounded, preventing
    "Too many open files" errors on large captures.

    Returns:
        Statistics dict with ``rows_written``, ``files_processed``, and
        per-file/per-packet skip/error counters.
    """
    files = _find_pcap_files(input_path)
    if not files:
        raise ConverterError(f"No pcap/pcapng files found in: {input_path}")

    ui = get_terminal()
    ui.header(
        "pcap2timesketch",
        subtitle="Convert pcap/pcapng captures → Timesketch timeline",
        badges=[("network", "accent"), (output_format, "muted")],
    )
    ui.step("Files found", f"{len(files)} capture file(s)")

    since_dt = _parse_since_until(since)
    until_dt = _parse_since_until(until)
    since_us = to_unix_microseconds(since_dt) if since_dt else None
    until_us = to_unix_microseconds(until_dt) if until_dt else None

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("pcap2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)

    writer = OutputWriter(output, output_format, compute_hash=report_path is not None)

    stats: dict[str, Any] = {
        "files_skipped_unsupported": 0,
        "packets_malformed": 0,
        "packets_skipped_unsupported_linktype": 0,
        "packets_skipped_by_time": 0,
        "rows_by_protocol": {},
    }

    spill_dir: Path | None = None
    if output != "-":
        spill_dir = Path(output).parent
        spill_dir.mkdir(parents=True, exist_ok=True)

    rows_written = 0
    ui.step("Processing", f"Parsing packets across {len(files)} file(s)")
    with ui.spinner("Parsing packets"):
        for row in _merge_file_streams(files, since_us, until_us, stats, spill_dir):
            writer.add(row)
            rows_written += 1

    written = writer.write()

    if report:
        if output == "-":
            report.add_stdout_output(writer.content_hash)
        else:
            report.add_output_file(output, writer.content_hash)
        report.set_statistics({
            "rows_written": written,
            "files_processed": len(files),
            **stats,
            "since": since,
            "until": until,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    summary_items: dict[str, Any] = {
        "Rows written": f"{written:,}",
        "Files processed": f"{len(files)}",
        "Files skipped (unsupported)": f"{stats['files_skipped_unsupported']:,}",
        "Packets malformed": f"{stats['packets_malformed']:,}",
        "Skipped (unsupported link type)": f"{stats['packets_skipped_unsupported_linktype']:,}",
        "Skipped by time": f"{stats['packets_skipped_by_time']:,}",
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
    }
    for protocol, count in sorted(stats["rows_by_protocol"].items()):
        summary_items[f"Protocol: {protocol}"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return {
        "rows_written": written,
        "files_processed": len(files),
        **stats,
    }
