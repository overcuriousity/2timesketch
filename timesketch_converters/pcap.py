#!/usr/bin/env python3
"""Packet capture (pcap/pcapng) to Timesketch timeline converter.

Parses raw network captures produced by Wireshark/tcpdump — both the
classic libpcap format and the newer block-based pcapng format — into one
Timesketch row per packet, decoded down to the Ethernet/Linux-SLL/raw-IP,
IPv4/IPv6, and TCP/UDP/ICMP/ARP headers. By default no TCP stream reassembly
and no multi-packet application-layer decoding is performed.

``--reassemble http`` adds one derived ``network:http:transaction`` row per
HTTP/1.x request/response pair, reassembled from the TCP streams. Those rows
are emitted *in addition to* the packet rows, never instead of them: packet
rows stay the forensic floor, and the same capture converted with and without
the flag yields identical packet rows. Limits: cleartext HTTP/1.0 and 1.1
only — no HTTPS (not decrypted), no HTTP/2 or HTTP/3 (binary framing +
HPACK/QPACK), and nothing useful from a snaplen-truncated or single-direction
capture. See ``README.md``.
"""

from __future__ import annotations

import collections
import datetime
import heapq
import ipaddress
import json
import re
import struct
import tempfile
import zlib
from pathlib import Path
from typing import Any, Callable, Iterator

from .common import (
    AuditReport,
    ConverterError,
    OutputWriter,
    add_writer_output,
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

# Rows held in memory while sorting one file's reassembled transaction rows
# back into timestamp order; a full chunk is spilled to a temporary JSONL.
_SORT_CHUNK_ROWS = 200_000


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
    fragment_offset = 0
    for _ in range(8):
        if next_header not in _IPV6_EXT_HEADERS or len(remaining) < 2:
            break
        if next_header == 44:  # Fragment header: fixed 8 bytes
            hdr_len_bytes = 8
            if len(remaining) >= 4:
                # Offset in 8-byte units, in the top 13 bits of the field;
                # reported in bytes, as for IPv4.
                fragment_offset = (struct.unpack(">H", remaining[2:4])[0] >> 3) * 8
        else:
            hdr_ext_len = remaining[1]
            hdr_len_bytes = (hdr_ext_len + 1) * 8
        if len(remaining) < hdr_len_bytes:
            break
        next_header = remaining[0]
        remaining = remaining[hdr_len_bytes:]

    return {
        "hop_limit": hop_limit,
        "fragment_offset": fragment_offset,
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


def _tcp_payload(segment: bytes) -> bytes:
    """Return the TCP payload of an L4 segment (empty if headers are short/bogus)."""
    if len(segment) < 20:
        return b""
    data_offset = (segment[12] >> 4) * 4
    if data_offset < 20 or data_offset > len(segment):
        return b""
    return segment[data_offset:]


def _build_row(
    ts_us: int,
    link_type: str,
    interface: str,
    captured_length: int,
    packet_length: int,
    raw_bytes: bytes,
    source_file: str,
    want_tcp_payload: bool = False,
) -> tuple[dict[str, Any], bytes]:
    """Decode one packet into a Timesketch row. Raises ``_MalformedPacket``
    when the L2/L3 headers cannot be decoded at all.

    Returns ``(row, tcp_payload)``. The payload is the reassembler's input and
    is empty unless ``want_tcp_payload`` is set and the packet is TCP — raw
    payload bytes are deliberately returned alongside the row rather than as a
    field, so they can never reach the output timeline.
    """
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
    l4_segment = b""

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
            l4_segment = ip["payload"]
            l4 = _decode_l4(protocol, l4_segment)
            if l4:
                row.update(l4)
    elif ethertype == 0x86DD:
        ip = _decode_ipv6(payload)
        if ip is None:
            raise _MalformedPacket("bad IPv6 header")
        row["ip_version"] = 6
        row["hop_limit"] = ip["hop_limit"]
        row["fragment_offset"] = ip["fragment_offset"]
        row["protocol_id"] = ip["protocol_id"]
        src_ip, dst_ip = ip["src_ip"], ip["dst_ip"]
        protocol = ip["protocol_name"]
        # As for IPv4: only the first fragment carries the L4 header. A later
        # fragment's payload is body bytes, and decoding it would invent ports
        # and sequence numbers — and, with --reassemble, a phantom flow.
        if ip["fragment_offset"] == 0:
            l4_segment = ip["payload"]
            l4 = _decode_l4(protocol, l4_segment)
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
    payload = _tcp_payload(l4_segment) if want_tcp_payload and protocol == "tcp" else b""
    return timesketch_row, payload


# ---------------------------------------------------------------------------
# TCP reassembly + HTTP/1.x framing  (--reassemble http)
#
# Emits one derived ``network:http:transaction`` row per request/response *in
# addition to* the per-packet rows, which stay the forensic floor: nothing here
# removes or replaces a packet row, and a capture converted without
# ``--reassemble`` yields the same packet rows as one converted with it.
#
# Every limit below exists because the input is incident evidence and therefore
# routinely hostile: sequence numbers, lengths, chunk sizes and compression
# ratios are all attacker-controlled. Exceeding any limit kills the one flow
# that did it (its packet rows survive), never the run.
# ---------------------------------------------------------------------------

# Buffered payload per direction of a connection. A request's bytes are
# consumed as it is framed, so this bounds the reassembly working set.
_REASM_MAX_STREAM_BYTES = 8 * 1024 * 1024
# Concurrently tracked connections; the least recently active is evicted first
# (its in-flight request is emitted as incomplete rather than dropped silently).
_REASM_MAX_FLOWS = 4096
# A flow with no packet for this much *capture* time is finalized and dropped.
_REASM_IDLE_SECONDS = 300
# Header block, before the terminating blank line, and its field count.
_REASM_MAX_HEADER_BYTES = 64 * 1024
_REASM_MAX_HEADERS = 256
# Body ceilings: framed (on the wire) and decompressed (gzip/deflate bomb).
_REASM_MAX_BODY_BYTES = 64 * 1024 * 1024
_REASM_MAX_DECOMPRESSED_BYTES = 32 * 1024 * 1024
# Out-of-order segments held while waiting for the gap ahead of them to fill.
_REASM_MAX_PENDING_SEGMENTS = 1024
# Framed requests waiting to be paired with a response. Deep pipelining is rare;
# an unbounded queue is really a single-direction capture (no response side ever
# arrives), so the overflow is emitted as ``http_response_missing`` rather than
# held forever.
_REASM_MAX_PENDING_REQUESTS = 256
# Idle sweep cadence, in packets fed to the reassembler.
_REASM_SWEEP_EVERY = 5000

_REASM_HTTP_PORTS = frozenset({80, 81, 591, 3128, 8000, 8008, 8080, 8081, 8088, 8888})

_RE_REQUEST_LINE = re.compile(rb"^([A-Z][A-Z_-]{1,19}) ([^ \r\n]{1,8192}) (HTTP/\d\.\d)\r?\n")
_RE_STATUS_LINE = re.compile(rb"^(HTTP/\d\.\d) (\d{3})(?:[ \t]+([^\r\n]{0,256}))?\r?\n")

# Requests are never framed against a peer method; see ``_HttpDirection.messages``.
_NO_PEER_METHOD: Callable[[], str] = lambda: ""  # noqa: E731


class _HttpMessage:
    """One framed HTTP/1.x message plus the capture records that carried it."""

    __slots__ = (
        "is_request",
        "method",
        "uri",
        "protocol",
        "status",
        "reason",
        "headers",
        "wire_bytes",
        "body_bytes",
        "decoded_body_bytes",
        "content_encoding",
        "records",
        "first_ts",
        "start_ts",
        "end_ts",
        "complete",
        "gap",
        "truncated",
    )

    def __init__(self, is_request: bool, start_ts: int) -> None:
        self.is_request = is_request
        self.method = ""
        self.uri = ""
        self.protocol = ""
        self.status = 0
        self.reason = ""
        self.headers: dict[str, str] = {}
        self.wire_bytes = 0
        self.body_bytes = 0
        self.decoded_body_bytes = -1
        self.content_encoding = ""
        # Stream-offset spans of the capture records that carried any byte of
        # this message; only their count reaches the row (``packet_count``).
        # The span is the identity — a record is credited once even when it
        # straddles the header/body boundary and is seen by two ``_take`` calls.
        self.records: set[tuple[int, int]] = set()
        # Capture time of the earliest record that carried any byte of this
        # message — its first captured byte, which is what the row is stamped
        # with. -1 until a record is attributed.
        self.first_ts = -1
        self.start_ts = start_ts
        self.end_ts = start_ts
        self.complete = False
        self.gap = False
        self.truncated = False


def _parse_headers(block: bytes) -> dict[str, str] | None:
    """Parse a header block (no start line, no terminating blank line).

    Returns lowercased field names mapped to values; repeated fields are joined
    with ``", "`` as RFC 9110 allows. ``None`` when the block is malformed or
    exceeds ``_REASM_MAX_HEADERS``.
    """
    headers: dict[str, str] = {}
    if not block:
        return headers
    lines = block.split(b"\n")
    if len(lines) > _REASM_MAX_HEADERS:
        return None
    name = ""
    for raw in lines:
        line = raw.rstrip(b"\r")
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):  # obs-fold continuation
            if not name:
                return None
            headers[name] += " " + line.strip().decode("latin-1")
            continue
        sep = line.find(b":")
        if sep <= 0:
            return None
        name = line[:sep].strip().lower().decode("latin-1")
        value = line[sep + 1 :].strip().decode("latin-1")
        headers[name] = f"{headers[name]}, {value}" if name in headers else value
    return headers


def _decoded_length(body: bytes, encoding: str) -> int:
    """Decompressed length of ``body``, or -1 when it cannot be decoded.

    Capped at ``_REASM_MAX_DECOMPRESSED_BYTES`` — a compression bomb stops the
    walk and reports -1 rather than materializing the expansion.
    """
    token = encoding.split(",")[0].strip().lower()
    if token in ("gzip", "x-gzip", "deflate"):
        wbits = zlib.MAX_WBITS | 32 if token != "deflate" else zlib.MAX_WBITS
    else:
        return -1
    for attempt_wbits in (wbits, -zlib.MAX_WBITS):
        obj = zlib.decompressobj(attempt_wbits)
        total = 0
        try:
            for start in range(0, len(body), 65536):
                out = obj.decompress(body[start : start + 65536], _REASM_MAX_DECOMPRESSED_BYTES)
                total += len(out)
                if total >= _REASM_MAX_DECOMPRESSED_BYTES or obj.unconsumed_tail:
                    return -1
            total += len(obj.flush())
        except zlib.error:
            continue
        return total
    return -1


class _HttpDirection:
    """One direction of a TCP connection: byte reassembly, then HTTP framing.

    Sequence-ordered buffering with ISN tracking. A retransmit of already
    delivered bytes is dropped, an overlapping segment is trimmed to the part
    that is new (first writer wins, matching what the receiver saw), and a
    segment landing past the contiguous end is held until the gap fills.
    """

    def __init__(self, is_request_side: bool) -> None:
        self.is_request_side = is_request_side
        self.started = False
        self.isn = 0
        self.base = 0
        self.data = bytearray()
        self.pending: dict[int, bytes] = {}
        # (start, end, ts) in stream-offset space, one per capture record.
        self.records: list[tuple[int, int, int]] = []
        self.buffered = 0
        self.gap = False
        self.truncated = False
        self.closed = False
        self.dead = False
        self.last_ts = 0
        # Framing state.
        self.phase = "start"  # start | body | chunk_size | chunk_data | chunk_crlf | trailer
        self.msg: _HttpMessage | None = None
        self.body_mode = "none"  # none | length | chunked | until_close
        self.need = 0
        self.body = bytearray()
        self.chunk_left = 0

    # -- byte layer --------------------------------------------------------

    def add(self, seq: int, syn: bool, payload: bytes, ts: int) -> None:
        if self.dead:
            return
        self.last_ts = ts
        if not self.started:
            # Without a SYN the capture started mid-stream: anchor on the first
            # sequence number seen, which makes offsets relative but consistent.
            self.isn = (seq + 1) & 0xFFFFFFFF if syn else seq
            self.started = True
        if not payload:
            return

        # Lift the 32-bit sequence into the window around the current base, so
        # a stream crossing the wrap point stays monotone.
        delta = (seq - self.isn - self.base) & 0xFFFFFFFF
        if delta >= 0x80000000:
            delta -= 0x100000000
        off = self.base + delta
        end = off + len(payload)

        contiguous_end = self.base + len(self.data)
        if end <= contiguous_end:
            return  # pure retransmit of bytes already delivered
        if off < contiguous_end:  # overlap: keep what the receiver already had
            payload = payload[contiguous_end - off :]
            off = contiguous_end

        self.records.append((off, off + len(payload), ts))
        self.buffered += len(payload)

        if off == contiguous_end:
            self.data += payload
            self._drain()
        else:
            if len(self.pending) >= _REASM_MAX_PENDING_SEGMENTS:
                self._forward_over_gap()
            existing = self.pending.get(off)
            if existing is None or len(existing) < len(payload):
                self.buffered -= len(existing) if existing else 0
                self.pending[off] = payload
            else:
                self.buffered -= len(payload)

        if self.buffered > _REASM_MAX_STREAM_BYTES:
            self.dead = True
            self._release()

    def _drain(self) -> None:
        while self.pending:
            contiguous_end = self.base + len(self.data)
            segment = self.pending.pop(contiguous_end, None)
            if segment is None:
                # Drop anything the contiguous run has since overtaken.
                stale = [off for off in self.pending if off < contiguous_end]
                if not stale:
                    break
                for off in stale:
                    held = self.pending.pop(off)
                    self.buffered -= len(held)
                    tail = held[contiguous_end - off :]
                    if tail and len(tail) > len(self.pending.get(contiguous_end, b"")):
                        self.buffered -= len(self.pending.get(contiguous_end, b""))
                        self.pending[contiguous_end] = tail
                        self.buffered += len(tail)
                continue
            # Pending bytes become contiguous bytes: no net change in ``buffered``.
            self.data += segment

    def _forward_over_gap(self) -> None:
        """Give up on a hole: jump to the lowest held segment, flagging the gap."""
        if not self.pending:
            return
        target = min(self.pending)
        self.gap = True
        if self.msg is not None:
            self.msg.gap = True
        self.buffered -= len(self.data)
        self.data.clear()
        self.base = target
        # Records that end at or before the new base can never be attributed by
        # ``_take`` again (it only looks at records reaching past it), so credit
        # their provenance here — they did carry bytes of this message — before
        # dropping them.
        keep: list[tuple[int, int, int]] = []
        for record in self.records:
            if record[1] > self.base:
                keep.append(record)
                continue
            self._attribute(record)
        self.records = keep
        self._drain()

    def _attribute(self, record: tuple[int, int, int]) -> None:
        """Credit one capture record to the message currently being framed."""
        message = self.msg
        if message is None:
            return
        message.records.add((record[0], record[1]))
        if message.first_ts < 0 or record[2] < message.first_ts:
            message.first_ts = record[2]

    def _release(self) -> None:
        self.data.clear()
        self.pending.clear()
        self.records.clear()
        self.body.clear()
        self.buffered = 0

    def _take(self, count: int) -> bytes:
        """Consume ``count`` bytes, attributing the records that carried them."""
        chunk = bytes(self.data[:count])
        start, end = self.base, self.base + count
        keep: list[tuple[int, int, int]] = []
        for record in self.records:
            if record[1] > start and record[0] < end:
                self._attribute(record)
            if record[1] > end:
                keep.append(record)
        self.records = keep
        del self.data[:count]
        self.base = end
        self.buffered -= count
        if self.msg is not None:
            self.msg.wire_bytes += count
        return chunk

    # -- HTTP framing ------------------------------------------------------

    def messages(
        self, ts: int, peer_method: Callable[[], str], at_close: bool
    ) -> Iterator[_HttpMessage]:
        """Yield every message the buffered bytes now complete.

        ``peer_method`` returns the method of the request the *next* response
        answers (a response to HEAD has no body whatever its ``Content-Length``
        says); it returns ``""`` on the request side. It is a callable, not a
        value, because this is a generator: several pipelined responses can be
        framed within one resumption, and each must be framed against its own
        request, which the caller only dequeues as responses are yielded.
        """
        while not self.dead:
            if self.phase == "start":
                header_end = self._find_header_end()
                if header_end is None:
                    if len(self.data) > _REASM_MAX_HEADER_BYTES:
                        self.dead = True
                        self._release()
                    return
                if not self._begin_message(header_end, ts, peer_method):
                    return
                continue
            message = self._advance_body(at_close)
            if message is None:
                return
            yield message

    def _find_header_end(self) -> int | None:
        idx = self.data.find(b"\r\n\r\n")
        if idx >= 0:
            return idx + 4
        idx = self.data.find(b"\n\n")  # tolerate LF-only framing
        return idx + 2 if idx >= 0 else None

    def _begin_message(self, header_end: int, ts: int, peer_method: Callable[[], str]) -> bool:
        """Parse one start line + header block. False kills or stalls the direction."""
        head = bytes(self.data[:header_end])
        if self.is_request_side:
            match = _RE_REQUEST_LINE.match(head)
        else:
            match = _RE_STATUS_LINE.match(head)
        if match is None:
            self.dead = True  # not HTTP/1.x on this connection
            self._release()
            return False
        headers = _parse_headers(head[match.end() : header_end].rstrip(b"\r\n"))
        if headers is None:
            self.dead = True
            self._release()
            return False

        message = _HttpMessage(self.is_request_side, ts)
        message.gap = self.gap
        message.truncated = self.truncated
        message.headers = headers
        self.msg = message
        if self.is_request_side:
            message.method = match.group(1).decode("latin-1")
            message.uri = match.group(2).decode("latin-1")
            message.protocol = match.group(3).decode("latin-1")
        else:
            message.protocol = match.group(1).decode("latin-1")
            message.status = int(match.group(2))
            message.reason = (match.group(3) or b"").decode("latin-1").strip()
        message.content_encoding = headers.get("content-encoding", "")

        self._take(header_end)
        self._start_body(message, headers, peer_method())
        return True

    def _start_body(self, message: _HttpMessage, headers: dict[str, str], peer_method: str) -> None:
        self.body = bytearray()
        transfer_encoding = headers.get("transfer-encoding", "").lower()
        bodyless = not self.is_request_side and (
            message.status < 200 or message.status in (204, 304) or peer_method.upper() == "HEAD"
        )
        if bodyless:
            self.body_mode = "none"
            self.phase = "body"
            self.need = 0
        elif "chunked" in transfer_encoding:
            self.body_mode = "chunked"
            self.phase = "chunk_size"
        elif "content-length" in headers:
            try:
                length = int(headers["content-length"].split(",")[0].strip())
            except ValueError:
                length = -1
            if length < 0 or length > _REASM_MAX_BODY_BYTES:
                self.dead = True
                self._release()
                return
            self.body_mode = "length"
            self.need = length
            self.phase = "body"
        elif self.is_request_side:
            self.body_mode = "none"  # a request with neither framing header has no body
            self.need = 0
            self.phase = "body"
        else:
            self.body_mode = "until_close"
            self.phase = "body"

    def _advance_body(self, at_close: bool) -> _HttpMessage | None:
        message = self.msg
        if message is None:
            self.phase = "start"
            return None

        if self.body_mode in ("none", "length"):
            take = min(self.need, len(self.data))
            if take:
                self.body += self._take(take)
                self.need -= take
            if self.need and not at_close:
                return None
            if self.need and at_close:
                message.complete = False
                return self._finish_message(partial=True)
            return self._finish_message(partial=False)

        if self.body_mode == "until_close":
            if self.data:
                # Nothing on the wire declares where this body ends, so the cap
                # is the only bound there is. Same verdict as an over-long
                # Content-Length or chunk size: the flow dies, its packet rows
                # survive.
                if len(self.body) + len(self.data) > _REASM_MAX_BODY_BYTES:
                    self.dead = True
                    self._release()
                    return None
                self.body += self._take(len(self.data))
            if not at_close:
                return None
            return self._finish_message(partial=False)

        return self._advance_chunked(at_close)

    def _advance_chunked(self, at_close: bool) -> _HttpMessage | None:
        while True:
            if self.phase == "chunk_size":
                idx = self.data.find(b"\n")
                if idx < 0:
                    if len(self.data) > _REASM_MAX_HEADER_BYTES:
                        self.dead = True
                        self._release()
                    break
                line = bytes(self._take(idx + 1)).strip()
                size_token = line.split(b";", 1)[0].strip()
                try:
                    self.chunk_left = int(size_token, 16)
                except ValueError:
                    self.dead = True
                    self._release()
                    break
                if self.chunk_left < 0 or len(self.body) + self.chunk_left > _REASM_MAX_BODY_BYTES:
                    self.dead = True
                    self._release()
                    break
                self.phase = "trailer" if self.chunk_left == 0 else "chunk_data"
            elif self.phase == "chunk_data":
                take = min(self.chunk_left, len(self.data))
                if take:
                    self.body += self._take(take)
                    self.chunk_left -= take
                if self.chunk_left:
                    break
                self.phase = "chunk_crlf"
            elif self.phase == "chunk_crlf":
                if len(self.data) < 2:
                    if len(self.data) == 1 and self.data[:1] == b"\n":
                        self._take(1)
                        self.phase = "chunk_size"
                        continue
                    break
                if self.data[:2] == b"\r\n":
                    self._take(2)
                elif self.data[:1] == b"\n":
                    self._take(1)
                self.phase = "chunk_size"
            else:  # trailer: header lines, then a blank line
                end = self._find_header_end()
                if end is None:
                    if self.data[:2] == b"\r\n":
                        self._take(2)
                        return self._finish_message(partial=False)
                    if self.data[:1] == b"\n":
                        self._take(1)
                        return self._finish_message(partial=False)
                    if len(self.data) > _REASM_MAX_HEADER_BYTES:
                        self.dead = True
                        self._release()
                    break
                self._take(end)
                return self._finish_message(partial=False)
        if at_close and self.msg is not None:
            return self._finish_message(partial=True)
        return None

    def _finish_message(self, partial: bool) -> _HttpMessage | None:
        message = self.msg
        if message is None:
            return None
        message.body_bytes = len(self.body)
        message.complete = not partial
        # Stamp the message with its own first captured byte, not with whichever
        # packet happened to complete the framing — that packet can belong to
        # the other direction (``_pump`` drives both from one arrival) or, with
        # an out-of-order start, arrive after bytes that came earlier.
        if message.first_ts >= 0:
            message.start_ts = message.first_ts
        message.end_ts = max(self.last_ts, message.start_ts)
        message.gap = message.gap or self.gap
        message.truncated = message.truncated or self.truncated
        if message.content_encoding and self.body:
            message.decoded_body_bytes = _decoded_length(bytes(self.body), message.content_encoding)
        self.msg = None
        self.body = bytearray()
        self.phase = "start"
        self.body_mode = "none"
        self.need = 0
        return message


class _HttpFlow:
    """Both directions of one TCP connection, plus the request/response pairing."""

    __slots__ = (
        "client_endpoint",
        "server_endpoint",
        "client",
        "server",
        "requests",
        "last_ts",
        "index",
        "dead",
    )

    def __init__(self) -> None:
        self.client_endpoint: tuple[str, int] | None = None
        self.server_endpoint: tuple[str, int] | None = None
        self.client = _HttpDirection(True)
        self.server = _HttpDirection(False)
        self.requests: collections.deque[_HttpMessage] = collections.deque()
        self.last_ts = 0
        self.index = 0
        self.dead = False


class _HttpReassembler:
    """Feeds TCP packets in, yields ``network:http:transaction`` rows out.

    One instance per capture file. Rows are produced when a transaction
    *completes*, so the caller must sort them before merging them into the
    timeline (see ``_iter_transactions_from_file``).
    """

    def __init__(self, source_file: str) -> None:
        self.source_file = source_file
        self.flows: collections.OrderedDict[tuple, _HttpFlow] = collections.OrderedDict()
        self.emitted = 0
        self.incomplete = 0
        self.evicted = 0
        self._seen = 0

    # -- packet intake -----------------------------------------------------

    def handle(self, row: dict[str, Any], payload: bytes, ts_us: int) -> list[dict[str, Any]]:
        src = (row.get("src_ip", ""), int(row.get("src_port") or 0))
        dst = (row.get("dst_ip", ""), int(row.get("dst_port") or 0))
        if not src[1] or not dst[1]:
            return []
        key = (src, dst) if src <= dst else (dst, src)

        self._seen += 1
        rows: list[dict[str, Any]] = []
        if self._seen % _REASM_SWEEP_EVERY == 0:
            rows.extend(self._sweep_idle(ts_us))

        flow = self.flows.get(key)
        if flow is None:
            flow = _HttpFlow()
            self.flows[key] = flow
            while len(self.flows) > _REASM_MAX_FLOWS:
                _, victim = self.flows.popitem(last=False)
                self.evicted += 1
                rows.extend(self._finalize(victim))
        else:
            self.flows.move_to_end(key)
        flow.last_ts = ts_us

        if flow.dead:
            return rows

        flags = row.get("tcp_flags", "")
        direction = self._direction_for(flow, src, dst, payload, flags)
        if direction is not None:
            if row.get("captured_length", 0) < row.get("packet_length", 0):
                direction.truncated = True
            sequence = int(row.get("tcp_sequence") or 0)
            direction.add(sequence, "SYN" in flags, payload, ts_us)
            rows.extend(self._pump(flow, ts_us, at_close=False))

        if "RST" in flags:
            rows.extend(self._finalize(flow))
            self.flows.pop(key, None)
        elif "FIN" in flags:
            if direction is not None:
                direction.closed = True
            if flow.client.closed and flow.server.closed:
                rows.extend(self._finalize(flow))
                self.flows.pop(key, None)
        if flow.client.dead and flow.server.dead and key in self.flows:
            rows.extend(self._finalize(flow))
            self.flows.pop(key, None)
        return rows

    def _direction_for(
        self,
        flow: _HttpFlow,
        src: tuple[str, int],
        dst: tuple[str, int],
        payload: bytes,
        flags: str,
    ) -> _HttpDirection | None:
        if flow.client_endpoint is None:
            # Assign roles from the first evidence available, in decreasing
            # order of reliability: handshake, wire content, then well-known port.
            # ``flags`` is the concatenated flag names ("PSHACK"), so match whole
            # names — "S" alone also hits PSH and RST.
            syn, ack = "SYN" in flags, "ACK" in flags
            src_is_client = True  # last resort: whoever spoke first
            for verdict, evidence in (
                (True, syn and not ack),
                (False, syn and ack),
                (False, payload[:5] == b"HTTP/"),
                (True, _RE_REQUEST_LINE.match(payload[:1024]) is not None),
                (True, dst[1] in _REASM_HTTP_PORTS),
                (False, src[1] in _REASM_HTTP_PORTS),
            ):
                if evidence:
                    src_is_client = verdict
                    break
            client = src if src_is_client else dst
            flow.client_endpoint = client
            flow.server_endpoint = dst if client == src else src
        if src == flow.client_endpoint:
            return flow.client
        if src == flow.server_endpoint:
            return flow.server
        return None

    def _sweep_idle(self, now_us: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        cutoff = now_us - _REASM_IDLE_SECONDS * 1_000_000
        while self.flows:
            key, flow = next(iter(self.flows.items()))
            if flow.last_ts >= cutoff:
                break
            self.flows.pop(key)
            self.evicted += 1
            rows.extend(self._finalize(flow))
        return rows

    # -- pairing / emission ------------------------------------------------

    def _pump(self, flow: _HttpFlow, ts: int, at_close: bool) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for request in flow.client.messages(ts, _NO_PEER_METHOD, at_close):
            flow.requests.append(request)
            # A queue this deep is a capture with no response side, not real
            # pipelining: retire the oldest unanswered request instead of
            # holding it for the rest of the run.
            while len(flow.requests) > _REASM_MAX_PENDING_REQUESTS:
                rows.append(self._transaction(flow, flow.requests.popleft(), None))

        def peer_method() -> str:
            return flow.requests[0].method if flow.requests else ""

        for response in flow.server.messages(ts, peer_method, at_close):
            if 100 <= response.status < 200 and response.status != 101:
                continue  # interim (100-continue): the real response still follows
            request = flow.requests.popleft() if flow.requests else None
            rows.append(self._transaction(flow, request, response))
            if response.status == 101 or (
                request is not None
                and request.method.upper() == "CONNECT"
                and response.status < 300
            ):
                # Upgraded/tunneled: the rest of the connection is not HTTP/1.x.
                flow.client.dead = flow.server.dead = True
                flow.client._release()
                flow.server._release()
                break
        return rows

    def _finalize(self, flow: _HttpFlow) -> list[dict[str, Any]]:
        if flow.dead:
            return []
        flow.dead = True
        rows = self._pump(flow, flow.last_ts, at_close=True)
        pending_request = flow.client.msg
        if pending_request is not None:
            flow.client._finish_message(partial=True)
            flow.requests.append(pending_request)
        for request in flow.requests:
            rows.append(self._transaction(flow, request, None))
        flow.requests.clear()
        flow.client._release()
        flow.server._release()
        return rows

    def _transaction(
        self, flow: _HttpFlow, request: _HttpMessage | None, response: _HttpMessage | None
    ) -> dict[str, Any]:
        flow.index += 1
        client_ip, client_port = flow.client_endpoint or ("", 0)
        server_ip, server_port = flow.server_endpoint or ("", 0)

        fields: dict[str, Any] = {
            "protocol": "tcp",
            "src_port": client_port,
            "dst_port": server_port,
            "http_transaction_index": flow.index,
        }

        records: set[tuple[int, int]] = set()
        if request is not None:
            records |= request.records
            fields["http_method"] = request.method
            fields["http_uri"] = request.uri
            fields["http_protocol"] = request.protocol
            fields["http_request_full"] = f"{request.method} {request.uri} {request.protocol}"
            fields["http_request_bytes"] = request.wire_bytes
            if request.body_bytes:
                fields["http_request_body_bytes"] = request.body_bytes
        else:
            fields["http_request_missing"] = "true"

        if response is not None:
            records |= response.records
            fields["status_code"] = response.status
            if response.reason:
                fields["http_status_reason"] = response.reason
            if not request:
                fields["http_protocol"] = response.protocol
            fields["http_response_bytes"] = response.wire_bytes
            fields["http_response_body_bytes"] = response.body_bytes
            if response.content_encoding:
                fields["http_content_encoding"] = response.content_encoding
                if response.decoded_body_bytes >= 0:
                    fields["http_response_body_decoded_bytes"] = response.decoded_body_bytes
                else:
                    fields["http_response_body_decode_failed"] = "true"
        else:
            fields["http_response_missing"] = "true"

        source = request or response
        if source is None:  # never called with neither; keeps the row well-formed if it is
            source = _HttpMessage(True, flow.last_ts)
        incomplete = (
            request is None or response is None or not request.complete or not response.complete
        )
        if incomplete:
            fields["http_incomplete"] = "true"
            self.incomplete += 1
        if (request and request.gap) or (response and response.gap):
            fields["reassembly_gap"] = "true"
        if (request and request.truncated) or (response and response.truncated):
            fields["reassembly_truncated_capture"] = "true"

        fields["reassembled"] = "true"
        fields["packet_count"] = len(records)

        end_ts = (response or source).end_ts
        if end_ts > source.start_ts:
            fields["duration_ms"] = (end_ts - source.start_ts) // 1000

        self.emitted += 1
        row: dict[str, Any] = {
            "datetime": to_iso8601(source.start_ts, unit="us"),
            "timestamp_desc": "HTTP Request Time",
            "message": _build_transaction_message(
                client_ip, client_port, server_ip, server_port, fields
            ),
            "data_type": "network:http:transaction",
            "timestamp": source.start_ts,
            "source": self.source_file,
            "src_ip": client_ip,
            "dst_ip": server_ip,
        }
        row.update(fields)
        return row

    def flush(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for flow in list(self.flows.values()):
            rows.extend(self._finalize(flow))
        self.flows.clear()
        return rows


def _build_transaction_message(
    client_ip: str, client_port: int, server_ip: str, server_port: int, fields: dict[str, Any]
) -> str:
    request = fields.get("http_request_full") or "(request not captured)"
    status = fields.get("status_code")
    outcome = str(status) if status else "no response"
    return (
        f"HTTP {_addr(client_ip, client_port)} -> {_addr(server_ip, server_port)} "
        f'"{request}" {outcome}'
    )


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


def _new_stats() -> dict[str, Any]:
    """A fresh per-run statistics accumulator."""
    return {
        "files_skipped_unsupported": 0,
        "packets_malformed": 0,
        "packets_skipped_unsupported_linktype": 0,
        "packets_skipped_by_time": 0,
        "transactions_reassembled": 0,
        "transactions_incomplete": 0,
        "flows_evicted": 0,
        "rows_by_protocol": {},
    }


def _iter_packets_from_file(
    path: Path,
    since_us: int | None,
    until_us: int | None,
    stats: dict[str, Any],
    want_tcp_payload: bool = False,
) -> Iterator[tuple[dict[str, Any], bytes, int]]:
    """Yield ``(row, tcp_payload, ts_us)`` for one capture file, in file order.

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
                row, payload = _build_row(
                    ts_us,
                    link_type_name,
                    interface,
                    captured_length,
                    packet_length,
                    raw_bytes,
                    source_str,
                    want_tcp_payload=want_tcp_payload,
                )
            except _MalformedPacket:
                stats["packets_malformed"] += 1
                continue

            protocol = row["protocol"]
            stats["rows_by_protocol"][protocol] = stats["rows_by_protocol"].get(protocol, 0) + 1
            yield row, payload, ts_us

    except (struct.error, PcapParseError) as exc:
        stats["files_skipped_unsupported"] += 1
        ui.warning(f"Corrupt or truncated capture, stopping at the failure point: {path} ({exc})")
    finally:
        fh.close()


def _iter_rows_from_file(
    path: Path, since_us: int | None, until_us: int | None, stats: dict[str, Any]
) -> Iterator[dict[str, Any]]:
    """Yield the packet rows for one capture file, in file order."""
    for row, _payload, _ts_us in _iter_packets_from_file(path, since_us, until_us, stats):
        yield row


def _iter_transactions_from_file(
    path: Path,
    since_us: int | None,
    until_us: int | None,
    stats: dict[str, Any],
    spill_dir: Path | None,
) -> Iterator[dict[str, Any]]:
    """Yield one capture file's ``network:http:transaction`` rows, time-sorted.

    A transaction row is produced when its *response* completes but is stamped
    with the time of its request's first captured byte, so the reassembler's
    output is not in timestamp order and cannot be fed to the k-way merge as
    is. This is a second, lazy pass over the same file: it re-decodes the
    packets (cheap relative to the I/O, and only when ``--reassemble`` is
    given), keeps only the derived rows, and sorts them — spilling to disk in
    chunks so a capture with very many transactions does not have to hold them
    all in memory.

    Only packets that survive ``--since``/``--until`` are fed in, so a filtered
    capture reassembles exactly the packet rows it emitted.
    """
    # Packet-level counters were already tallied by the packet pass; a throwaway
    # accumulator keeps this pass from counting every packet twice.
    pass_stats = _new_stats()
    reassembler = _HttpReassembler(str(path.resolve()))

    def produce() -> Iterator[dict[str, Any]]:
        for row, payload, ts_us in _iter_packets_from_file(
            path, since_us, until_us, pass_stats, want_tcp_payload=True
        ):
            if row["protocol"] != "tcp":
                continue
            yield from reassembler.handle(row, payload, ts_us)
        # Connections still open at end of file: their in-flight request is
        # emitted as incomplete rather than dropped.
        yield from reassembler.flush()

    yield from _sort_rows(produce(), spill_dir)
    stats["transactions_reassembled"] += reassembler.emitted
    stats["transactions_incomplete"] += reassembler.incomplete
    stats["flows_evicted"] += reassembler.evicted


def _sort_rows(rows: Iterator[dict[str, Any]], spill_dir: Path | None) -> Iterator[dict[str, Any]]:
    """Yield ``rows`` ordered by ``timestamp``, spilling to disk in chunks.

    Up to :data:`_SORT_CHUNK_ROWS` rows are sorted in memory at a time; every
    full chunk is written to a temporary JSONL file and the chunks are merged
    on the way out, so peak memory stays bounded regardless of row count.
    """
    chunk: list[dict[str, Any]] = []
    spill_paths: list[Path] = []

    def spill(sorted_chunk: list[dict[str, Any]]) -> None:
        handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".pcapsort.jsonl", dir=spill_dir, delete=False
        )
        for row in sorted_chunk:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        handle.close()
        spill_paths.append(Path(handle.name))

    try:
        for row in rows:
            chunk.append(row)
            if len(chunk) >= _SORT_CHUNK_ROWS:
                chunk.sort(key=lambda r: r["timestamp"])
                spill(chunk)
                chunk = []
        chunk.sort(key=lambda r: r["timestamp"])
        if not spill_paths:
            yield from chunk
            return
        if chunk:
            spill(chunk)
        yield from heapq.merge(
            *(_iter_jsonl_rows(p) for p in spill_paths), key=lambda r: r["timestamp"]
        )
    finally:
        for path in spill_paths:
            path.unlink(missing_ok=True)


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
    reassemble: str | None = None,
) -> Iterator[dict[str, Any]]:
    """Merge rows from many capture files into one chronological stream.

    ``heapq.merge`` over thousands of files would hold one file descriptor per
    file, quickly exhausting the process limit.  This implementation merges in
    chunks of :data:`_MAX_MERGE_STREAMS` files and spills intermediate results
    to temporary JSONL files, so the number of simultaneously open descriptors
    stays bounded.

    With ``reassemble="http"`` each file contributes a second stream of derived
    transaction rows, sorted by :func:`_iter_transactions_from_file` before it
    reaches the merge.
    """
    streams: list[Iterator[dict[str, Any]]] = [
        _iter_rows_from_file(f, since_us, until_us, stats) for f in files
    ]
    if reassemble == "http":
        streams.extend(
            _iter_transactions_from_file(f, since_us, until_us, stats, spill_dir) for f in files
        )

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
    split: str | None = None,
    reassemble: str | None = None,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, Any]:
    """Convert pcap/pcapng captures under ``input_path`` to a Timesketch timeline.

    Every discovered file is decoded lazily and merged into one globally
    chronological output via a k-way merge (stdlib ``heapq.merge``), rather
    than buffering every row in memory.  The merge is performed in chunks so
    the number of simultaneously open capture files is bounded, preventing
    "Too many open files" errors on large captures.

    ``reassemble="http"`` additionally emits one ``network:http:transaction``
    row per reassembled HTTP/1.x request/response pair, on top of — never
    instead of — the packet rows.

    Returns:
        Statistics dict with ``rows_written``, ``files_processed``, and
        per-file/per-packet skip/error counters.
    """
    files = _find_pcap_files(input_path)
    if not files:
        raise ConverterError(f"No pcap/pcapng files found in: {input_path}")

    ui = get_terminal()
    badges = [("network", "accent"), (output_format, "muted")]
    if reassemble:
        badges.append((f"reassemble:{reassemble}", "purple"))
    ui.header(
        "pcap2timesketch",
        subtitle="Convert pcap/pcapng captures → Timesketch timeline",
        badges=badges,
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

    writer = OutputWriter(output, output_format, compute_hash=report_path is not None, split=split)

    stats: dict[str, Any] = _new_stats()

    spill_dir: Path | None = None
    if output != "-":
        spill_dir = Path(output).parent
        spill_dir.mkdir(parents=True, exist_ok=True)

    rows_written = 0
    ui.step("Processing", f"Parsing packets across {len(files)} file(s)")
    with ui.spinner("Parsing packets"):
        for row in _merge_file_streams(files, since_us, until_us, stats, spill_dir, reassemble):
            writer.add(row)
            rows_written += 1

    written = writer.write()

    if report:
        add_writer_output(report, writer)
        report.set_statistics({
            "rows_written": written,
            "files_processed": len(files),
            **stats,
            "since": since,
            "until": until,
            "reassemble": reassemble,
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
    if reassemble:
        summary_items["HTTP transactions"] = f"{stats['transactions_reassembled']:,}"
        summary_items["HTTP transactions (incomplete)"] = f"{stats['transactions_incomplete']:,}"
        summary_items["Flows evicted"] = f"{stats['flows_evicted']:,}"
    for protocol, count in sorted(stats["rows_by_protocol"].items()):
        summary_items[f"Protocol: {protocol}"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return {
        "rows_written": written,
        "files_processed": len(files),
        **stats,
    }
