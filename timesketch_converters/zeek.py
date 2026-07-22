#!/usr/bin/env python3
"""Zeek (Bro) NSM log to Timesketch timeline converter.

Zeek (https://zeek.org/) writes structured TSV logs - ``conn.log``,
``dns.log``, ``http.log``, ``ssl.log``, ``files.log``, ``notice.log``,
``weird.log``, and many more - each carrying metadata headers
(``#separator``, ``#fields``, ``#types``, ``#path``, ...) that describe the
column layout. This converter parses those headers generically, so *any*
Zeek log type works (including custom/local scripts) without a per-type
schema; rotated ZeekControl files and gzip-compressed logs are supported as
well.

The 4-tuple fields are promoted (renamed) onto the suite-wide shared
columns - ``id.orig_h`` -> ``src_ip``, ``id.resp_h`` -> ``dst_ip``,
``id.orig_p`` -> ``src_port``, ``id.resp_p`` -> ``dst_port`` - and
http.log's ``host``/``uri`` become ``host``/``url``. Every other field keeps
its Zeek-native name. Each log type maps onto the ``zeek:<path>:<event>``
data_type taxonomy. Multiple log files are merged into one globally
time-sorted timeline via a streaming k-way merge (stdlib ``heapq.merge``).
"""

from __future__ import annotations

import datetime
import gzip
import heapq
from pathlib import Path
from typing import Any, Iterator

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

# Per-path event name for the data_type taxonomy. Any #path not listed here
# falls back to ``zeek:<path>:log``.
_DATA_TYPE_EVENT = {
    "conn": "connection",
    "dns": "query",
    "http": "request",
    "ssl": "connection",
    "ssh": "session",
    "ftp": "session",
    "smtp": "message",
    "files": "file",
    "notice": "alert",
    "weird": "anomaly",
    "x509": "certificate",
    "software": "software",
    "kerberos": "request",
    "ntlm": "authentication",
    "rdp": "connection",
    "dhcp": "lease",
    "sip": "call",
    "snmp": "query",
    "irc": "message",
    "dce_rpc": "call",
    "smb_files": "file_access",
    "smb_mapping": "share_access",
    "tunnel": "tunnel",
    "dpd": "protocol_violation",
    "known_hosts": "host",
    "known_services": "service",
    "known_certs": "certificate",
    "traceroute": "traceroute",
    "pe": "binary",
}

# Human-readable timestamp_desc per #path.
_TIMESTAMP_DESC = {
    "conn": "Connection Time",
    "dns": "DNS Query Time",
    "http": "HTTP Request Time",
    "ssl": "TLS Connection Time",
    "ssh": "SSH Session Time",
    "ftp": "FTP Session Time",
    "smtp": "SMTP Message Time",
    "files": "File Analysis Time",
    "notice": "Notice Time",
    "weird": "Weird Activity Time",
    "x509": "Certificate Seen Time",
    "software": "Software Seen Time",
    "kerberos": "Kerberos Request Time",
    "ntlm": "NTLM Authentication Time",
    "rdp": "RDP Connection Time",
    "dhcp": "DHCP Lease Time",
    "sip": "SIP Call Time",
    "snmp": "SNMP Query Time",
    "irc": "IRC Message Time",
    "dce_rpc": "DCE/RPC Call Time",
    "smb_files": "SMB File Access Time",
    "smb_mapping": "SMB Share Access Time",
    "tunnel": "Tunnel Time",
    "dpd": "Protocol Violation Time",
    "known_hosts": "Known Host Time",
    "known_services": "Known Service Time",
    "known_certs": "Known Certificate Time",
    "traceroute": "Traceroute Time",
    "pe": "PE Binary Time",
}

# Fields promoted onto explicit/shared row keys; skipped when copying the
# remaining record fields onto Zeek-native columns.
_PROMOTED_KEYS = {"ts", "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p"}


class ZeekParseError(ConverterError):
    """Raised when a Zeek log line cannot be parsed."""


def _data_type(zpath: str) -> str:
    event = _DATA_TYPE_EVENT.get(zpath, "log")
    return f"zeek:{zpath}:{event}"


def _timestamp_desc(zpath: str) -> str:
    return _TIMESTAMP_DESC.get(zpath, f"Zeek {zpath} Time")


def _safe_int(value: Any) -> int | None:
    """Return ``value`` as int, or None if it is empty/non-numeric."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _decode_separator(value: str) -> str:
    """Decode a Zeek ``#separator`` value such as ``\\x09``."""
    return value.encode("utf-8").decode("unicode_escape")


def _parse_open_time(value: str) -> int:
    """Parse a Zeek ``#open``/``#close`` timestamp (``YYYY-MM-DD-HH-MM-SS``)."""
    try:
        dt = datetime.datetime.strptime(value, "%Y-%m-%d-%H-%M-%S")
    except ValueError:
        return 0
    return to_unix_microseconds(dt.replace(tzinfo=datetime.timezone.utc))


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _iter_zeek_rows(
    log_file: Path, stats: dict[str, Any]
) -> Iterator[tuple[int, str, dict[str, str], str]]:
    """Yield ``(timestamp_us, zeek_path, record, source)`` tuples from a log.

    Header directives are re-read whenever they appear, so concatenated logs
    with multiple ``#open``/``#close`` blocks are handled. Malformed rows are
    counted in ``stats`` and skipped.
    """
    separator = "\t"
    empty_field = "(empty)"
    unset_field = "-"
    zpath = log_file.name
    fields: list[str] = []
    open_ts_us = 0
    source_str = str(log_file.resolve())

    with _open_log(log_file) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue

            if line.startswith("#"):
                # Directive names are followed either by a space
                # (#separator \x09, #path conn, #open ...) or by the field
                # separator itself (#fields<TAB>..., #types<TAB>...).
                body = line[1:]
                space_at = body.find(" ")
                sep_at = body.find(separator)
                if space_at != -1 and (sep_at == -1 or space_at < sep_at):
                    directive, value = body.split(" ", 1)
                elif sep_at != -1:
                    directive, value = body.split(separator, 1)
                else:
                    directive, value = body, ""
                if directive == "separator":
                    separator = _decode_separator(value)
                elif directive == "empty_field":
                    empty_field = value
                elif directive == "unset_field":
                    unset_field = value
                elif directive == "path":
                    zpath = value
                elif directive == "open":
                    open_ts_us = _parse_open_time(value)
                elif directive == "fields":
                    fields = value.split(separator)
                continue

            try:
                if not fields:
                    raise ZeekParseError("data row before #fields header")
                values = line.split(separator)
                if len(values) != len(fields):
                    raise ZeekParseError(
                        f"row has {len(values)} fields, expected {len(fields)}"
                    )
                record = {
                    name: ("" if value in (unset_field, empty_field) else value)
                    for name, value in zip(fields, values)
                }
                ts_us = open_ts_us
                ts_raw = record.get("ts", "")
                if ts_raw:
                    try:
                        ts_us = int(float(ts_raw) * 1_000_000)
                    except ValueError:
                        raise ZeekParseError(
                            f"unrecognised ts value: {ts_raw!r}"
                        ) from None
            except ZeekParseError as exc:
                stats["parse_errors"] += 1
                if len(stats["samples"]) < 3:
                    stats["samples"].append(f"{log_file}: {exc}")
                continue

            yield ts_us, zpath, record, source_str


def _with_progress(
    it: Iterator[tuple[int, str, dict[str, str], str]],
    idx: int,
    total: int,
    label: str,
) -> Iterator[tuple[int, str, dict[str, str], str]]:
    """Yield from ``it``, then report one unit of progress."""
    yield from it
    get_terminal().progress(idx, total, label=label)


def _msg_conn(record: dict[str, str], src_ip: str, dst_ip: str,
              src_port: int | None, dst_port: int | None) -> str:
    proto = (record.get("proto") or "").upper() or "IP"
    msg = f"{proto} {src_ip}:{src_port or '?'} -> {dst_ip}:{dst_port or '?'}"
    details = []
    if record.get("conn_state"):
        details.append(f"state {record['conn_state']}")
    if record.get("service"):
        details.append(f"service {record['service']}")
    orig = record.get("orig_bytes") or "0"
    resp = record.get("resp_bytes") or "0"
    details.append(f"orig {orig} B / resp {resp} B")
    return f"{msg} ({', '.join(details)})"


def _msg_dns(record: dict[str, str], *_: Any) -> str:
    query = record.get("query") or "?"
    qtype = record.get("qtype_name") or record.get("qtype") or ""
    msg = f"DNS query {query}"
    if qtype:
        msg += f" ({qtype})"
    answers = record.get("answers") or ""
    if answers:
        msg += f" -> {answers}"
    return msg


def _msg_http(record: dict[str, str], *_: Any) -> str:
    method = record.get("method") or "HTTP"
    target = f"{record.get('host', '')}{record.get('uri', '')}" or "?"
    msg = f"{method} {target}"
    if record.get("status_code"):
        msg += f" [{record['status_code']}]"
    return msg


def _msg_ssl(record: dict[str, str], src_ip: str, dst_ip: str,
             src_port: int | None, dst_port: int | None) -> str:
    msg = f"TLS {src_ip}:{src_port or '?'} -> {dst_ip}:{dst_port or '?'}"
    details = []
    if record.get("server_name"):
        details.append(f"SNI {record['server_name']}")
    if record.get("version"):
        details.append(record["version"])
    if record.get("validation_status"):
        details.append(f"cert {record['validation_status']}")
    if details:
        msg += f" ({', '.join(details)})"
    return msg


def _msg_files(record: dict[str, str], *_: Any) -> str:
    name = record.get("filename") or record.get("fuid") or "?"
    details = []
    if record.get("mime_type"):
        details.append(record["mime_type"])
    if record.get("seen_bytes"):
        details.append(f"{record['seen_bytes']} bytes")
    if record.get("sha256"):
        details.append(f"sha256 {record['sha256']}")
    msg = f"File {name}"
    if details:
        msg += f" ({', '.join(details)})"
    return msg


def _msg_notice(record: dict[str, str], *_: Any) -> str:
    note = record.get("note") or "?"
    msg = record.get("msg") or ""
    return f"Notice {note}: {msg}" if msg else f"Notice {note}"


def _msg_weird(record: dict[str, str], *_: Any) -> str:
    name = record.get("name") or "?"
    addl = record.get("addl") or ""
    return f"Weird {name}: {addl}" if addl else f"Weird {name}"


def _msg_x509(record: dict[str, str], *_: Any) -> str:
    subject = record.get("certificate.subject") or record.get("id") or "?"
    return f"X.509 certificate {subject}"


def _msg_ssh(record: dict[str, str], src_ip: str, dst_ip: str,
             src_port: int | None, dst_port: int | None) -> str:
    msg = f"SSH {src_ip}:{src_port or '?'} -> {dst_ip}:{dst_port or '?'}"
    if record.get("auth_success"):
        msg += f" (auth_success={record['auth_success']})"
    if record.get("client"):
        msg += f" [{record['client']}]"
    return msg


def _msg_smtp(record: dict[str, str], *_: Any) -> str:
    mailfrom = record.get("mailfrom") or "?"
    rcptto = record.get("rcptto") or "?"
    msg = f"SMTP mail from {mailfrom} to {rcptto}"
    if record.get("subject"):
        msg += f" (subject: {record['subject']})"
    return msg


def _msg_ftp(record: dict[str, str], src_ip: str, dst_ip: str, *_: Any) -> str:
    command = record.get("command") or "?"
    arg = record.get("arg") or ""
    msg = f"FTP {command} {arg}".rstrip()
    return f"{msg} ({src_ip} -> {dst_ip})"


def _msg_dhcp(record: dict[str, str], *_: Any) -> str:
    mac = record.get("mac") or "?"
    assigned = record.get("assigned_addr") or "?"
    return f"DHCP {mac} assigned {assigned}"


def _msg_software(record: dict[str, str], *_: Any) -> str:
    name = record.get("name") or "?"
    version = record.get("version.addl") or record.get("version.major") or ""
    host = record.get("host") or "?"
    msg = f"Software {name}"
    if version:
        msg += f" {version}"
    return f"{msg} on {host}"


_MESSAGE_BUILDERS = {
    "conn": _msg_conn,
    "dns": _msg_dns,
    "http": _msg_http,
    "ssl": _msg_ssl,
    "files": _msg_files,
    "notice": _msg_notice,
    "weird": _msg_weird,
    "x509": _msg_x509,
    "ssh": _msg_ssh,
    "smtp": _msg_smtp,
    "ftp": _msg_ftp,
    "dhcp": _msg_dhcp,
    "software": _msg_software,
}


def _build_message(zpath: str, record: dict[str, str], src_ip: str, dst_ip: str,
                   src_port: int | None, dst_port: int | None) -> str:
    builder = _MESSAGE_BUILDERS.get(zpath)
    if builder is not None:
        return builder(record, src_ip, dst_ip, src_port, dst_port)
    uid = record.get("uid", "")
    return f"Zeek {zpath} event" + (f" ({uid})" if uid else "")


def _build_row(
    ts_us: int, zpath: str, record: dict[str, str], source_file: str
) -> dict[str, Any]:
    """Map a parsed Zeek record onto a Timesketch row."""
    src_ip = normalize_ip(record.get("id.orig_h", ""))
    dst_ip = normalize_ip(record.get("id.resp_h", ""))
    src_port = _safe_int(record.get("id.orig_p"))
    dst_port = _safe_int(record.get("id.resp_p"))

    row: dict[str, Any] = {
        "datetime": to_iso8601(ts_us, unit="us"),
        "timestamp": ts_us,
        "timestamp_desc": _timestamp_desc(zpath),
        "message": _build_message(zpath, record, src_ip, dst_ip, src_port, dst_port),
        "data_type": _data_type(zpath),
        "source": source_file,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port if src_port is not None else "",
        "dst_port": dst_port if dst_port is not None else "",
        "zeek_log": zpath,
    }

    for key, value in record.items():
        if key in _PROMOTED_KEYS or value == "":
            continue
        if zpath == "http" and key in ("host", "uri"):
            continue
        row[key] = value

    if zpath == "http":
        host = record.get("host", "")
        uri = record.get("uri", "")
        if host:
            row["host"] = host
        if host or uri:
            row["url"] = f"{host}{uri}"

    return row


def _find_log_files(input_path: str) -> list[Path]:
    """Resolve the input path into a list of Zeek log files."""
    path = Path(input_path)

    if path.is_file():
        return [path]

    if path.is_dir():
        files: set[Path] = set()
        for pattern in ("*.log", "*.log.gz"):
            files.update(path.rglob(pattern))
        return sorted(files)

    raise ConverterError(f"Input path not found: {input_path}")


def _parse_time_boundary(value: str) -> datetime.datetime:
    dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def convert_zeek(
    input_path: str,
    output: str,
    output_format: str,
    output_dir: str | None = None,
    since: str | None = None,
    until: str | None = None,
    verbose: bool = True,
    split: str | None = None,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, Any]:
    """Convert Zeek NSM logs to a Timesketch timeline.

    Returns:
        Statistics dict with ``rows_written``, ``files_processed``,
        ``parse_errors``, ``rows_skipped_by_time``, and ``rows_by_log``.
    """
    files = _find_log_files(input_path)
    if not files:
        raise ConverterError(f"No Zeek log files found in: {input_path}")

    ui = get_terminal()
    ui.header(
        "zeek2timesketch",
        subtitle="Convert Zeek NSM logs → Timesketch timeline",
        badges=[("nsm", "info"), (output_format, "muted")],
    )
    ui.step("Files found", f"{len(files)} Zeek log file(s)")

    since_dt = _parse_time_boundary(since) if since else None
    until_dt = _parse_time_boundary(until) if until else None
    since_us = to_unix_microseconds(since_dt) if since_dt else None
    until_us = to_unix_microseconds(until_dt) if until_dt else None

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("zeek2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)

    stats: dict[str, Any] = {"parse_errors": 0, "samples": []}
    rows_skipped_by_time = 0
    rows_by_log: dict[str, int] = {}
    compute_hash = report_path is not None

    def in_time_range(ts_us: int) -> bool:
        nonlocal rows_skipped_by_time
        if ts_us and since_us is not None and ts_us < since_us:
            rows_skipped_by_time += 1
            return False
        if ts_us and until_us is not None and ts_us > until_us:
            rows_skipped_by_time += 1
            return False
        return True

    merged = heapq.merge(
        *(
            _with_progress(_iter_zeek_rows(f, stats), idx, len(files), str(f))
            for idx, f in enumerate(files, start=1)
        ),
        key=lambda item: item[0],
    )

    written = 0

    if output_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        writers: dict[str, OutputWriter] = {}
        counts: dict[str, int] = {}

        for ts_us, zpath, record, source_str in merged:
            if not in_time_range(ts_us):
                continue
            writer = writers.get(zpath)
            if writer is None:
                dest = out_dir / f"timesketch_{zpath}.{output_format}"
                writer = OutputWriter(
                    str(dest), output_format, compute_hash=compute_hash, split=split
                )
                writers[zpath] = writer
                counts[zpath] = 0
            writer.add(_build_row(ts_us, zpath, record, source_str))
            counts[zpath] += 1
            rows_by_log[zpath] = rows_by_log.get(zpath, 0) + 1

        ui.end_progress()

        for zpath, writer in sorted(writers.items()):
            dest = out_dir / f"timesketch_{zpath}.{output_format}"
            written += writer.write()
            if report:
                add_writer_output(report, writer)
            ui.success(f"Wrote {counts[zpath]:,} rows to {dest}")
    else:
        writer = OutputWriter(
            output, output_format, compute_hash=compute_hash, split=split
        )

        for ts_us, zpath, record, source_str in merged:
            if not in_time_range(ts_us):
                continue
            writer.add(_build_row(ts_us, zpath, record, source_str))
            rows_by_log[zpath] = rows_by_log.get(zpath, 0) + 1

        ui.end_progress()
        written = writer.write()

        if report:
            add_writer_output(report, writer)

    for sample in stats["samples"]:
        ui.warning(sample)

    if report:
        report.set_statistics({
            "rows_written": written,
            "files_processed": len(files),
            "parse_errors": stats["parse_errors"],
            "rows_skipped_by_time": rows_skipped_by_time,
            "rows_by_log": rows_by_log,
            "since": since,
            "until": until,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    summary_items: dict[str, Any] = {
        "Rows written": f"{written:,}",
        "Files processed": f"{len(files)}",
        "Parse errors": f"{stats['parse_errors']:,}",
        "Skipped by time": f"{rows_skipped_by_time:,}",
        "Output": output_dir or (output if output != "-" else "stdout"),
        "Format": output_format,
    }
    for zpath, count in sorted(rows_by_log.items()):
        summary_items[f"Log: {zpath}"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return {
        "rows_written": written,
        "files_processed": len(files),
        "parse_errors": stats["parse_errors"],
        "rows_skipped_by_time": rows_skipped_by_time,
        "rows_by_log": rows_by_log,
    }
