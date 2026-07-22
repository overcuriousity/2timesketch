#!/usr/bin/env python3
"""Cowrie SSH/Telnet honeypot log to Timesketch timeline converter.

Cowrie (https://github.com/cowrie/cowrie) emits one JSON object per line
(``cowrie.json``, optionally rotated as ``cowrie.json.YYYY-MM-DD`` or
gzip-compressed). Every record carries an ``eventid`` such as
``cowrie.session.connect`` or ``cowrie.command.input``; this converter maps
each ``eventid`` onto the suite-wide ``data_type`` taxonomy
(``cowrie:<category>:<event>``) and promotes the fields Cowrie already emits
natively (``src_ip``, ``dst_ip``, ``src_port``, ``dst_port``, ``protocol``)
onto the shared timeline columns. Any event-specific field that doesn't fit
a shared role (``session``, ``username``, ``input``, ``hassh``, ...) keeps
its Cowrie-native name.
"""

from __future__ import annotations

import datetime
import gzip
import json
from pathlib import Path
from typing import Any

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

# Human-readable timestamp_desc per eventid. Any eventid not listed here
# falls back to a generic "Cowrie <eventid> Time" description.
_TIMESTAMP_DESC = {
    "cowrie.session.connect": "Session Connect Time",
    "cowrie.session.closed": "Session Closed Time",
    "cowrie.session.params": "Session Parameters Time",
    "cowrie.session.file_upload": "File Upload Time",
    "cowrie.login.success": "Login Success Time",
    "cowrie.login.failed": "Login Failed Time",
    "cowrie.command.input": "Command Input Time",
    "cowrie.command.success": "Command Success Time",
    "cowrie.command.failed": "Command Failed Time",
    "cowrie.client.version": "Client Version Time",
    "cowrie.client.kex": "Client Key Exchange Time",
    "cowrie.client.fingerprint": "Client Fingerprint Time",
    "cowrie.client.var": "Client Environment Variable Time",
    "cowrie.direct-tcpip.request": "Direct TCP Forward Request Time",
    "cowrie.direct-tcpip.data": "Direct TCP Forward Data Time",
    "cowrie.direct-tcpip.ja4": "Direct TCP JA4 Fingerprint Time",
    "cowrie.direct-tcpip.ja4h": "Direct TCP JA4H Fingerprint Time",
    "cowrie.log.closed": "TTY Log Closed Time",
    "cowrie.telnet.option": "Telnet Option Negotiation Time",
}

# Fields already promoted onto explicit row keys; skipped when flattening the
# remaining record fields onto source-native columns.
_PROMOTED_KEYS = {
    "eventid",
    "timestamp",
    "message",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "session",
    "sensor",
    "uuid",
}


class CowrieParseError(ConverterError):
    """Raised when a Cowrie JSON line cannot be parsed."""


def _data_type(eventid: str) -> str:
    """Map a Cowrie eventid onto the suite-wide data_type taxonomy."""
    rest = eventid[len("cowrie."):] if eventid.startswith("cowrie.") else eventid
    return "cowrie:" + rest.replace(".", ":")


def _timestamp_desc(eventid: str) -> str:
    return _TIMESTAMP_DESC.get(eventid, f"Cowrie {eventid} Time")


def _safe_int(value: Any) -> int | None:
    """Return ``value`` as int, or None if it is empty/non-numeric."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _build_message(record: dict[str, Any], eventid: str, dst_ip: str, dst_port: int | None) -> str:
    """Build a human-readable message, avoiding Cowrie's raw payload dumps."""
    raw = record.get("message")

    if eventid == "cowrie.direct-tcpip.data":
        data = record.get("data", "")
        data_str = data if isinstance(data, str) else str(data)
        preview = data_str[:120] + ("..." if len(data_str) > 120 else "")
        dst = f"{dst_ip}:{dst_port}" if dst_port is not None else dst_ip
        return f"Direct-tcp forward data to {dst} ({len(data_str)} chars): {preview}"

    if isinstance(raw, str) and raw.strip():
        return raw

    if eventid == "cowrie.session.params":
        return f"Session parameters: arch={record.get('arch', '')}"

    return f"Cowrie event: {eventid}"


def _flatten_extra(record: dict[str, Any]) -> dict[str, Any]:
    """Promote remaining record fields onto source-native columns."""
    extra: dict[str, Any] = {}
    for key, value in record.items():
        if key in _PROMOTED_KEYS or value is None:
            continue
        if isinstance(value, list):
            extra[key] = ",".join(str(v) for v in value)
        elif isinstance(value, dict):
            for sub_key, sub_value in value.items():
                extra[f"{key}.{sub_key}"] = sub_value
        else:
            extra[key] = value
    return extra


def _parse_line(line: str, source_file: str) -> dict[str, Any] | None:
    """Parse a single Cowrie JSON line into a Timesketch row."""
    line = line.strip()
    if not line:
        return None

    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise CowrieParseError(f"Invalid JSON: {exc}") from exc

    if not isinstance(record, dict):
        raise CowrieParseError("JSON line is not an object")

    eventid = record.get("eventid")
    ts_value = record.get("timestamp")
    if not eventid or not ts_value:
        raise CowrieParseError("record missing eventid or timestamp")

    try:
        dt = datetime.datetime.fromisoformat(str(ts_value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise CowrieParseError(f"Unrecognised timestamp format: {ts_value}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    ts_us = to_unix_microseconds(dt.astimezone(datetime.timezone.utc))

    dst_ip = normalize_ip(record.get("dst_ip", ""))
    dst_port = _safe_int(record.get("dst_port"))

    row: dict[str, Any] = {
        "datetime": to_iso8601(ts_us, unit="us"),
        "timestamp": ts_us,
        "timestamp_desc": _timestamp_desc(eventid),
        "message": _build_message(record, eventid, dst_ip, dst_port),
        "data_type": _data_type(eventid),
        "source": source_file,
        "src_ip": normalize_ip(record.get("src_ip", "")),
        "dst_ip": dst_ip,
        "src_port": _safe_int(record.get("src_port")),
        "dst_port": dst_port,
        "protocol": record.get("protocol", ""),
        "eventid": eventid,
        "session": record.get("session", ""),
        "sensor": record.get("sensor", ""),
        "uuid": record.get("uuid", ""),
    }
    row.update(_flatten_extra(record))
    return row


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _find_log_files(input_path: str) -> list[Path]:
    """Resolve the input path into a list of Cowrie log files."""
    path = Path(input_path)

    if path.is_file():
        return [path]

    if path.is_dir():
        files: set[Path] = set()
        for pattern in ("cowrie.json", "cowrie.json.*", "cowrie.json*.gz"):
            files.update(path.rglob(pattern))
        return sorted(files)

    raise ConverterError(f"Input path not found: {input_path}")


def convert_cowrie(
    input_path: str,
    output: str,
    output_format: str,
    since: str | None = None,
    until: str | None = None,
    verbose: bool = True,
    split: str | None = None,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, Any]:
    """Convert Cowrie honeypot logs to a Timesketch timeline.

    Returns:
        Statistics dict with ``rows_written``, ``files_processed``,
        ``parse_errors``, ``rows_skipped_by_time``, and
        ``rows_by_eventid``.
    """
    files = _find_log_files(input_path)
    if not files:
        raise ConverterError(f"No Cowrie log files found in: {input_path}")

    ui = get_terminal()
    ui.header(
        "cowrie2timesketch",
        subtitle="Convert Cowrie SSH/Telnet honeypot logs → Timesketch timeline",
        badges=[("honeypot", "danger"), (output_format, "muted")],
    )
    ui.step("Files found", f"{len(files)} Cowrie log file(s)")

    since_dt: datetime.datetime | None = None
    until_dt: datetime.datetime | None = None
    if since:
        since_dt = datetime.datetime.fromisoformat(since.replace("Z", "+00:00"))
        if since_dt.tzinfo is None:
            since_dt = since_dt.replace(tzinfo=datetime.timezone.utc)
    if until:
        until_dt = datetime.datetime.fromisoformat(until.replace("Z", "+00:00"))
        if until_dt.tzinfo is None:
            until_dt = until_dt.replace(tzinfo=datetime.timezone.utc)

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("cowrie2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)

    writer = OutputWriter(output, output_format, compute_hash=report_path is not None, split=split)
    rows_written = 0
    files_processed = 0
    parse_errors = 0
    skipped_by_time = 0
    eventid_counts: dict[str, int] = {}
    _parse_error_samples: list[str] = []

    for idx, log_file in enumerate(files, start=1):
        ui.progress(idx, len(files), label=str(log_file))
        source_str = str(log_file.resolve())

        try:
            with _open_log(log_file) as fh:
                for line in fh:
                    if not line.strip():
                        continue

                    try:
                        row = _parse_line(line, source_str)
                    except CowrieParseError as exc:
                        parse_errors += 1
                        if len(_parse_error_samples) < 3:
                            _parse_error_samples.append(f"{log_file}: {exc}")
                        continue

                    if row is None:
                        continue

                    ts = row.get("timestamp", 0)
                    if since_dt and ts and ts < to_unix_microseconds(since_dt):
                        skipped_by_time += 1
                        continue
                    if until_dt and ts and ts > to_unix_microseconds(until_dt):
                        skipped_by_time += 1
                        continue

                    eventid = row.get("eventid", "unknown")
                    eventid_counts[eventid] = eventid_counts.get(eventid, 0) + 1

                    writer.add(row)
                    rows_written += 1
        except OSError as exc:
            raise ConverterError(f"Failed to read {log_file}: {exc}") from exc

        files_processed += 1

    ui.end_progress()

    for sample in _parse_error_samples:
        ui.warning(sample)

    written = writer.write()

    if report:
        add_writer_output(report, writer)
        report.set_statistics({
            "rows_written": written,
            "files_processed": files_processed,
            "parse_errors": parse_errors,
            "rows_skipped_by_time": skipped_by_time,
            "rows_by_eventid": eventid_counts,
            "since": since,
            "until": until,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    summary_items: dict[str, Any] = {
        "Rows written": f"{written:,}",
        "Files processed": f"{files_processed}/{len(files)}",
        "Parse errors": f"{parse_errors:,}",
        "Skipped by time": f"{skipped_by_time:,}",
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
    }
    for eventid, count in sorted(eventid_counts.items()):
        summary_items[f"Event: {eventid}"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return {
        "rows_written": written,
        "files_processed": files_processed,
        "parse_errors": parse_errors,
        "rows_skipped_by_time": skipped_by_time,
        "rows_by_eventid": eventid_counts,
    }
