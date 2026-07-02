#!/usr/bin/env python3
"""Suricata IDS/IPS log to Timesketch timeline converter.

Supports three input formats:

- **EVE JSON** (``eve.json``): one JSON object per line, Suricata's native
  structured output. Any ``event_type`` is accepted; alerts are summarised by
  their signature, all other events by event type and key fields.
- **fast.log**: Suricata's classic single-line alert format.
- **OPNsense syslog export**: tab-separated syslog lines where the message
  payload is a fast.log-style alert, optionally prefixed with markers such as
  ``[wDrop]``.

The format is auto-detected line-by-line, so a single input can mix formats if
necessary.
"""

from __future__ import annotations

import datetime
import gzip
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from .common import (
    AuditReport,
    ConverterError,
    OutputWriter,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal


# Standard Suricata fast.log alert line.
# Example:
#   03/21/2021-20:24:02.524057 [**] [1:2006380:14] ET POLICY ... [**]
#   [Classification: Potential Corporate Privacy Violation] [Priority: 1]
#   {TCP} 192.168.10.14:48820 -> 192.168.10.18:8086
_FASTLOG_RE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.+?)\s+\[\*\*\]\s+"
    r"(?:\[Classification:\s*(?P<class>[^\]]+)\]\s+)?"
    r"(?:\[Priority:\s*(?P<priority>\d+)\]\s+)?"
    r"\{(?P<proto>[^}]+)\}\s+"
    r"(?P<src_ip>\S+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>\S+):(?P<dst_port>\d+)\s*$"
)

# OPNsense syslog export:
#   2026-07-02T19:51:58\tNotice\tsuricata\t [1:2101129:10] GPL WEB_SERVER ...
# The message payload after the tab-separated syslog header is a fast.log-style
# alert, optionally prefixed with [wDrop] or similar markers.
_OPNSENSE_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:[+-]\d{2}:?\d{2})?)\t"
    r"(?P<level>[^\t]+)\t"
    r"(?P<program>[^\t]+)\t"
    r"(?P<msg>.*)$"
)

# Alert payload used inside an OPNsense syslog message (and also the core of
# fast.log).  It may carry an optional action marker such as [wDrop].
_ALERT_PAYLOAD_RE = re.compile(
    r"^\s*(?:\[(?P<marker>[^\]]+)\]\s+)?"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.+?)\s+"
    r"(?:\[Classification:\s*(?P<class>[^\]]+)\]\s+)?"
    r"(?:\[Priority:\s*(?P<priority>\d+)\]\s+)?"
    r"\{(?P<proto>[^}]+)\}\s+"
    r"(?P<src_ip>\S+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>\S+):(?P<dst_port>\d+)\s*$"
)

# IPv4/IPv6 with optional port suffix, used as a fallback for the connection
# tuple when only the IP flow can be extracted.
_FLOW_RE = re.compile(
    r"(?P<src_ip>[0-9a-fA-F:.]+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>[0-9a-fA-F:.]+):(?P<dst_port>\d+)"
)

# Generic Suricata informational line, e.g.:
#   [102042] <Notice> -- rule reload complete
_GENERIC_NOTICE_RE = re.compile(
    r"^\[(?P<pid>\d+)\]\s+<(?P<level>[^>]+)>\s+--\s+(?P<text>.*)$"
)


class SuricataParseError(ConverterError):
    """Raised when a Suricata line cannot be parsed."""


def _parse_timestamp(value: str) -> tuple[datetime.datetime, int]:
    """Parse a Suricata timestamp string and return (UTC datetime, microseconds).

    Accepts:
    - EVE JSON ISO 8601: ``2025-07-08T09:55:36.806000-0400``
    - fast.log: ``03/21/2021-20:24:02.524057``
    - OPNsense syslog: ``2026-07-02T19:51:58`` (no microseconds)

    Timestamps without timezone information are treated as UTC.
    """
    value = value.strip()

    # ISO 8601 variants (EVE JSON and OPNsense).
    iso = value.replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(iso)
    except ValueError:
        dt = None

    if dt is None:
        # fast.log: MM/DD/YYYY-HH:MM:SS.microseconds
        try:
            dt = datetime.datetime.strptime(value, "%m/%d/%Y-%H:%M:%S.%f")
        except ValueError:
            raise SuricataParseError(f"Unrecognised timestamp format: {value}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)

    dt_utc = dt.astimezone(datetime.timezone.utc)
    return dt_utc, to_unix_microseconds(dt_utc)


def _normalize_ip(value: str) -> str:
    """Validate and canonicalize an IP address, returning empty if invalid."""
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return ""


def _safe_int(value: Any) -> int | None:
    """Return ``value`` as int, or None if it is empty/non-numeric."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Recursively flatten a nested dict into dot-notation keys."""
    result: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_key = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                result.update(_flatten(value, new_key))
            else:
                result[new_key] = value
    else:
        result[prefix] = obj
    return result


def _detect_line_format(line: str) -> str:
    """Detect whether a line is EVE JSON, OPNsense syslog, or fast.log."""
    stripped = line.strip()
    if not stripped:
        return "empty"
    if stripped.startswith("{"):
        return "eve"
    if "\t" in line:
        parts = line.split("\t", 3)
        if len(parts) >= 3 and parts[2].lower() == "suricata":
            return "opnsense"
    return "fast"


def _build_alert_message(
    signature: str,
    category: str | None,
    priority: int | None,
    proto: str,
    src: str,
    dst: str,
    marker: str | None = None,
) -> str:
    """Build a concise human-readable message for an alert."""
    parts: list[str] = []
    if marker:
        parts.append(f"[{marker}]")
    parts.append(f"Suricata {proto} alert:")
    parts.append(signature)
    if category:
        parts.append(f"[{category}]")
    parts.append(f"{src} -> {dst}")
    return " ".join(parts)


def _build_eve_message(record: dict[str, Any]) -> str:
    """Build a human-readable message for an EVE JSON record."""
    event_type = record.get("event_type", "unknown")
    proto = record.get("proto", "")
    src_ip = record.get("src_ip", "")
    src_port = record.get("src_port", "")
    dest_ip = record.get("dest_ip", "")
    dest_port = record.get("dest_port", "")

    src = f"{src_ip}:{src_port}" if src_port not in (None, "") else src_ip
    dst = f"{dest_ip}:{dest_port}" if dest_port not in (None, "") else dest_ip

    alert = record.get("alert") or {}
    if alert:
        signature = alert.get("signature", "Unknown signature")
        category = alert.get("category")
        action = alert.get("action")
        parts = ["Suricata alert:"]
        if action:
            parts.append(f"[{action}]")
        parts.append(signature)
        if category:
            parts.append(f"[{category}]")
        if src or dst:
            parts.append(f"{src} -> {dst}")
        return " ".join(parts)

    # Non-alert event types.
    if event_type == "http":
        http = record.get("http") or {}
        return f"Suricata HTTP {http.get('http_method', '')} {http.get('hostname', '')}{http.get('url', '')} ({src} -> {dst})".strip()
    if event_type == "dns":
        dns = record.get("dns") or {}
        return f"Suricata DNS query {dns.get('rrname', '')} ({src} -> {dst})".strip()
    if event_type == "tls":
        tls = record.get("tls") or {}
        return f"Suricata TLS {tls.get('sni', '')} ({src} -> {dst})".strip()
    if event_type in ("flow", "netflow"):
        return f"Suricata {event_type} {proto} {src} -> {dst}"

    return f"Suricata {event_type} {proto} {src} -> {dst}".strip()


def _parse_eve_line(line: str, source_file: str) -> dict[str, Any] | None:
    """Parse a single EVE JSON line into a Timesketch row."""
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SuricataParseError(f"Invalid JSON: {exc}") from exc

    if not isinstance(record, dict):
        raise SuricataParseError("JSON line is not an object")

    event_type = record.get("event_type", "unknown")
    ts_value = record.get("timestamp", "")
    if not ts_value:
        raise SuricataParseError("EVE record missing timestamp")

    dt, ts_us = _parse_timestamp(str(ts_value))

    row: dict[str, Any] = {
        "datetime": to_iso8601(ts_us, unit="us"),
        "timestamp": ts_us,
        "timestamp_desc": f"Suricata {event_type} event time",
        "message": _build_eve_message(record),
        "data_type": "ids:alert:suricata" if event_type == "alert" else "ids:event:suricata",
        "source": source_file,
        "src_ip": normalize_ip(record.get("src_ip", "")),
        "dst_ip": normalize_ip(record.get("dest_ip", "")),
        "event_type": event_type,
        "protocol": record.get("proto", ""),
        "src_port": _safe_int(record.get("src_port")),
        "dst_port": _safe_int(record.get("dest_port")),
    }

    if event_type == "alert":
        alert = record.get("alert") or {}
        row["alert_action"] = alert.get("action", "")
        row["alert_gid"] = _safe_int(alert.get("gid"))
        row["alert_signature_id"] = _safe_int(alert.get("signature_id"))
        row["alert_rev"] = _safe_int(alert.get("rev"))
        row["alert_signature"] = alert.get("signature", "")
        row["alert_category"] = alert.get("category", "")
        severity = _safe_int(alert.get("severity"))
        priority = _safe_int(alert.get("priority"))
        # Suricata uses "severity" in EVE JSON and "Priority" in fast.log;
        # expose both names for cross-format queries.
        row["alert_severity"] = severity if severity is not None else priority
        row["alert_priority"] = priority if priority is not None else severity

    # Flatten nested structures (flow, http, dns, tls, fileinfo, etc.) so the
    # full event context is available as searchable columns.  The ``alert``
    # object is already promoted to top-level columns above.
    for key, value in record.items():
        if key in row or value is None or key == "alert":
            continue
        if isinstance(value, dict):
            row.update(_flatten(value, key))
        elif not isinstance(value, (list, dict)):
            row[key] = value

    return row


def _parse_fast_alert_match(
    match: re.Match[str],
    source_file: str,
    timestamp_str: str,
    marker: str | None = None,
) -> dict[str, Any]:
    """Turn a fast.log / OPNsense alert regex match into a Timesketch row."""
    dt, ts_us = _parse_timestamp(timestamp_str)

    src_ip = _normalize_ip(match.group("src_ip"))
    dst_ip = _normalize_ip(match.group("dst_ip"))
    src_port = _safe_int(match.group("src_port"))
    dst_port = _safe_int(match.group("dst_port"))
    src = f"{src_ip}:{src_port}" if src_port is not None else src_ip
    dst = f"{dst_ip}:{dst_port}" if dst_port is not None else dst_ip

    signature = match.group("msg").strip()
    category = (match.group("class") or "").strip()
    priority = _safe_int(match.group("priority"))
    proto = (match.group("proto") or "").strip().upper()
    gid = _safe_int(match.group("gid"))
    sid = _safe_int(match.group("sid"))
    rev = _safe_int(match.group("rev"))

    row: dict[str, Any] = {
        "datetime": to_iso8601(ts_us, unit="us"),
        "timestamp": ts_us,
        "timestamp_desc": "Suricata alert time",
        "message": _build_alert_message(signature, category or None, priority, proto, src, dst, marker),
        "data_type": "ids:alert:suricata",
        "source": source_file,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "event_type": "alert",
        "alert_action": "drop" if marker and marker.lower() == "wdrop" else "alert",
        "alert_gid": gid,
        "alert_signature_id": sid,
        "alert_rev": rev,
        "alert_signature": signature,
        "alert_category": category,
        "alert_priority": priority,
        "alert_severity": priority,
    }

    if marker:
        row["drop_marker"] = marker

    return row


def _parse_fast_line(line: str, source_file: str) -> dict[str, Any] | None:
    """Parse a classic Suricata fast.log alert line."""
    match = _FASTLOG_RE.match(line)
    if match:
        return _parse_fast_alert_match(match, source_file, match.group("ts"))

    # Fallback: generic notice line such as rule reload messages.
    generic = _GENERIC_NOTICE_RE.match(line.strip())
    if generic:
        # Best-effort timestamp extraction from the start of the line if present.
        ts_str = line.strip().split(" ", 1)[0]
        try:
            dt, ts_us = _parse_timestamp(ts_str)
        except SuricataParseError:
            return None
        return {
            "datetime": to_iso8601(ts_us, unit="us"),
            "timestamp": ts_us,
            "timestamp_desc": "Suricata notice",
            "message": generic.group("text").strip(),
            "data_type": "ids:notice:suricata",
            "source": source_file,
            "event_type": "notice",
            "suricata_pid": _safe_int(generic.group("pid")),
        }

    return None


def _parse_opnsense_line(line: str, source_file: str) -> dict[str, Any] | None:
    """Parse an OPNsense syslog export line containing a Suricata alert."""
    syslog = _OPNSENSE_SYSLOG_RE.match(line)
    if not syslog:
        return None

    timestamp_str = syslog.group("ts")
    message = syslog.group("msg")

    alert = _ALERT_PAYLOAD_RE.match(message)
    if alert:
        marker = alert.group("marker")
        return _parse_fast_alert_match(
            alert, source_file, timestamp_str, marker=marker
        )

    # Fallback: generic notice line inside syslog payload.
    generic = _GENERIC_NOTICE_RE.match(message.strip())
    if generic:
        dt, ts_us = _parse_timestamp(timestamp_str)
        return {
            "datetime": to_iso8601(ts_us, unit="us"),
            "timestamp": ts_us,
            "timestamp_desc": "Suricata notice",
            "message": generic.group("text").strip(),
            "data_type": "ids:notice:suricata",
            "source": source_file,
            "event_type": "notice",
            "suricata_pid": _safe_int(generic.group("pid")),
        }

    return None


def _parse_line(line: str, source_file: str) -> dict[str, Any] | None:
    """Parse a single Suricata line in any supported format."""
    fmt = _detect_line_format(line)
    if fmt == "empty":
        return None
    if fmt == "eve":
        return _parse_eve_line(line, source_file)
    if fmt == "opnsense":
        return _parse_opnsense_line(line, source_file)
    return _parse_fast_line(line, source_file)


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _find_log_files(input_path: str) -> list[Path]:
    """Resolve the input path into a list of Suricata log files."""
    path = Path(input_path)

    if path.is_file():
        return [path]

    if path.is_dir():
        files: set[Path] = set()
        for ext in ("*.log", "*.log.gz", "*.json", "*.json.gz"):
            files.update(path.rglob(ext))
        # Also include any file whose name contains suricata or eve.
        for candidate in path.rglob("*"):
            if candidate.is_file():
                name = candidate.name.lower()
                if "suricata" in name or "eve" in name:
                    files.add(candidate)
        return sorted(files)

    raise ConverterError(f"Input path not found: {input_path}")


def convert_suricata(
    input_path: str,
    output: str,
    output_format: str,
    since: str | None = None,
    until: str | None = None,
    verbose: bool = True,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, Any]:
    """Convert Suricata logs to a Timesketch timeline.

    Returns:
        Statistics dict with ``rows_written``, ``files_processed``,
        ``parse_errors``, ``rows_skipped_by_time``, and
        ``rows_by_event_type``.
    """
    files = _find_log_files(input_path)
    if not files:
        raise ConverterError(f"No Suricata log files found in: {input_path}")

    ui = get_terminal()
    ui.header(
        "suricata2timesketch",
        subtitle="Convert Suricata IDS/IPS logs → Timesketch timeline",
        badges=[("ids", "danger"), (output_format, "muted")],
    )
    ui.step("Files found", f"{len(files)} Suricata log file(s)")

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
        report = AuditReport("suricata2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)

    writer = OutputWriter(output, output_format, compute_hash=report_path is not None)
    rows_written = 0
    files_processed = 0
    parse_errors = 0
    skipped_by_time = 0
    event_type_counts: dict[str, int] = {}
    _parse_error_samples: list[str] = []

    for idx, log_file in enumerate(files, start=1):
        ui.progress(idx, len(files), label=str(log_file))
        source_str = str(log_file.resolve())

        try:
            with _open_log(log_file) as fh:
                for line in fh:
                    line = line.rstrip("\n\r\x00")
                    if not line.strip().strip("\x00"):
                        continue

                    try:
                        row = _parse_line(line, source_str)
                    except SuricataParseError as exc:
                        parse_errors += 1
                        if len(_parse_error_samples) < 3:
                            _parse_error_samples.append(f"{log_file}: {exc}")
                        continue

                    if row is None:
                        parse_errors += 1
                        if len(_parse_error_samples) < 3:
                            sample = line[:120] + "..." if len(line) > 120 else line
                            _parse_error_samples.append(f"{log_file}: unrecognized line: {sample}")
                        continue

                    ts = row.get("timestamp", 0)
                    if since_dt and ts and ts < to_unix_microseconds(since_dt):
                        skipped_by_time += 1
                        continue
                    if until_dt and ts and ts > to_unix_microseconds(until_dt):
                        skipped_by_time += 1
                        continue

                    event_type = row.get("event_type", "unknown")
                    event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1

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
        if output == "-":
            report.add_stdout_output(writer.content_hash)
        else:
            report.add_output_file(output, writer.content_hash)
        report.set_statistics({
            "rows_written": written,
            "files_processed": files_processed,
            "parse_errors": parse_errors,
            "rows_skipped_by_time": skipped_by_time,
            "rows_by_event_type": event_type_counts,
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
    for event_type, count in sorted(event_type_counts.items()):
        summary_items[f"Event type: {event_type}"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return {
        "rows_written": written,
        "files_processed": files_processed,
        "parse_errors": parse_errors,
        "rows_skipped_by_time": skipped_by_time,
        "rows_by_event_type": event_type_counts,
    }
