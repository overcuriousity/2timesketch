#!/usr/bin/env python3
"""pfSense/OPNsense filterlog to Timesketch timeline converter.

Turns pfSense/OPNsense ``filterlog`` firewall log entries into Timesketch-
compatible CSV/JSONL timelines. Supports the de-facto standard FreeBSD ``pf``
filterlog format for IPv4/IPv6, TCP/UDP/ICMP, and the common syslog variants
produced by pfSense and OPNsense.
"""

from __future__ import annotations

import datetime
import gzip
import re
from pathlib import Path
from typing import Any

from .common import (
    AuditReport,
    ConverterError,
    OutputWriter,
    log,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)

# Regexes for the leading syslog/export timestamp.
_ISO_TIMESTAMP_RE = re.compile(
    r"^(?:<\d+>\s*)?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:[+-]\d{2}:?\d{2})?)"
)
_BSD_TIMESTAMP_RE = re.compile(
    r"^(?:<\d+>\s*)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)

# ICMP type -> ordered list of field names that follow the ICMP type field.
_ICMP_FIELD_MAP: dict[str, list[str]] = {
    "request": ["icmp_id", "icmp_sequence"],
    "reply": ["icmp_id", "icmp_sequence"],
    "unreachproto": ["icmp_destination_ip", "icmp_protocol_id"],
    "unreachport": ["icmp_destination_ip", "icmp_protocol_id", "icmp_port"],
    "needfrag": ["icmp_destination_ip", "icmp_mtu"],
    "tstamp": ["icmp_id", "icmp_sequence"],
    "tstampreply": [
        "icmp_id",
        "icmp_sequence",
        "icmp_otime",
        "icmp_rtime",
        "icmp_ttime",
    ],
}

# ICMP types that only carry a free-form description after the type field.
_ICMP_DESCRIPTION_TYPES = {
    "unreach",
    "timexceed",
    "paramprob",
    "redirect",
    "maskreply",
}


class FilterLogParseError(ConverterError):
    """Raised when a filterlog line cannot be parsed."""


def _safe_int(value: str) -> int | None:
    """Return ``value`` as int, or None if it is empty/non-numeric."""
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _add_field(row: dict[str, Any], key: str, value: Any) -> None:
    """Add a field to the row if it has a non-empty value."""
    if value is not None and value != "":
        row[key] = value


def _extract_payload(line: str) -> str:
    """Return the CSV payload of a filterlog line.

    Handles:
    - OPNsense export: ``<ts>\t<level>\tfilterlog\t <csv>``
    - BSD syslog:    ``<ts> <host> filterlog: <csv>``
    - Bare CSV:      ``<csv>``
    """
    marker = "filterlog"
    idx = line.find(marker)
    if idx == -1:
        return line.strip()

    payload = line[idx + len(marker) :]
    return payload.lstrip(" \t:").rstrip("\n\r")


def _parse_syslog_timestamp(prefix: str, year: int | None) -> datetime.datetime | None:
    """Parse a syslog/export timestamp prefix into a UTC-aware datetime.

    Returns None if no recognizable timestamp is found.
    """
    prefix = prefix.strip()

    iso_match = _ISO_TIMESTAMP_RE.match(prefix)
    if iso_match:
        ts = iso_match.group(1)
        if " " in ts:
            ts = ts.replace(" ", "T")
        ts = ts.replace("Z", "+00:00")
        try:
            dt = datetime.datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.astimezone(datetime.timezone.utc)
        except ValueError:
            return None

    bsd_match = _BSD_TIMESTAMP_RE.match(prefix)
    if bsd_match:
        ts = bsd_match.group(1)
        try:
            dt = datetime.datetime.strptime(ts, "%b %d %H:%M:%S")
        except ValueError:
            return None
        if year is None:
            year = datetime.datetime.now(datetime.timezone.utc).year
        try:
            dt = dt.replace(year=year, tzinfo=datetime.timezone.utc)
        except ValueError:
            return None
        return dt

    return None


def _timestamp_from_line(line: str, year: int | None) -> datetime.datetime | None:
    """Extract the event timestamp from the syslog/export prefix, if present."""
    marker = "filterlog"
    idx = line.find(marker)
    if idx == -1:
        return None
    prefix = line[:idx]
    return _parse_syslog_timestamp(prefix, year)


def _map_icmp_fields(
    fields: list[str], start: int
) -> dict[str, Any]:
    """Map ICMP-specific fields starting at ``start`` (the icmp_type position)."""
    result: dict[str, Any] = {}
    if start >= len(fields):
        return result

    icmp_type = fields[start]
    _add_field(result, "icmp_type", icmp_type)

    field_names = _ICMP_FIELD_MAP.get(icmp_type)
    if field_names is None and icmp_type in _ICMP_DESCRIPTION_TYPES:
        field_names = ["icmp_description"]

    if field_names is None:
        # Unknown ICMP type: keep the trailing raw fields.
        trailing = fields[start + 1 :]
        if trailing:
            result["icmp_raw_fields"] = ",".join(trailing)
        return result

    for offset, name in enumerate(field_names, start=1):
        idx = start + offset
        if idx < len(fields):
            value = fields[idx]
            if "_id" in name or "_sequence" in name or "_mtu" in name or "_port" in name or "_protocol_id" in name:
                int_value = _safe_int(value)
                if int_value is not None:
                    result[name] = int_value
                else:
                    _add_field(result, name, value)
            else:
                _add_field(result, name, value)

    return result


def _parse_filterlog_csv(
    csv_payload: str, source_file: str, event_dt: datetime.datetime | None
) -> dict[str, Any] | None:
    """Parse a single filterlog CSV payload into a Timesketch row."""
    fields = csv_payload.split(",")
    if len(fields) < 9:
        # Not enough fields for the common header.
        return None

    # Common fields (indices 0-8).
    (
        rule_number,
        sub_rule_number,
        anchor,
        rule_uuid,
        interface,
        reason,
        action,
        direction,
        ip_version,
    ) = fields[:9]

    if not action or not ip_version:
        return None

    row: dict[str, Any] = {
        "rule_number": rule_number,
        "sub_rule_number": sub_rule_number,
        "anchor": anchor,
        "rule_uuid": rule_uuid,
        "interface": interface,
        "reason": reason,
        "action": action,
        "direction": direction,
        "ip_version": ip_version,
    }

    protocol = ""
    source_ip = ""
    destination_ip = ""

    if ip_version == "4":
        # IPv4 fixed fields: indices 9-19.
        ipv4_fields = {
            "tos": 9,
            "ecn": 10,
            "ttl": 11,
            "ip_id": 12,
            "fragment_offset": 13,
            "ip_flags": 14,
            "protocol_id": 15,
            "protocol": 16,
            "packet_length": 17,
            "src_ip": 18,
            "dst_ip": 19,
        }
        for name, idx in ipv4_fields.items():
            if idx < len(fields):
                value = fields[idx]
                if name in {"ttl", "ip_id", "fragment_offset", "protocol_id", "packet_length"}:
                    int_value = _safe_int(value)
                    if int_value is not None:
                        row[name] = int_value
                    else:
                        _add_field(row, name, value)
                else:
                    _add_field(row, name, value)

        protocol = (row.get("protocol") or "").lower()
        source_ip = row.get("src_ip", "")
        destination_ip = row.get("dst_ip", "")

        if protocol in ("tcp", "udp"):
            if len(fields) > 20:
                _add_field(row, "source_port", _safe_int(fields[20]))
            if len(fields) > 21:
                _add_field(row, "destination_port", _safe_int(fields[21]))
            if len(fields) > 22:
                _add_field(row, "data_length", _safe_int(fields[22]))

            if protocol == "tcp" and len(fields) > 23:
                tcp_names = [
                    "tcp_flags",
                    "tcp_sequence",
                    "tcp_ack",
                    "tcp_window",
                    "tcp_urg",
                    "tcp_options",
                ]
                for offset, name in enumerate(tcp_names, start=23):
                    idx = offset
                    if idx >= len(fields):
                        break
                    value = fields[idx]
                    if name in {"tcp_sequence", "tcp_ack", "tcp_window"}:
                        _add_field(row, name, _safe_int(value))
                    else:
                        _add_field(row, name, value)

        elif protocol == "icmp":
            row.update(_map_icmp_fields(fields, 20))

        else:
            # Unknown protocol: preserve trailing raw fields.
            if len(fields) > 20:
                row["raw_fields"] = ",".join(fields[20:])

    elif ip_version == "6":
        # IPv6 fixed fields: indices 9-16.
        ipv6_fields = {
            "class": 9,
            "flow_label": 10,
            "hop_limit": 11,
            "protocol": 12,
            "protocol_id": 13,
            "packet_length": 14,
            "src_ip": 15,
            "dst_ip": 16,
        }
        for name, idx in ipv6_fields.items():
            if idx < len(fields):
                value = fields[idx]
                if name in {"flow_label", "hop_limit", "protocol_id", "packet_length"}:
                    int_value = _safe_int(value)
                    if int_value is not None:
                        row[name] = int_value
                    else:
                        _add_field(row, name, value)
                else:
                    _add_field(row, name, value)

        protocol = (row.get("protocol") or "").lower()
        source_ip = row.get("src_ip", "")
        destination_ip = row.get("dst_ip", "")

        if protocol in ("tcp", "udp"):
            if len(fields) > 17:
                _add_field(row, "source_port", _safe_int(fields[17]))
            if len(fields) > 18:
                _add_field(row, "destination_port", _safe_int(fields[18]))
            if len(fields) > 19:
                _add_field(row, "data_length", _safe_int(fields[19]))

            if protocol == "tcp" and len(fields) > 20:
                tcp_names = [
                    "tcp_flags",
                    "tcp_sequence",
                    "tcp_ack",
                    "tcp_window",
                    "tcp_urg",
                    "tcp_options",
                ]
                for offset, name in enumerate(tcp_names, start=20):
                    idx = offset
                    if idx >= len(fields):
                        break
                    value = fields[idx]
                    if name in {"tcp_sequence", "tcp_ack", "tcp_window"}:
                        _add_field(row, name, _safe_int(value))
                    else:
                        _add_field(row, name, value)

        elif protocol == "icmp":
            row.update(_map_icmp_fields(fields, 17))

        else:
            if len(fields) > 17:
                row["raw_fields"] = ",".join(fields[17:])

    else:
        # Unknown IP version: keep common fields and raw payload.
        row["raw_fields"] = ",".join(fields[9:])

    # Timestamp handling.
    timestamp_us = 0
    datetime_str = ""
    if event_dt is not None:
        timestamp_us = to_unix_microseconds(event_dt)
        datetime_str = to_iso8601(timestamp_us, unit="us")

    # Build a human-readable message.
    message = _build_message(row)

    # src_ip/dst_ip: validate and canonicalize the addresses parsed above.
    # icmp_destination_ip (the original packet's destination carried inside
    # an ICMP error payload) is a distinct field and is not folded in here.
    row["src_ip"] = normalize_ip(source_ip)
    row["dst_ip"] = normalize_ip(destination_ip)

    data_type = f"firewall:filterlog:{action.lower()}"

    timesketch_row: dict[str, Any] = {
        "datetime": datetime_str,
        "timestamp_desc": "Firewall Log Event Time",
        "message": message,
        "data_type": data_type,
        "timestamp": timestamp_us,
        "source": source_file,
        "src_ip": row["src_ip"],
        "dst_ip": row["dst_ip"],
    }
    timesketch_row.update(row)
    return timesketch_row


def _build_message(row: dict[str, Any]) -> str:
    """Build a concise human-readable summary of a filterlog row."""
    action = row.get("action", "unknown")
    interface = row.get("interface", "")
    protocol = row.get("protocol", "")
    protocol_id = row.get("protocol_id")
    source_ip = row.get("src_ip", "")
    destination_ip = row.get("dst_ip", "")
    source_port = row.get("source_port")
    destination_port = row.get("destination_port")
    rule_number = row.get("rule_number", "")
    rule_uuid = row.get("rule_uuid", "")
    icmp_type = row.get("icmp_type", "")

    proto = protocol or (str(protocol_id) if protocol_id is not None else "unknown")

    src = source_ip
    if source_port is not None:
        src = f"{src}:{source_port}"

    dst = destination_ip
    if destination_port is not None:
        dst = f"{dst}:{destination_port}"

    parts = [f"firewall {action} {proto}"]
    if src and dst:
        parts.append(f"{src} -> {dst}")
    elif src or dst:
        parts.append(f"{src}{dst}")

    if interface:
        parts.append(f"on {interface}")

    if icmp_type:
        parts.append(f"icmp_type={icmp_type}")

    rule_parts = []
    if rule_number:
        rule_parts.append(str(rule_number))
    if rule_uuid:
        rule_parts.append(str(rule_uuid))
    if rule_parts:
        parts.append(f"(rule {' / '.join(rule_parts)})")

    return " ".join(parts)


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _find_log_files(input_path: str) -> list[Path]:
    """Resolve the input path into a list of filterlog files."""
    path = Path(input_path)

    if path.is_file():
        return [path]

    if path.is_dir():
        files: set[Path] = set()
        for ext in ("*.log", "*.log.gz"):
            files.update(path.rglob(ext))
        # Also include any file whose name contains filterlog.
        for candidate in path.rglob("*"):
            if candidate.is_file() and "filterlog" in candidate.name.lower():
                files.add(candidate)
        return sorted(files)

    raise ConverterError(f"Input path not found: {input_path}")


def _parse_since_until(value: str | None) -> datetime.datetime | None:
    """Parse an ISO 8601 ``--since``/``--until`` value to a UTC datetime."""
    if not value:
        return None
    dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def convert_filterlog(
    input_path: str,
    output: str,
    output_format: str,
    since: str | None = None,
    until: str | None = None,
    year: int | None = None,
    verbose: bool = True,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, Any]:
    """Convert pfSense/OPNsense filterlog entries to a Timesketch timeline.

    Returns:
        Statistics dict with ``rows_written``, ``files_processed``,
        ``rows_skipped_by_time``, ``rows_unparseable``, and ``actions``.
    """
    files = _find_log_files(input_path)
    if not files:
        raise ConverterError(f"No filterlog files found in: {input_path}")

    log(f"Found {len(files)} filterlog file(s)", verbose)

    since_dt = _parse_since_until(since)
    until_dt = _parse_since_until(until)

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("filterlog2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)

    writer = OutputWriter(output, output_format, compute_hash=report_path is not None)
    rows_written = 0
    rows_skipped_by_time = 0
    rows_unparseable = 0
    action_counts: dict[str, int] = {}

    for log_file in files:
        log(f"  Processing {log_file}", verbose)
        source_str = str(log_file.resolve())

        try:
            with _open_log(log_file) as fh:
                for line in fh:
                    line = line.rstrip("\n\r")
                    if not line:
                        continue

                    payload = _extract_payload(line)
                    if not payload:
                        continue

                    event_dt = _timestamp_from_line(line, year)
                    row = _parse_filterlog_csv(payload, source_str, event_dt)
                    if row is None:
                        rows_unparseable += 1
                        continue

                    ts = row.get("timestamp", 0)
                    if since_dt and ts and ts < to_unix_microseconds(since_dt):
                        rows_skipped_by_time += 1
                        continue
                    if until_dt and ts and ts > to_unix_microseconds(until_dt):
                        rows_skipped_by_time += 1
                        continue

                    action = row.get("action", "unknown")
                    action_counts[action] = action_counts.get(action, 0) + 1

                    writer.add(row)
                    rows_written += 1
        except OSError as exc:
            raise ConverterError(f"Failed to read {log_file}: {exc}") from exc

    written = writer.write()

    if report:
        if output == "-":
            report.add_stdout_output(writer.content_hash)
        else:
            report.add_output_file(output, writer.content_hash)
        report.set_statistics({
            "rows_written": written,
            "files_processed": len(files),
            "rows_skipped_by_time": rows_skipped_by_time,
            "rows_unparseable": rows_unparseable,
            "actions": action_counts,
            "since": since,
            "until": until,
            "year": year,
        })
        report.write(report_path)
        log(f"Audit report written to {report_path}", verbose)

    log(
        f"Exported {written} rows from {len(files)} files "
        f"({rows_skipped_by_time} skipped by time, {rows_unparseable} unparseable).",
        verbose,
    )

    return {
        "rows_written": written,
        "files_processed": len(files),
        "rows_skipped_by_time": rows_skipped_by_time,
        "rows_unparseable": rows_unparseable,
        "actions": action_counts,
    }
