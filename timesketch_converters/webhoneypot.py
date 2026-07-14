#!/usr/bin/env python3
"""DShield webhoneypot log to Timesketch timeline converter.

The DShield web honeypot (isc-agent) writes one JSON object per line into
daily files named ``webhoneypot_YYYY-MM-DD.json``. Each record describes a
single HTTP request: ``time``, the raw request ``headers`` dict, the socket
peer (``sip``) and honeypot (``dip``) addresses, ``method``, ``url``,
``version``, ``useragent``, the request body (``data``) and the matched
signature (``signature_id``).

Deployments behind a reverse proxy report the proxy's address in ``sip``
while the real client arrives in ``X-Real-Ip`` / ``X-Forwarded-For``. The
converter therefore prefers a valid forwarded-header address for the shared
``src_ip`` column and keeps the raw socket peer in ``socket_src_ip``. The
full header dict is preserved as a compact JSON string (``http_headers``)
so the CSV schema stays fixed regardless of which headers a client sends.
"""

from __future__ import annotations

import datetime
import gzip
import json
from pathlib import Path
from typing import Any

from .common import (
    COMMON_FIELDS,
    AuditReport,
    ConverterError,
    OutputWriter,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal

# Fixed non-common columns, kept sorted for a stable CSV header.
_EXTRA_FIELDS = sorted([
    "host",
    "http_data",
    "http_headers",
    "http_method",
    "http_protocol",
    "http_uri",
    "referer",
    "response_id",
    "signature_comment",
    "signature_id",
    "signature_min_score",
    "socket_src_ip",
    "user_agent",
])

_FIELDNAMES = COMMON_FIELDS + _EXTRA_FIELDS


class WebhoneypotParseError(ConverterError):
    """Raised when a webhoneypot JSON line cannot be parsed."""


def _safe_int(value: Any) -> int | None:
    """Return ``value`` as int, or None if it is empty/non-numeric."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _header_lookup(headers: dict[str, Any], name: str) -> str:
    """Case-insensitive lookup of a header value."""
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return str(value)
    return ""


def _effective_src_ip(headers: dict[str, Any], sip: str) -> str:
    """Pick the client address: forwarded header first, socket peer last.

    ``X-Forwarded-For`` may carry a comma-separated chain; the first entry
    is the original client.
    """
    candidate = normalize_ip(_header_lookup(headers, "X-Real-Ip"))
    if candidate:
        return candidate
    forwarded = _header_lookup(headers, "X-Forwarded-For")
    if forwarded:
        candidate = normalize_ip(forwarded.split(",")[0].strip())
        if candidate:
            return candidate
    return normalize_ip(sip)


def _build_message(record: dict[str, Any], src_ip: str, comment: str) -> str:
    """Build a human-readable request summary."""
    parts = [
        str(record.get("method", "")),
        str(record.get("url", "")),
        str(record.get("version", "")),
    ]
    message = " ".join(p for p in parts if p)
    if src_ip:
        message += f" from {src_ip}"
    if comment:
        message += f" [{comment}]"
    return message or "Webhoneypot HTTP request"


def _parse_line(line: str, source_file: str) -> dict[str, Any] | None:
    """Parse a single webhoneypot JSON line into a Timesketch row."""
    line = line.strip()
    if not line:
        return None

    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise WebhoneypotParseError(f"Invalid JSON: {exc}") from exc

    if not isinstance(record, dict):
        raise WebhoneypotParseError("JSON line is not an object")

    ts_value = record.get("time")
    if not ts_value:
        raise WebhoneypotParseError("record missing time")

    try:
        dt = datetime.datetime.fromisoformat(str(ts_value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise WebhoneypotParseError(f"Unrecognised timestamp format: {ts_value}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    ts_us = to_unix_microseconds(dt.astimezone(datetime.timezone.utc))

    headers = record.get("headers")
    if not isinstance(headers, dict):
        headers = {}

    sip = str(record.get("sip", ""))
    src_ip = _effective_src_ip(headers, sip)

    signature = record.get("signature_id")
    if not isinstance(signature, dict):
        signature = {}
    comment = str(signature.get("comment", "") or "")

    return {
        "datetime": to_iso8601(ts_us, unit="us"),
        "timestamp": ts_us,
        "timestamp_desc": "HTTP Request Time",
        "message": _build_message(record, src_ip, comment),
        "data_type": "webhoneypot:http:request",
        "source": source_file,
        "src_ip": src_ip,
        "dst_ip": normalize_ip(record.get("dip", "")),
        "socket_src_ip": normalize_ip(sip),
        "http_method": record.get("method", ""),
        "http_uri": record.get("url", ""),
        "http_protocol": record.get("version", ""),
        "user_agent": record.get("useragent", ""),
        "host": _header_lookup(headers, "Host"),
        "referer": _header_lookup(headers, "Referer"),
        "http_data": record.get("data", ""),
        "http_headers": json.dumps(headers, separators=(",", ":"), ensure_ascii=False),
        "response_id": _safe_int(record.get("response_id")),
        "signature_id": _safe_int(signature.get("id")),
        "signature_comment": comment,
        "signature_min_score": _safe_int(signature.get("min_score")),
    }


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _find_log_files(input_path: str) -> list[Path]:
    """Resolve the input path into a list of webhoneypot log files."""
    path = Path(input_path)

    if path.is_file():
        return [path]

    if path.is_dir():
        files: set[Path] = set()
        for pattern in ("webhoneypot_*.json", "webhoneypot_*.json.gz"):
            files.update(path.rglob(pattern))
        return sorted(files)

    raise ConverterError(f"Input path not found: {input_path}")


def convert_webhoneypot(
    input_path: str,
    output: str,
    output_format: str,
    since: str | None = None,
    until: str | None = None,
    verbose: bool = True,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, Any]:
    """Convert DShield webhoneypot logs to a Timesketch timeline.

    Returns:
        Statistics dict with ``rows_written``, ``files_processed``,
        ``parse_errors``, and ``rows_skipped_by_time``.
    """
    files = _find_log_files(input_path)
    if not files:
        raise ConverterError(f"No webhoneypot log files found in: {input_path}")

    ui = get_terminal()
    ui.header(
        "webhoneypot2timesketch",
        subtitle="Convert DShield webhoneypot logs → Timesketch timeline",
        badges=[("honeypot", "danger"), (output_format, "muted")],
    )
    ui.step("Files found", f"{len(files)} webhoneypot log file(s)")

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
        report = AuditReport("webhoneypot2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)

    writer = OutputWriter(
        output,
        output_format,
        fieldnames=_FIELDNAMES,
        compute_hash=report_path is not None,
    )
    rows_written = 0
    files_processed = 0
    parse_errors = 0
    skipped_by_time = 0
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
                    except WebhoneypotParseError as exc:
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
    ui.summary("Result", summary_items)

    return {
        "rows_written": written,
        "files_processed": files_processed,
        "parse_errors": parse_errors,
        "rows_skipped_by_time": skipped_by_time,
    }
