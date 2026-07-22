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

For easier hunting the converter additionally promotes a curated set of
well-known headers into fixed ``http_*`` columns (Content-Type, Cookie,
Authorization, ...), splits the URL into ``url_path`` / ``url_query`` /
``url_query_params`` plus a percent-decoded ``url_fetch_target`` for
SSRF-style ``?url=``/``?uri=``/``?dest=`` probes, and — when the request
body parses as a JSON object — extracts JSON-RPC / Model Context Protocol
fields (``jsonrpc_method``, ``jsonrpc_version``, ``mcp_protocol_version``,
``mcp_client_name``, ``mcp_client_version``). The raw ``http_uri``,
``http_data`` and ``http_headers`` values are always preserved unchanged.
"""

from __future__ import annotations

import datetime
import gzip
import json
from pathlib import Path
from typing import Any
from urllib import parse as urlparse

from .common import (
    COMMON_FIELDS,
    AuditReport,
    ConverterError,
    OutputWriter,
    add_writer_output,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal

# Fixed non-common columns, kept sorted for a stable CSV header.
_EXTRA_FIELDS = sorted([
    "host",
    "http_accept",
    "http_accept_encoding",
    "http_accept_language",
    "http_authorization",
    "http_connection",
    "http_content_length",
    "http_content_type",
    "http_cookie",
    "http_data",
    "http_headers",
    "http_method",
    "http_origin",
    "http_protocol",
    "http_uri",
    "http_x_forwarded_for",
    "jsonrpc_method",
    "jsonrpc_version",
    "mcp_client_name",
    "mcp_client_version",
    "mcp_protocol_version",
    "referer",
    "response_id",
    "signature_comment",
    "signature_id",
    "signature_min_score",
    "socket_src_ip",
    "url_fetch_target",
    "url_path",
    "url_query",
    "url_query_params",
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


# Well-known headers promoted to fixed columns. X-Forwarded-For is promoted
# verbatim here; _effective_src_ip independently consumes it for src_ip.
_PROMOTED_HEADERS = {
    "Accept": "http_accept",
    "Accept-Encoding": "http_accept_encoding",
    "Accept-Language": "http_accept_language",
    "Authorization": "http_authorization",
    "Connection": "http_connection",
    "Content-Length": "http_content_length",
    "Content-Type": "http_content_type",
    "Cookie": "http_cookie",
    "Origin": "http_origin",
    "X-Forwarded-For": "http_x_forwarded_for",
}

# Query parameter names commonly abused for SSRF / open-redirect probes.
_SSRF_PARAM_NAMES = (
    "url",
    "uri",
    "path",
    "dest",
    "destination",
    "redirect",
    "target",
    "next",
    "fetch",
)

# Bodies larger than this are never JSON-parsed; scanners send small probes.
_MAX_JSON_BODY = 1_000_000


def _promote_headers(headers: dict[str, Any]) -> dict[str, str]:
    """Extract the curated well-known headers into their fixed columns."""
    return {
        column: _header_lookup(headers, name)
        for name, column in _PROMOTED_HEADERS.items()
    }


def _split_url(url: str) -> dict[str, str]:
    """Split a request URL into path, raw query and derived hunt columns.

    ``url_query`` stays percent-encoded so analysts see the original bytes;
    ``url_fetch_target`` is decoded so encoded SSRF targets are huntable.
    """
    fields = {
        "url_path": url,
        "url_query": "",
        "url_query_params": "",
        "url_fetch_target": "",
    }
    try:
        split = urlparse.urlsplit(url)
    except ValueError:
        return fields

    fields["url_path"] = split.path
    fields["url_query"] = split.query
    if not split.query:
        return fields

    pairs = urlparse.parse_qsl(split.query, keep_blank_values=True)
    names = sorted({name.lower() for name, _ in pairs})
    fields["url_query_params"] = " ".join(names)
    for name, value in pairs:
        if name.lower() in _SSRF_PARAM_NAMES:
            fields["url_fetch_target"] = urlparse.unquote(value)
            break
    return fields


def _parse_body_json(data: Any) -> tuple[dict[str, str], str]:
    """Extract JSON-RPC / MCP fields from a JSON object request body.

    Returns ``(fields, status)`` with status one of ``empty``, ``json`` or
    ``non_json``. Never raises; unparsable bodies stay raw in ``http_data``.
    """
    body = str(data or "").strip()
    if not body:
        return {}, "empty"
    if not body.startswith("{") or len(body) > _MAX_JSON_BODY:
        return {}, "non_json"

    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        return {}, "non_json"
    if not isinstance(obj, dict):
        return {}, "non_json"

    fields = {
        "jsonrpc_version": str(obj.get("jsonrpc", "") or ""),
        "jsonrpc_method": str(obj.get("method", "") or ""),
        "mcp_protocol_version": "",
        "mcp_client_name": "",
        "mcp_client_version": "",
    }
    params = obj.get("params")
    if isinstance(params, dict):
        fields["mcp_protocol_version"] = str(params.get("protocolVersion", "") or "")
        client_info = params.get("clientInfo")
        if isinstance(client_info, dict):
            fields["mcp_client_name"] = str(client_info.get("name", "") or "")
            fields["mcp_client_version"] = str(client_info.get("version", "") or "")
    return fields, "json"


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

    url_fields = _split_url(str(record.get("url", "")))
    body_fields, body_status = _parse_body_json(record.get("data", ""))

    row = {
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
        # Popped by the caller before writing; only used for statistics.
        "_body_status": body_status,
    }
    row.update(_promote_headers(headers))
    row.update(url_fields)
    row.update(body_fields)
    return row


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
    split: str | None = None,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, Any]:
    """Convert DShield webhoneypot logs to a Timesketch timeline.

    Returns:
        Statistics dict with ``rows_written``, ``files_processed``,
        ``parse_errors``, ``rows_skipped_by_time``, ``json_bodies_parsed``,
        and ``non_json_bodies``.
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
        split=split,
    )
    rows_written = 0
    files_processed = 0
    parse_errors = 0
    skipped_by_time = 0
    json_bodies = 0
    non_json_bodies = 0
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

                    body_status = row.pop("_body_status", "empty")

                    ts = row.get("timestamp", 0)
                    if since_dt and ts and ts < to_unix_microseconds(since_dt):
                        skipped_by_time += 1
                        continue
                    if until_dt and ts and ts > to_unix_microseconds(until_dt):
                        skipped_by_time += 1
                        continue

                    if body_status == "json":
                        json_bodies += 1
                    elif body_status == "non_json":
                        non_json_bodies += 1

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
            "json_bodies_parsed": json_bodies,
            "non_json_bodies": non_json_bodies,
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
        "JSON bodies parsed": f"{json_bodies:,}",
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
    }
    ui.summary("Result", summary_items)

    return {
        "rows_written": written,
        "files_processed": files_processed,
        "parse_errors": parse_errors,
        "rows_skipped_by_time": skipped_by_time,
        "json_bodies_parsed": json_bodies,
        "non_json_bodies": non_json_bodies,
    }
