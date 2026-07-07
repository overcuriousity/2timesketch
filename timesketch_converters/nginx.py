#!/usr/bin/env python3
"""nginx log to Timesketch timeline converter."""

from __future__ import annotations

import datetime
import gzip
import re
from pathlib import Path
from typing import Any

from .common import (
    COMMON_FIELDS,
    AuditReport,
    ConverterError,
    OutputWriter,
    log,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal

# Combined log format used for access and redirect logs.
_ACCESS_LOG_RE = re.compile(
    r'(\S+) (\S*) (\S*) \[([^\]]+)\] "([^"]*)" (\d+) (\S+) "([^"]*)" "([^"]*)"'
    r'(?:\s+"([^"]*)")?'
)

# Error log format: "2026/06/25 09:46:41 [error] 1234#1234: *1 message..."
_ERROR_LOG_RE = re.compile(
    r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#(\d+): \*(\d+) (.*)$'
)

# Order matters for name-based detection: "redirect" must be checked before
# "access", because "access.log" is a substring of "redirect-access.log".
_LOG_TYPES = {
    "redirect": {
        "patterns": ["redirect-access.log*"],
        "timestamp_desc": "Redirect Request Time",
        "data_type": "web:redirect:request",
    },
    "access": {
        "patterns": ["access.log*"],
        "timestamp_desc": "HTTP Request Time",
        "data_type": "web:access:request",
    },
    "error": {
        "patterns": ["error.log*"],
        "timestamp_desc": "Error Event Time",
        "data_type": "web:error:log",
    },
}

# Fields beyond the shared timeline columns, per log type. Used to build the
# fixed CSV header so output can be streamed without buffering rows.
_EXTRA_FIELDS_BY_TYPE = {
    "access": sorted([
        "additional_field",
        "http_method",
        "http_protocol",
        "http_request_full",
        "http_uri",
        "log_type",
        "referer",
        "remote_ident",
        "remote_user",
        "response_size",
        "status_code",
        "user_agent",
    ]),
    "error": sorted([
        "connection_id",
        "error_level",
        "log_type",
        "worker_pid",
        "worker_tid",
    ]),
}
_EXTRA_FIELDS_BY_TYPE["redirect"] = _EXTRA_FIELDS_BY_TYPE["access"]


def _fieldnames_for(log_types: list[str]) -> list[str]:
    """Build the fixed CSV column order for the given log types."""
    extras: set[str] = set()
    for log_type in log_types:
        extras.update(_EXTRA_FIELDS_BY_TYPE[log_type])
    # nginx logs never yield a distinct destination address, so dst_ip is
    # omitted from the header.
    base = [f for f in COMMON_FIELDS if f != "dst_ip"]
    return base + sorted(extras)


def _detect_log_type(filename: str) -> str | None:
    """Determine log type from a filename."""
    name_lower = Path(filename).name.lower()
    for log_type, config in _LOG_TYPES.items():
        for pattern in config["patterns"]:
            # Convert glob to a simple substring check.
            bare = pattern.rstrip("*")
            if bare in name_lower:
                return log_type
    return None


def _parse_access_line(line: str, log_type: str, source_file: str) -> dict[str, Any] | None:
    """Parse an access/redirect log line."""
    match = _ACCESS_LOG_RE.match(line)
    if not match:
        return None

    groups = match.groups()
    ip = groups[0]
    remote_ident = groups[1] if groups[1] != "-" else None
    remote_user = groups[2] if groups[2] != "-" else None
    timestamp_str = groups[3]
    request = groups[4]
    status = groups[5]
    size = groups[6]
    referer = groups[7] if groups[7] != "-" else None
    user_agent = groups[8]
    additional = groups[9] if len(groups) > 9 and groups[9] else None

    request_parts = request.split(" ")
    method = request_parts[0] if len(request_parts) > 0 else None
    uri = request_parts[1] if len(request_parts) > 1 else None
    protocol = request_parts[2] if len(request_parts) > 2 else None

    try:
        dt = datetime.datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

    config = _LOG_TYPES[log_type]
    return {
        "message": line.strip(),
        "datetime": to_iso8601(to_unix_microseconds(dt), unit="us"),
        "timestamp": to_unix_microseconds(dt),
        "timestamp_desc": config["timestamp_desc"],
        "data_type": config["data_type"],
        "source": source_file,
        "log_type": log_type,
        "src_ip": normalize_ip(ip),
        "remote_ident": remote_ident,
        "remote_user": remote_user,
        "http_method": method,
        "http_uri": uri,
        "http_protocol": protocol,
        "http_request_full": request,
        "status_code": int(status),
        "response_size": int(size) if size.isdigit() else 0,
        "referer": referer,
        "user_agent": user_agent,
        "additional_field": additional,
    }


def _parse_error_line(line: str, source_file: str) -> dict[str, Any] | None:
    """Parse an nginx error log line."""
    match = _ERROR_LOG_RE.match(line)
    if not match:
        return None

    timestamp_str, level, pid, tid, conn_id, message = match.groups()
    try:
        dt = datetime.datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
        # nginx error logs have no timezone; treat as UTC.
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None

    config = _LOG_TYPES["error"]
    row: dict[str, Any] = {
        "message": line.strip(),
        "datetime": to_iso8601(to_unix_microseconds(dt), unit="us"),
        "timestamp": to_unix_microseconds(dt),
        "timestamp_desc": config["timestamp_desc"],
        "data_type": config["data_type"],
        "source": source_file,
        "log_type": "error",
        "src_ip": "",
        "error_level": level,
        "worker_pid": int(pid),
        "worker_tid": int(tid),
        "connection_id": int(conn_id),
    }

    # Try to extract the client IP from the raw message tail.
    client_match = re.search(r"client:\s+(\S+)", message)
    if client_match:
        row["src_ip"] = normalize_ip(client_match.group(1).rstrip(",;."))

    return row


def _parse_line(line: str, log_type: str, source_file: str) -> dict[str, Any] | None:
    """Parse a single log line according to its detected log type."""
    if log_type in ("access", "redirect"):
        return _parse_access_line(line, log_type, source_file)
    if log_type == "error":
        return _parse_error_line(line, source_file)
    return None


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _sniff_log_type(path: Path) -> str | None:
    """Detect the log type from file content by sampling the first lines.

    Returns "access" or "error", or None when no sampled line matches either
    format. A redirect log is indistinguishable from an access log by content,
    so it is classified as "access" unless the filename says otherwise.
    """
    access_hits = 0
    error_hits = 0
    sampled = 0
    try:
        with _open_log(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if _ACCESS_LOG_RE.match(line):
                    access_hits += 1
                elif _ERROR_LOG_RE.match(line):
                    error_hits += 1
                sampled += 1
                if sampled >= 50:
                    break
    except OSError:
        return None

    if access_hits == 0 and error_hits == 0:
        return None
    return "access" if access_hits >= error_hits else "error"


def _find_log_files(input_path: str) -> dict[str, list[Path]]:
    """Resolve the input path into log files grouped by log type."""
    path = Path(input_path)

    if path.is_file():
        # A directly passed file does not need to follow the nginx naming
        # convention; fall back to content sniffing when the name is opaque.
        log_type = _detect_log_type(path.name) or _sniff_log_type(path)
        if log_type is None:
            raise ConverterError(
                f"Could not determine log type for: {input_path} "
                "(filename not recognized and content matches neither the "
                "combined access log format nor the error log format)"
            )
        return {log_type: [path]}

    if path.is_dir():
        files_by_type: dict[str, list[Path]] = {}
        for log_type, config in _LOG_TYPES.items():
            found: list[Path] = []
            for pattern in config["patterns"]:
                found.extend(sorted(path.glob(pattern)))
            if found:
                files_by_type[log_type] = found
        if not files_by_type:
            raise ConverterError(f"No supported nginx log files found in: {input_path}")
        return files_by_type

    # Treat as a glob pattern.
    matches = sorted(Path(".").glob(input_path))
    if not matches:
        raise ConverterError(f"No files matched pattern: {input_path}")
    files_by_type = {}
    for match in matches:
        if not match.is_file():
            continue
        log_type = _detect_log_type(match.name)
        if log_type is None:
            continue
        files_by_type.setdefault(log_type, []).append(match)
    if not files_by_type:
        raise ConverterError(f"No supported nginx log files matched: {input_path}")
    return files_by_type


def _filter_by_time(
    row: dict[str, Any],
    since_dt: datetime.datetime | None,
    until_dt: datetime.datetime | None,
) -> bool:
    """Return True if the row timestamp is within the requested range."""
    ts = row.get("timestamp")
    if not ts:
        return True
    dt = datetime.datetime.fromtimestamp(int(ts) / 1_000_000, tz=datetime.timezone.utc)
    if since_dt is not None and dt < since_dt:
        return False
    if until_dt is not None and dt > until_dt:
        return False
    return True


def convert_nginx(
    input_path: str,
    output: str,
    output_format: str,
    output_dir: str | None = None,
    since: str | None = None,
    until: str | None = None,
    verbose: bool = True,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, int]:
    """Convert nginx log files to a Timesketch timeline.

    Returns:
        Mapping of log_type -> number of rows written.
    """
    files_by_type = _find_log_files(input_path)

    ui = get_terminal()
    ui.header(
        "nginx2timesketch",
        subtitle="Convert nginx access/error/redirect logs → Timesketch timeline",
        badges=[("nginx", "accent"), (output_format, "muted")],
    )
    ui.step("Log types found", ", ".join(files_by_type.keys()))

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("nginx2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)
        else:
            # Glob pattern: record only the files that were actually processed.
            for files in files_by_type.values():
                for log_file in files:
                    report.add_input_path(log_file)

    since_dt: datetime.datetime | None = None
    until_dt: datetime.datetime | None = None
    if since:
        since_dt = datetime.datetime.fromisoformat(since)
        if since_dt.tzinfo is None:
            since_dt = since_dt.replace(tzinfo=datetime.timezone.utc)
    if until:
        until_dt = datetime.datetime.fromisoformat(until)
        if until_dt.tzinfo is None:
            until_dt = until_dt.replace(tzinfo=datetime.timezone.utc)

    total_files = sum(len(files) for files in files_by_type.values())
    processed_files = 0
    compute_hash = report_path is not None
    counts: dict[str, int] = {}

    def _stream_files(log_type: str, files: list[Path], writer: OutputWriter) -> int:
        """Parse the given files and write rows straight to the writer."""
        nonlocal processed_files
        written = 0
        for log_file in files:
            processed_files += 1
            ui.step(
                f"[{processed_files}/{total_files}] {log_type}",
                str(log_file),
            )
            try:
                with _open_log(log_file) as fh:
                    for line in fh:
                        row = _parse_line(line.strip(), log_type, str(log_file.resolve()))
                        if row is None:
                            continue
                        if not _filter_by_time(row, since_dt, until_dt):
                            continue
                        # Remove None values to keep output tidy.
                        writer.add({k: v for k, v in row.items() if v is not None})
                        written += 1
            except OSError as exc:
                raise ConverterError(f"Failed to read {log_file}: {exc}") from exc
        return written

    if output_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for log_type, files in files_by_type.items():
            dest = out_dir / f"timesketch_{log_type}.{output_format}"
            writer = OutputWriter(
                str(dest),
                output_format,
                fieldnames=_fieldnames_for([log_type]),
                compute_hash=compute_hash,
            )
            _stream_files(log_type, files, writer)
            counts[log_type] = writer.write()
            if report:
                report.add_output_file(str(dest), writer.content_hash)
            ui.success(f"Wrote {counts[log_type]:,} rows to {dest}")
    else:
        # Combined output.
        writer = OutputWriter(
            output,
            output_format,
            fieldnames=_fieldnames_for(list(files_by_type.keys())),
            compute_hash=compute_hash,
        )
        for log_type, files in files_by_type.items():
            _stream_files(log_type, files, writer)
        total = writer.write()
        counts = {"combined": total}
        if report:
            if output == "-":
                report.add_stdout_output(writer.content_hash)
            else:
                report.add_output_file(output, writer.content_hash)

    if report:
        report.set_statistics({
            "rows_by_type": counts,
            "since": since,
            "until": until,
            "output_dir": output_dir,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    summary_items: dict[str, Any] = {
        "Files processed": str(total_files),
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
    }
    if output_dir:
        summary_items["Output directory"] = output_dir
    for log_type, count in counts.items():
        summary_items[f"Rows ({log_type})"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return counts
