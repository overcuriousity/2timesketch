#!/usr/bin/env python3
"""Apache HTTP Server log to Timesketch timeline converter.

Handles Apache access logs (combined and common/CLF LogFormat, including
``other_vhosts_access.log`` with its leading ``vhost:port`` token) and error
logs (Apache 2.4 ``[Day Mon DD HH:MM:SS.us YYYY] [module:level] [pid N:tid N]
[client ip:port]`` format plus the 2.2 legacy variant).

Access rows reuse the suite-wide ``web:*`` data_type taxonomy shared with the
nginx converter, so saved Timesketch queries work across both servers; the
originating web server is distinguished by the ``source`` column and the
Apache-specific extra columns.
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Any

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
from .nginx import (
    _EXTRA_FIELDS_BY_TYPE as _NGINX_EXTRA_FIELDS_BY_TYPE,
    _filter_by_time,
    _open_log,
    _parse_access_line,
)
from .terminal import get_terminal

# Common Log Format (Apache's default "common" LogFormat): no quoted
# referer/user-agent tail. Tried when the combined-format regex fails.
_CLF_RE = re.compile(
    r'(\S+) (\S*) (\S*) \[([^\]]+)\] "([^"]*)" (\d+) (\S+)\s*$'
)

# other_vhosts_access.log prepends "vhost:port " before the client address.
_VHOST_PREFIX_RE = re.compile(r"^(\S+:\d+)\s+")

# [client ip:port] value; IPv6 addresses are themselves bracketed
# (e.g. "[client [2001:db8::1]:5678]"), so the client token is either a
# bracketed IPv6 host:port or a plain IPv4/hostname:port.
_CLIENT_RE = r"\[client (\[[^\]]+\]:\d+|[^\]]+)\]"

# Apache 2.4 error log:
# [Fri Jul 11 12:34:56.789012 2026] [core:error] [pid 123:tid 456] [client 1.2.3.4:5678] AH00126: ...
_ERROR_24_RE = re.compile(
    r"^\[(\w{3} \w{3} [\d ]\d \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] "
    r"\[(?:([\w-]+):)?(\w+)\] "
    r"\[pid (\d+)(?::tid (\d+))?\]"
    rf"(?: {_CLIENT_RE})? "
    r"(.*)$"
)

# Apache 2.2 legacy error log:
# [Fri Jul 11 12:34:56 2026] [error] [client 1.2.3.4] message
_ERROR_22_RE = re.compile(
    r"^\[(\w{3} \w{3} [\d ]\d \d{2}:\d{2}:\d{2} \d{4})\] "
    r"\[(\w+)\]"
    rf"(?: {_CLIENT_RE})? "
    r"(.*)$"
)

_AH_CODE_RE = re.compile(r"\b(AH\d{5})\b")

_LOG_TYPES = {
    "access": {
        "patterns": [
            "access.log*",
            "access_log*",
            "ssl_access*",
            "other_vhosts_access.log*",
        ],
        "timestamp_desc": "HTTP Request Time",
        "data_type": "web:access:request",
    },
    "error": {
        "patterns": ["error.log*", "error_log*", "ssl_error*"],
        "timestamp_desc": "Error Event Time",
        "data_type": "web:error:log",
    },
}

_EXTRA_FIELDS_BY_TYPE = {
    "access": sorted(set(_NGINX_EXTRA_FIELDS_BY_TYPE["access"]) | {"vhost"}),
    "error": sorted([
        "error_code",
        "error_level",
        "log_type",
        "module",
        "src_port",
        "worker_pid",
        "worker_tid",
    ]),
}


def _fieldnames_for(log_types: list[str]) -> list[str]:
    """Build the fixed CSV column order for the given log types."""
    extras: set[str] = set()
    for log_type in log_types:
        extras.update(_EXTRA_FIELDS_BY_TYPE[log_type])
    # Apache logs never yield a distinct destination address, so dst_ip is
    # omitted from the header.
    base = [f for f in COMMON_FIELDS if f != "dst_ip"]
    return base + sorted(extras)


def _detect_log_type(filename: str) -> str | None:
    """Determine log type from a filename."""
    name_lower = Path(filename).name.lower()
    for log_type, config in _LOG_TYPES.items():
        for pattern in config["patterns"]:
            bare = pattern.rstrip("*")
            if bare in name_lower:
                return log_type
    return None


def _parse_apache_access_line(
    line: str, source_file: str
) -> dict[str, Any] | None:
    """Parse an Apache access log line (combined, CLF, or vhost-prefixed)."""
    row = _parse_apache_access_line_no_vhost(line, source_file)
    if row is not None:
        return row

    vhost_match = _VHOST_PREFIX_RE.match(line)
    if vhost_match:
        stripped = line[vhost_match.end():]
        row = _parse_apache_access_line_no_vhost(stripped, source_file)
        if row is not None:
            row["vhost"] = vhost_match.group(1)
            return row

    return None


def _parse_apache_access_line_no_vhost(
    line: str, source_file: str
) -> dict[str, Any] | None:
    """Parse a combined or plain-CLF access line without a vhost prefix."""
    row = _parse_access_line(line, "access", source_file)
    if row is not None:
        # _parse_access_line stamps timestamp_desc/data_type from nginx's own
        # _LOG_TYPES config; overwrite with apache's own config so the two
        # stay independent even if nginx's values ever diverge.
        config = _LOG_TYPES["access"]
        row["timestamp_desc"] = config["timestamp_desc"]
        row["data_type"] = config["data_type"]
        return row

    match = _CLF_RE.match(line)
    if not match:
        return None

    ip, remote_ident, remote_user, timestamp_str, request, status, size = match.groups()

    try:
        dt = datetime.datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

    request_parts = request.split(" ")
    method = request_parts[0] if len(request_parts) > 0 else None
    uri = request_parts[1] if len(request_parts) > 1 else None
    protocol = request_parts[2] if len(request_parts) > 2 else None

    config = _LOG_TYPES["access"]
    return {
        "message": line.strip(),
        "datetime": to_iso8601(to_unix_microseconds(dt), unit="us"),
        "timestamp": to_unix_microseconds(dt),
        "timestamp_desc": config["timestamp_desc"],
        "data_type": config["data_type"],
        "source": source_file,
        "log_type": "access",
        "src_ip": normalize_ip(ip),
        "remote_ident": remote_ident if remote_ident != "-" else None,
        "remote_user": remote_user if remote_user != "-" else None,
        "http_method": method,
        "http_uri": uri,
        "http_protocol": protocol,
        "http_request_full": request,
        "status_code": int(status),
        "response_size": int(size) if size.isdigit() else 0,
    }


def _split_client(client: str) -> tuple[str, int | None]:
    """Split an error-log ``[client ip:port]`` value; IPv6-safe.

    IPv6 hosts are themselves bracketed (``[2001:db8::1]:5678``), so a
    leading ``[...]`` is treated as the whole host and only a ``:port``
    directly after it is split off. A bare (unbracketed) host is split on
    the last colon, but only when it's a single colon+digits suffix, since a
    raw IPv6 address without brackets or a port also contains colons.
    """
    if client.startswith("["):
        end = client.find("]")
        if end != -1:
            ip = client[1:end]
            rest = client[end + 1:]
            port = int(rest[1:]) if rest[:1] == ":" and rest[1:].isdigit() else None
            return normalize_ip(ip), port
        return normalize_ip(client), None

    if client.count(":") == 1:
        head, _, tail = client.rpartition(":")
        if tail.isdigit() and head:
            return normalize_ip(head), int(tail)

    return normalize_ip(client), None


def _parse_error_line(line: str, source_file: str) -> dict[str, Any] | None:
    """Parse an Apache 2.4 or 2.2 error log line."""
    module: str | None = None
    pid: str | None = None
    tid: str | None = None

    match = _ERROR_24_RE.match(line)
    if match:
        timestamp_str, module, level, pid, tid, client, message = match.groups()
    else:
        match = _ERROR_22_RE.match(line)
        if not match:
            return None
        timestamp_str, level, client, message = match.groups()

    dt: datetime.datetime | None = None
    for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
        try:
            dt = datetime.datetime.strptime(timestamp_str, fmt)
            break
        except ValueError:
            continue
    if dt is None:
        return None
    # Apache error logs carry no timezone; treat as UTC like nginx errors.
    dt = dt.replace(tzinfo=datetime.timezone.utc)

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
        "module": module,
        "worker_pid": int(pid) if pid else None,
        "worker_tid": int(tid) if tid else None,
    }

    if client:
        src_ip, src_port = _split_client(client)
        row["src_ip"] = src_ip
        if src_port is not None:
            row["src_port"] = src_port

    code_match = _AH_CODE_RE.search(message)
    if code_match:
        row["error_code"] = code_match.group(1)

    return row


def _parse_line(line: str, log_type: str, source_file: str) -> dict[str, Any] | None:
    """Parse a single log line according to its detected log type."""
    if log_type == "access":
        return _parse_apache_access_line(line, source_file)
    if log_type == "error":
        return _parse_error_line(line, source_file)
    return None


def _sniff_log_type(path: Path) -> str | None:
    """Detect the log type from file content by sampling the first lines."""
    access_hits = 0
    error_hits = 0
    sampled = 0
    try:
        with _open_log(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if _parse_apache_access_line(line, "") is not None:
                    access_hits += 1
                elif _ERROR_24_RE.match(line) or _ERROR_22_RE.match(line):
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
        log_type = _detect_log_type(path.name) or _sniff_log_type(path)
        if log_type is None:
            raise ConverterError(
                f"Could not determine log type for: {input_path} "
                "(filename not recognized and content matches neither the "
                "Apache access log formats nor the error log formats)"
            )
        return {log_type: [path]}

    if path.is_dir():
        files_by_type: dict[str, list[Path]] = {}
        for log_type, config in _LOG_TYPES.items():
            found: set[Path] = set()
            for pattern in config["patterns"]:
                found.update(path.glob(pattern))
            if found:
                files_by_type[log_type] = sorted(found)
        if not files_by_type:
            raise ConverterError(f"No supported Apache log files found in: {input_path}")
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
        raise ConverterError(f"No supported Apache log files matched: {input_path}")
    return files_by_type


def convert_apache(
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
) -> dict[str, int]:
    """Convert Apache log files to a Timesketch timeline.

    Returns:
        Mapping of log_type -> number of rows written.
    """
    files_by_type = _find_log_files(input_path)

    ui = get_terminal()
    ui.header(
        "apache2timesketch",
        subtitle="Convert Apache access/error logs → Timesketch timeline",
        badges=[("apache", "accent"), (output_format, "muted")],
    )
    ui.step("Log types found", ", ".join(files_by_type.keys()))

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("apache2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)
        else:
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
    rows_unparseable = 0

    def _stream_files(log_type: str, files: list[Path], writer: OutputWriter) -> int:
        """Parse the given files and write rows straight to the writer."""
        nonlocal processed_files, rows_unparseable
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
                        line = line.strip()
                        if not line:
                            continue
                        row = _parse_line(line, log_type, str(log_file.resolve()))
                        if row is None:
                            rows_unparseable += 1
                            continue
                        if not _filter_by_time(row, since_dt, until_dt):
                            continue
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
                split=split,
            )
            _stream_files(log_type, files, writer)
            counts[log_type] = writer.write()
            if report:
                add_writer_output(report, writer)
            ui.success(f"Wrote {counts[log_type]:,} rows to {dest}")
    else:
        writer = OutputWriter(
            output,
            output_format,
            fieldnames=_fieldnames_for(list(files_by_type.keys())),
            compute_hash=compute_hash,
            split=split,
        )
        for log_type, files in files_by_type.items():
            _stream_files(log_type, files, writer)
        total = writer.write()
        counts = {"combined": total}
        if report:
            add_writer_output(report, writer)

    if report:
        report.set_statistics({
            "rows_by_type": counts,
            "rows_unparseable": rows_unparseable,
            "since": since,
            "until": until,
            "output_dir": output_dir,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    summary_items: dict[str, Any] = {
        "Files processed": str(total_files),
        "Unparseable": f"{rows_unparseable:,}",
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
    }
    if output_dir:
        summary_items["Output directory"] = output_dir
    for log_type, count in counts.items():
        summary_items[f"Rows ({log_type})"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return counts
