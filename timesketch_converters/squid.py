#!/usr/bin/env python3
"""Squid proxy logs to Timesketch timeline converter.

Handles the three logs a Squid deployment actually writes:

  * ``access.log`` — one row per proxied request, in either the native
    ``logformat squid`` (``<unix.msec> <elapsed> <client> <CODE/status>
    <bytes> <method> <url> <user> <hierarchy/peer> <content-type>``) or the
    httpd-style ``common``/``combined`` formats. The format is detected from
    the data rather than assumed, because which one is in use is a one-line
    config choice that nothing in the file announces.
  * ``cache.log`` — the daemon's own diary: startup, reconfigure, helper
    churn, and the ``WARNING``/``ERROR``/``FATAL``/``SECURITY ALERT`` lines
    that explain why access.log looks the way it does. Both the ``kidN|``
    SMP-worker prefix and the ``(helper)[pid] LEVEL`` form that helper
    processes write into the same file are parsed.
  * ``icap.log`` — the ICAP (content-adaptation) transaction log, which
    shares access.log's native prefix.

**Timezone.** access.log timestamps are Unix epoch seconds, which are
unambiguous. cache.log and the httpd-style access formats without an offset
are *not*: Squid writes them in the server's local time with no offset
recorded. They are taken as UTC by default and ``--assume-tz`` overrides
that for the whole run; either way the choice is written into the audit
report, so a timeline shifted by an hour is a visible decision rather than a
silent one.
"""

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
    add_writer_output,
    log,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal

# Native "logformat squid": epoch.msec, elapsed ms, client, CODE/status,
# bytes, method, URL, rfc931 user, hierarchy/peer, content type.
_NATIVE_RE = re.compile(
    r"^\s*(?P<epoch>\d{9,11}(?:\.\d+)?)\s+"
    r"(?P<elapsed>-?\d+)\s+"
    r"(?P<client>\S+)\s+"
    r"(?P<code>[A-Z_]+(?:_[A-Z]+)*)/(?P<status>\d{3})\s+"
    r"(?P<bytes>\d+)\s+"
    r"(?P<method>\S+)\s+"
    r"(?P<url>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<hier>[A-Z_]+)/(?P<peer>\S+)"
    r"(?:\s+(?P<ctype>\S+))?"
    r"(?P<rest>.*)$"
)

# httpd-style "common"/"combined": the trailing "TCP_MISS:HIER_DIRECT" token
# is what distinguishes a Squid common log from a plain Apache one.
_HTTPD_RE = re.compile(
    r'^(?P<client>\S+) (?P<ident>\S*) (?P<user>\S*) \[(?P<ts>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<agent>(?:[^"\\]|\\.)*)")?'
    r'(?:\s+(?P<code>[A-Z_]+):(?P<hier>[A-Z_]+))?\s*$'
)

# cache.log, SMP form:  "2026/08/23 00:17:03 kid3| storeDirWriteCleanLogs: ..."
# cache.log, plain:     "2026/08/23 00:17:03| Starting Squid ..."
_CACHE_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"(?: kid(?P<kid>\d+))?\|\s?(?P<message>.*)$"
)

# cache.log, helper form: "2026/08/23 00:34:44 (socat)[19907] E connect(...)"
# The level is a single letter in the helper convention (D/I/N/W/E/F).
_CACHE_HELPER_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"\(?(?P<program>[\w.+-]+)\)?\[(?P<pid>\d+)\]\s+"
    r"(?:(?P<level>[DINWEF])\s+)?(?P<message>.*)$"
)

# Severity words Squid puts at the head of a cache.log message.
_SEVERITY_RE = re.compile(
    r"^(SECURITY ALERT|FATAL|ERROR|WARNING|CRITICAL|NOTICE|DEBUG|INFO)\s*:?\s*",
    re.IGNORECASE,
)

_HELPER_LEVELS = {
    "D": "debug",
    "I": "info",
    "N": "notice",
    "W": "warning",
    "E": "error",
    "F": "fatal",
}

_LOG_TYPES = {
    "access": {
        "timestamp_desc": "Proxy Request Time",
        "data_type": "squid:access:entry",
    },
    "cache": {
        "timestamp_desc": "Squid Log Entry Time",
        "data_type": "squid:cache:entry",
    },
    "icap": {
        "timestamp_desc": "ICAP Transaction Time",
        "data_type": "squid:icap:entry",
    },
}

_EXTRA_FIELDS_BY_TYPE = {
    "access": sorted([
        "content_type",
        "duration_ms",
        "hierarchy_code",
        "http_method",
        "http_url",
        "log_type",
        "peer_host",
        "referer",
        "remote_ident",
        "response_size",
        "squid_code",
        "squid_format",
        "status_code",
        "user_agent",
        "username",
    ]),
    "cache": sorted([
        "log_type",
        "kid",
        "process_id",
        "program",
        "severity",
        "timestamp_inferred",
    ]),
    "icap": sorted([
        "duration_ms",
        "http_method",
        "http_url",
        "icap_service",
        "log_type",
        "response_size",
        "squid_code",
        "status_code",
        "username",
    ]),
}


class SquidParseError(ConverterError):
    """Raised when a Squid log line cannot be parsed."""


def _fieldnames_for(log_types: list[str]) -> list[str]:
    """Build the fixed CSV column order for the given log types."""
    extras: set[str] = set()
    for log_type in log_types:
        extras.update(_EXTRA_FIELDS_BY_TYPE[log_type])
    return list(COMMON_FIELDS) + sorted(extras)


# ---------------------------------------------------------------------------
# Timezone handling
# ---------------------------------------------------------------------------

def parse_tz_offset(value: str | None) -> datetime.timezone:
    """Parse an ``--assume-tz`` value into a fixed-offset timezone.

    Accepts ``UTC``/``Z``, ``local`` (the converting machine's current
    offset), or an explicit ``+HH:MM`` / ``-HHMM`` / ``+02`` offset.
    """
    if not value or value.upper() in {"UTC", "Z"}:
        return datetime.timezone.utc
    if value.lower() == "local":
        offset = datetime.datetime.now().astimezone().utcoffset()
        return datetime.timezone(offset or datetime.timedelta(0))
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})?", value.strip())
    if not match:
        raise ConverterError(
            f"Invalid --assume-tz value {value!r}: use UTC, local, or an "
            "offset such as +02:00."
        )
    sign = 1 if match.group(1) == "+" else -1
    hours = int(match.group(2))
    minutes = int(match.group(3) or 0)
    return datetime.timezone(sign * datetime.timedelta(hours=hours, minutes=minutes))


# ---------------------------------------------------------------------------
# Line parsing
# ---------------------------------------------------------------------------

def _row_base(log_type: str, dt: datetime.datetime, line: str, source_file: str) -> dict[str, Any]:
    config = _LOG_TYPES[log_type]
    return {
        "message": line,
        "datetime": to_iso8601(to_unix_microseconds(dt), unit="us"),
        "timestamp": to_unix_microseconds(dt),
        "timestamp_desc": config["timestamp_desc"],
        "data_type": config["data_type"],
        "source": source_file,
        "log_type": log_type,
        "src_ip": "",
        "dst_ip": "",
    }


def _parse_native(line: str, log_type: str, source_file: str) -> dict[str, Any] | None:
    """Parse a native ``logformat squid`` access.log / icap.log line."""
    match = _NATIVE_RE.match(line)
    if not match:
        return None
    g = match.groupdict()
    dt = datetime.datetime.fromtimestamp(float(g["epoch"]), tz=datetime.timezone.utc)

    row = _row_base(log_type, dt, line, source_file)
    row["squid_format"] = "native"
    row["src_ip"] = normalize_ip(g["client"])
    if not row["src_ip"]:
        row["client_host"] = g["client"]
    row["duration_ms"] = int(g["elapsed"])
    row["squid_code"] = g["code"]
    row["status_code"] = int(g["status"])
    row["response_size"] = int(g["bytes"])
    row["http_method"] = g["method"]
    row["http_url"] = g["url"]
    if g["user"] and g["user"] != "-":
        row["username"] = g["user"]
    row["hierarchy_code"] = g["hier"]
    if g["peer"] and g["peer"] != "-":
        row["peer_host"] = g["peer"]
        row["dst_ip"] = normalize_ip(g["peer"])
    if g["ctype"] and g["ctype"] != "-":
        row["content_type"] = g["ctype"]
    if log_type == "icap":
        # icap.log reuses the native prefix; its "url" column is the ICAP
        # service URI, which is the field an analyst filters on.
        row["icap_service"] = g["url"]
    return row


def _parse_httpd(
    line: str, log_type: str, source_file: str, tz: datetime.timezone
) -> dict[str, Any] | None:
    """Parse an httpd-style ``common``/``combined`` Squid access.log line."""
    match = _HTTPD_RE.match(line)
    if not match:
        return None
    g = match.groupdict()
    try:
        dt = datetime.datetime.strptime(g["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        try:
            dt = datetime.datetime.strptime(g["ts"], "%d/%b/%Y:%H:%M:%S").replace(tzinfo=tz)
        except ValueError:
            return None
    dt = dt.astimezone(datetime.timezone.utc)

    row = _row_base(log_type, dt, line, source_file)
    row["squid_format"] = "combined" if g["agent"] is not None else "common"
    row["src_ip"] = normalize_ip(g["client"])
    if not row["src_ip"]:
        row["client_host"] = g["client"]
    if g["ident"] and g["ident"] != "-":
        row["remote_ident"] = g["ident"]
    if g["user"] and g["user"] != "-":
        row["username"] = g["user"]
    parts = g["request"].split(" ")
    if parts:
        row["http_method"] = parts[0]
    if len(parts) > 1:
        row["http_url"] = parts[1]
    row["status_code"] = int(g["status"])
    if g["bytes"].isdigit():
        row["response_size"] = int(g["bytes"])
    if g["referer"] and g["referer"] != "-":
        row["referer"] = g["referer"]
    if g["agent"] and g["agent"] != "-":
        row["user_agent"] = g["agent"]
    if g["code"]:
        row["squid_code"] = g["code"]
    if g["hier"]:
        row["hierarchy_code"] = g["hier"]
    return row


def _parse_cache(
    line: str,
    source_file: str,
    tz: datetime.timezone,
    last_dt: datetime.datetime | None,
) -> dict[str, Any] | None:
    """Parse a cache.log line, including helper output and continuations."""
    match = _CACHE_RE.match(line)
    helper = None
    if not match:
        helper = _CACHE_HELPER_RE.match(line)
    if not match and not helper:
        # A continuation of the previous entry (Squid wraps long messages and
        # prints unprefixed detail lines). Keeping it anchored to the entry it
        # belongs to preserves the reason text that the prefixed line omits.
        if last_dt is None or not line.strip():
            return None
        row = _row_base("cache", last_dt, line, source_file)
        row["timestamp_inferred"] = "true"
        return row

    g = (match or helper).groupdict()
    ts = g["ts"]
    fmt = "%Y/%m/%d %H:%M:%S.%f" if "." in ts else "%Y/%m/%d %H:%M:%S"
    try:
        dt = datetime.datetime.strptime(ts, fmt).replace(tzinfo=tz)
    except ValueError:
        return None
    dt = dt.astimezone(datetime.timezone.utc)

    message = g["message"]
    row = _row_base("cache", dt, line, source_file)
    if match:
        if g.get("kid"):
            row["kid"] = int(g["kid"])
    else:
        row["program"] = g["program"]
        row["process_id"] = int(g["pid"])
        if g.get("level"):
            row["severity"] = _HELPER_LEVELS.get(g["level"], g["level"])

    severity_match = _SEVERITY_RE.match(message)
    if severity_match:
        row["severity"] = severity_match.group(1).lower()

    found = [ip for ip in _iter_ips(message)]
    if found:
        row["src_ip"] = found[0]
    return row


def _iter_ips(text: str) -> Any:
    """Yield validated IPv4 addresses appearing in a free-form message."""
    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        normalized = normalize_ip(candidate)
        if normalized:
            yield normalized


def parse_line(
    line: str,
    log_type: str,
    source_file: str,
    tz: datetime.timezone,
    last_dt: datetime.datetime | None = None,
) -> dict[str, Any] | None:
    """Parse a single Squid log line according to its log type."""
    if log_type == "cache":
        return _parse_cache(line, source_file, tz, last_dt)
    if log_type in ("access", "icap"):
        return _parse_native(line, log_type, source_file) or _parse_httpd(
            line, log_type, source_file, tz
        )
    return None


# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------

_NAME_PATTERNS = {
    "access": ["access.log", "access_log"],
    "cache": ["cache.log", "cache_log"],
    "icap": ["icap.log", "icap_log"],
}


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def detect_log_type(filename: str) -> str | None:
    """Determine the Squid log type from a filename."""
    name = Path(filename).name.lower()
    for log_type, patterns in _NAME_PATTERNS.items():
        if any(name.startswith(pattern) for pattern in patterns):
            return log_type
    return None


def sniff_log_type(path: Path) -> str | None:
    """Detect the log type by sampling the first lines of the file."""
    access = cache = 0
    sampled = 0
    try:
        with _open_log(path) as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                if _NATIVE_RE.match(line) or _HTTPD_RE.match(line):
                    access += 1
                elif _CACHE_RE.match(line) or _CACHE_HELPER_RE.match(line):
                    cache += 1
                sampled += 1
                if sampled >= 50:
                    break
    except OSError:
        return None
    if access == 0 and cache == 0:
        return None
    return "access" if access >= cache else "cache"


def find_log_files(input_path: str) -> dict[str, list[Path]]:
    """Resolve the input path into Squid log files grouped by log type."""
    path = Path(input_path)

    if path.is_file():
        log_type = detect_log_type(path.name) or sniff_log_type(path)
        if log_type is None:
            raise ConverterError(
                f"Could not determine log type for: {input_path} "
                "(filename not recognized and content matches neither the "
                "access log formats nor the cache log format)"
            )
        return {log_type: [path]}

    if path.is_dir():
        files_by_type: dict[str, list[Path]] = {}
        for log_type, patterns in _NAME_PATTERNS.items():
            found: list[Path] = []
            for pattern in patterns:
                found.extend(sorted(path.glob(f"{pattern}*")))
            if found:
                files_by_type[log_type] = found
        if not files_by_type:
            raise ConverterError(f"No supported Squid log files found in: {input_path}")
        return files_by_type

    matches = sorted(Path(".").glob(input_path))
    if not matches:
        raise ConverterError(f"No files matched pattern: {input_path}")
    files_by_type = {}
    for match in matches:
        if not match.is_file():
            continue
        log_type = detect_log_type(match.name) or sniff_log_type(match)
        if log_type is None:
            continue
        files_by_type.setdefault(log_type, []).append(match)
    if not files_by_type:
        raise ConverterError(f"No supported Squid log files matched: {input_path}")
    return files_by_type


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------

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


def convert_squid(
    input_path: str,
    output: str,
    output_format: str,
    output_dir: str | None = None,
    since: str | None = None,
    until: str | None = None,
    assume_tz: str | None = None,
    verbose: bool = True,
    split: str | None = None,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, int]:
    """Convert Squid log files to a Timesketch timeline.

    Returns:
        Mapping of log_type -> number of rows written.
    """
    files_by_type = find_log_files(input_path)
    tz = parse_tz_offset(assume_tz)

    ui = get_terminal()
    ui.header(
        "squid2timesketch",
        subtitle="Convert Squid access/cache/icap logs → Timesketch timeline",
        badges=[("squid", "accent"), (output_format, "muted")],
    )
    ui.step("Log types found", ", ".join(files_by_type.keys()))
    ui.step("Naive timestamps", f"assumed {assume_tz or 'UTC'}")

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("squid2timesketch", command_line or [])
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
        since_dt = datetime.datetime.fromisoformat(since.replace("Z", "+00:00"))
        if since_dt.tzinfo is None:
            since_dt = since_dt.replace(tzinfo=datetime.timezone.utc)
    if until:
        until_dt = datetime.datetime.fromisoformat(until.replace("Z", "+00:00"))
        if until_dt.tzinfo is None:
            until_dt = until_dt.replace(tzinfo=datetime.timezone.utc)

    total_files = sum(len(files) for files in files_by_type.values())
    processed_files = 0
    compute_hash = report_path is not None
    counts: dict[str, int] = {}
    skipped_lines = 0
    continuation_lines = 0

    def _stream_files(log_type: str, files: list[Path], writer: OutputWriter) -> None:
        nonlocal processed_files, skipped_lines, continuation_lines
        for log_file in files:
            processed_files += 1
            ui.step(f"[{processed_files}/{total_files}] {log_type}", str(log_file))
            source = str(log_file.resolve())
            last_dt: datetime.datetime | None = None
            try:
                with _open_log(log_file) as fh:
                    for raw in fh:
                        line = raw.rstrip("\n").rstrip("\r")
                        if not line.strip():
                            continue
                        row = parse_line(line, log_type, source, tz, last_dt)
                        if row is None:
                            skipped_lines += 1
                            continue
                        if row.get("timestamp_inferred"):
                            continuation_lines += 1
                        else:
                            last_dt = datetime.datetime.fromtimestamp(
                                row["timestamp"] / 1_000_000, tz=datetime.timezone.utc
                            )
                        if not _filter_by_time(row, since_dt, until_dt):
                            continue
                        writer.add({k: v for k, v in row.items() if v is not None})
            except OSError as exc:
                raise ConverterError(f"Failed to read {log_file}: {exc}") from exc

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
        counts = {"combined": writer.write()}
        if report:
            add_writer_output(report, writer)

    if continuation_lines:
        log(
            f"{continuation_lines} cache.log continuation line(s) anchored to the "
            "preceding entry (timestamp_inferred=true)",
            verbose,
        )

    if report:
        report.set_statistics({
            "rows_by_type": counts,
            "skipped_lines": skipped_lines,
            "continuation_lines": continuation_lines,
            "timezone_assumption": (
                "access.log epoch timestamps are absolute UTC; naive cache.log "
                f"and httpd-format timestamps assumed {assume_tz or 'UTC'}"
            ),
            "since": since,
            "until": until,
            "output_dir": output_dir,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    summary_items: dict[str, Any] = {
        "Files processed": str(total_files),
        "Unparseable lines": f"{skipped_lines:,}",
        "Continuation lines": f"{continuation_lines:,}",
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
    }
    if output_dir:
        summary_items["Output directory"] = output_dir
    for log_type, count in counts.items():
        summary_items[f"Rows ({log_type})"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return counts
