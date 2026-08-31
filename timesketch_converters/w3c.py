#!/usr/bin/env python3
"""W3C Extended Log File Format to Timesketch timeline converter.

Covers the whole ``#Fields:``-described W3C Extended family, with per-variant
field semantics for the two Microsoft dialects that dominate incident work:

  * **IIS** site logs (``u_ex*.log``, ``#Software: Microsoft Internet
    Information Services``) — one row per HTTP request served.
  * **HTTPERR** (``httperr*.log``, ``#Software: Microsoft HTTP API``) — the
    http.sys kernel error log: requests rejected or timed out *before* IIS
    saw them, which is exactly where the evidence of a failed exploit
    attempt, a connection flood, or a stalled RPC proxy lives.
  * Any other W3C Extended log (Exchange front-end transport, Windows Media
    Services, third-party servers) is parsed generically from its own
    ``#Fields:`` directive.

The ``#Fields:`` directive is authoritative and is honoured *per occurrence*:
IIS rewrites it whenever the site's logging configuration changes or the
service restarts, so a single file can legitimately change its column set
mid-stream. Re-reading it is not an edge case — a converter that latches the
first directive silently shifts every column after an IIS restart.

Per the W3C spec (and IIS/http.sys defaults) the ``date``/``time`` fields are
UTC, and are taken as such. A log configured for local time is therefore
off by its offset; the flavor and that assumption are both recorded in the
audit report so the shift is visible rather than invisible.
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
    add_writer_output,
    log,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal

# "#Fields: date time c-ip ..." / "#Software: ..." / "#Date: 2025-04-08 11:11:32"
_DIRECTIVE_RE = re.compile(r"^#\s*([A-Za-z][A-Za-z-]*)\s*:\s*(.*)$")

# An IPv6 literal logged by Windows may carry a scope/zone index ("%3"), which
# ipaddress rejects. The zone is kept as its own column rather than dropped:
# it names the interface the address was seen on.
_ZONE_RE = re.compile(r"%[0-9A-Za-z]+$")


class W3CParseError(ConverterError):
    """Raised when a W3C Extended log cannot be parsed."""


# ---------------------------------------------------------------------------
# Flavors
# ---------------------------------------------------------------------------

# Matched against the "#Software:" directive, lowercased, in order.
_SOFTWARE_FLAVORS = [
    ("microsoft internet information services", "iis"),
    ("microsoft-iis", "iis"),
    ("microsoft http api", "httperr"),
    ("microsoft httpapi", "httperr"),
]

_FLAVORS = {
    "iis": {
        "timestamp_desc": "HTTP Request Time",
        "data_type": "iis:access:entry",
    },
    "httperr": {
        "timestamp_desc": "HTTP Error Time",
        "data_type": "httperr:error:entry",
    },
    "w3c": {
        "timestamp_desc": "W3C Log Entry Time",
        "data_type": "w3c:extended:entry",
    },
}

# Filename hints, checked before content. IIS names its logs by the fields it
# records (u_ex = extended/UTC, u_in = IIS format, u_nc = NCSA, ex/in/nc =
# local time), so the "u_"-less variants are matched too.
_FILENAME_FLAVORS = [
    (re.compile(r"^httperr", re.IGNORECASE), "httperr"),
    (re.compile(r"^u_(ex|in|nc|ec)\d", re.IGNORECASE), "iis"),
    (re.compile(r"^(ex|in|nc|ec)\d{6}", re.IGNORECASE), "iis"),
]


# ---------------------------------------------------------------------------
# Field naming
# ---------------------------------------------------------------------------

# W3C field name (lowercased) -> canonical suite column. Names not listed here
# are kept under a sanitized form of their own W3C name, so an unmodelled
# dialect loses nothing.
_FIELD_MAP = {
    "c-ip": "src_ip",
    "s-ip": "dst_ip",
    "c-port": "src_port",
    "s-port": "dst_port",
    "cs-method": "http_method",
    "cs-uri-stem": "http_uri",
    "cs-uri-query": "http_query",
    "cs-uri": "http_uri",
    "cs-version": "http_protocol",
    "cs-username": "username",
    "cs-host": "http_host",
    "cs(host)": "http_host",
    "cs(user-agent)": "user_agent",
    "cs(referer)": "referer",
    "cs(referrer)": "referer",
    "cs(cookie)": "cookie",
    "cs(x-forwarded-for)": "x_forwarded_for",
    "x-forwarded-for": "x_forwarded_for",
    "sc-status": "status_code",
    "sc-substatus": "sub_status",
    "sc-win32-status": "win32_status",
    "sc-bytes": "response_size",
    "cs-bytes": "request_size",
    "sc(x-powered-by)": "x_powered_by",
    "time-taken": "time_taken_ms",
    "s-sitename": "site_name",
    "s-computername": "server_name",
    "s-siteid": "site_id",
    "s-reason": "reason",
    "s-queuename": "queue_name",
    "streamid": "stream_id",
    "s-event": "event",
    "s-process-type": "process_type",
    "s-user-time": "user_time",
    "s-kernel-time": "kernel_time",
}

# Columns emitted as integers when the value parses as one.
_INT_COLUMNS = {
    "src_port",
    "dst_port",
    "status_code",
    "sub_status",
    "win32_status",
    "response_size",
    "request_size",
    "time_taken_ms",
    "site_id",
    "stream_id",
}

_SANITIZE_RE = re.compile(r"[^a-z0-9]+")


def _sanitize_field(name: str) -> str:
    """Return a W3C field name as a lowercase snake_case column name."""
    return _SANITIZE_RE.sub("_", name.strip().lower()).strip("_") or "field"


def canonical_field(name: str) -> str:
    """Map a W3C field name to its suite column name."""
    return _FIELD_MAP.get(name.strip().lower()) or _sanitize_field(name)


# ---------------------------------------------------------------------------
# Value decoding
# ---------------------------------------------------------------------------

def _split_ip_zone(value: str) -> tuple[str, str]:
    """Split ``fe80::1%3`` into its address and scope-zone parts."""
    match = _ZONE_RE.search(value)
    if not match:
        return value, ""
    return value[: match.start()], match.group(0)[1:]


def _decode_value(column: str, value: str) -> Any:
    """Decode one W3C field value into its output form.

    ``-`` is the format's "not recorded" placeholder and becomes an omitted
    column rather than a literal dash. IIS writes a ``+`` where the User-Agent
    contained a space; that substitution is reversed for the User-Agent alone,
    because it is the only field where a literal ``+`` is not also plausible
    payload (a URI, query, or Referer may legitimately contain one, and
    "fixing" those would corrupt the evidence).
    """
    if value == "-" or value == "":
        return None
    if column in _INT_COLUMNS:
        try:
            return int(value)
        except ValueError:
            return value
    if column == "user_agent":
        return value.replace("+", " ")
    return value


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------

def _parse_datetime(
    values: dict[str, str], header_date: str | None
) -> datetime.datetime | None:
    """Build a UTC datetime from the row's date/time fields.

    Handles the three shapes seen in the wild: separate ``date`` + ``time``
    columns (IIS, HTTPERR), a ``time`` column alone (the day then comes from
    the preceding ``#Date:`` directive), and a single combined ``date-time``
    ISO column.
    """
    combined = values.get("date-time") or values.get("datetime")
    if combined:
        try:
            dt = datetime.datetime.fromisoformat(
                re.sub(r"(\.\d{6})\d+", r"\1", combined.replace("Z", "+00:00"))
            )
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)

    time_str = values.get("time")
    if not time_str:
        return None
    date_str = values.get("date") or header_date
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.datetime.strptime(f"{date_str} {time_str}", fmt)
        except ValueError:
            continue
        return dt.replace(tzinfo=datetime.timezone.utc)
    return None


# ---------------------------------------------------------------------------
# Line parsing
# ---------------------------------------------------------------------------

class _FileState:
    """Directive state carried across the lines of one file.

    W3C directives are positional: a ``#Fields:`` line describes the rows that
    follow it, until the next one. IIS emits a fresh header block on every
    service restart and configuration change, so this state is re-read rather
    than latched.
    """

    def __init__(self, flavor: str | None = None):
        self.fields: list[str] = []
        self.columns: list[str] = []
        self.software: str = ""
        self.header_date: str | None = None
        self.flavor: str | None = flavor
        self.flavor_from_filename = flavor is not None
        self.field_sets: int = 0

    def apply_directive(self, name: str, value: str) -> None:
        key = name.lower()
        if key == "fields":
            self.fields = value.split()
            self.columns = [canonical_field(f) for f in self.fields]
            self.field_sets += 1
        elif key == "software":
            self.software = value.strip()
            if not self.flavor_from_filename:
                lowered = self.software.lower()
                for needle, flavor in _SOFTWARE_FLAVORS:
                    if needle in lowered:
                        self.flavor = flavor
                        break
        elif key == "date":
            # "#Date: 2025-04-08 11:11:32" — only the day part is useful as a
            # fallback for logs that record `time` without `date`.
            self.header_date = value.split()[0] if value.split() else None


def parse_line(line: str, state: _FileState, source_file: str) -> dict[str, Any] | None:
    """Parse one data line against the file's current ``#Fields:`` set.

    Returns None for blank lines, directive lines (which mutate ``state``),
    and rows that carry no usable timestamp.
    """
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith("#"):
        match = _DIRECTIVE_RE.match(stripped)
        if match:
            state.apply_directive(match.group(1), match.group(2))
        return None
    if not state.fields:
        return None

    parts = stripped.split(" ")
    # A trailing field may legitimately contain spaces in some dialects; fold
    # the surplus back into the last column rather than dropping it.
    if len(parts) > len(state.fields):
        head = parts[: len(state.fields) - 1]
        parts = head + [" ".join(parts[len(state.fields) - 1 :])]

    raw = {
        name.lower(): value
        for name, value in zip(state.fields, parts)
    }
    dt = _parse_datetime(raw, state.header_date)
    if dt is None:
        return None

    flavor = state.flavor or "w3c"
    config = _FLAVORS.get(flavor, _FLAVORS["w3c"])
    row: dict[str, Any] = {
        "message": stripped,
        "datetime": to_iso8601(to_unix_microseconds(dt), unit="us"),
        "timestamp": to_unix_microseconds(dt),
        "timestamp_desc": config["timestamp_desc"],
        "data_type": config["data_type"],
        "source": source_file,
        "log_type": flavor,
        "src_ip": "",
        "dst_ip": "",
    }
    if state.software:
        row["software"] = state.software

    for field, value in zip(state.fields, parts):
        column = canonical_field(field)
        if column in ("date", "time", "date_time", "datetime"):
            continue
        if column in ("src_ip", "dst_ip"):
            if value == "-":
                continue
            address, zone = _split_ip_zone(value)
            row[column] = normalize_ip(address) or address
            if zone:
                row[f"{column}_zone"] = zone
            continue
        decoded = _decode_value(column, value)
        if decoded is not None:
            row[column] = decoded

    return row


# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------

_LOG_GLOBS = ["*.log", "*.log.gz", "*.LOG", "*.txt", "u_*", "httperr*"]


def detect_flavor_from_name(filename: str) -> str | None:
    """Return the W3C flavor implied by a filename, if any."""
    name = Path(filename).name
    for pattern, flavor in _FILENAME_FLAVORS:
        if pattern.search(name):
            return flavor
    return None


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace")
    return open(path, "r", encoding="utf-8-sig", errors="replace")


def is_w3c_log(path: Path) -> bool:
    """Return True when the file's opening lines declare a ``#Fields:`` set."""
    try:
        with _open_log(path) as fh:
            for index, line in enumerate(fh):
                if line.startswith("#"):
                    match = _DIRECTIVE_RE.match(line.strip())
                    if match and match.group(1).lower() == "fields":
                        return True
                if index >= 32:
                    break
    except OSError:
        return False
    return False


def find_log_files(input_path: str) -> list[Path]:
    """Resolve the input path into W3C log files.

    A directory is searched recursively: IIS keeps one directory per site
    (``W3SVC1/``, ``W3SVC2/``) under a single log root, and HTTPERR sits
    beside them, so the useful thing to point this at is the root.
    """
    path = Path(input_path)

    if path.is_file():
        return [path]

    if path.is_dir():
        seen: set[Path] = set()
        for pattern in _LOG_GLOBS:
            for match in path.rglob(pattern):
                if match.is_file():
                    seen.add(match)
        found = sorted(p for p in seen if is_w3c_log(p))
        if not found:
            raise ConverterError(
                f"No W3C Extended log files found in: {input_path} "
                "(no file carried a '#Fields:' directive in its first lines)"
            )
        return found

    matches = sorted(p for p in Path(".").glob(input_path) if p.is_file())
    if not matches:
        raise ConverterError(f"No files matched pattern: {input_path}")
    return matches


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


def convert_w3c(
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
    """Convert W3C Extended log files to a Timesketch timeline.

    Returns:
        Mapping of flavor -> number of rows written (or ``{"combined": n}``).
    """
    files = find_log_files(input_path)

    ui = get_terminal()
    ui.header(
        "w3c2timesketch",
        subtitle="Convert IIS / HTTPERR / W3C Extended logs → Timesketch timeline",
        badges=[("w3c", "accent"), (output_format, "muted")],
    )
    ui.step("Files found", str(len(files)))

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("w3c2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)
        else:
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

    # Group by flavor so --output-dir can split IIS from HTTPERR, and so the
    # run summary names what was actually recognized.
    files_by_flavor: dict[str, list[Path]] = {}
    for log_file in files:
        flavor = detect_flavor_from_name(log_file.name) or _sniff_flavor(log_file) or "w3c"
        files_by_flavor.setdefault(flavor, []).append(log_file)
    ui.step("Flavors", ", ".join(sorted(files_by_flavor)))

    total_files = len(files)
    processed_files = 0
    compute_hash = report_path is not None
    counts: dict[str, int] = {}
    field_sets_seen = 0
    skipped_lines = 0

    def _stream_files(flavor: str, log_files: list[Path], writer: OutputWriter) -> None:
        nonlocal processed_files, field_sets_seen, skipped_lines
        for log_file in log_files:
            processed_files += 1
            ui.step(f"[{processed_files}/{total_files}] {flavor}", str(log_file))
            state = _FileState(
                flavor=detect_flavor_from_name(log_file.name)
            )
            try:
                with _open_log(log_file) as fh:
                    for line in fh:
                        stripped = line.strip()
                        if not stripped:
                            continue
                        row = parse_line(stripped, state, str(log_file.resolve()))
                        if row is None:
                            if not stripped.startswith("#"):
                                skipped_lines += 1
                            continue
                        if not _filter_by_time(row, since_dt, until_dt):
                            continue
                        writer.add({k: v for k, v in row.items() if v is not None})
            except OSError as exc:
                raise ConverterError(f"Failed to read {log_file}: {exc}") from exc
            field_sets_seen += state.field_sets
            if state.field_sets > 1:
                log(
                    f"{log_file.name}: {state.field_sets} '#Fields:' directives "
                    "(column set changed mid-file; each block parsed against its own)",
                    verbose,
                )

    if output_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for flavor, log_files in sorted(files_by_flavor.items()):
            dest = out_dir / f"timesketch_{flavor}.{output_format}"
            writer = OutputWriter(
                str(dest), output_format, compute_hash=compute_hash, split=split
            )
            _stream_files(flavor, log_files, writer)
            counts[flavor] = writer.write()
            if report:
                add_writer_output(report, writer)
            ui.success(f"Wrote {counts[flavor]:,} rows to {dest}")
    else:
        writer = OutputWriter(output, output_format, compute_hash=compute_hash, split=split)
        for flavor, log_files in sorted(files_by_flavor.items()):
            _stream_files(flavor, log_files, writer)
        counts = {"combined": writer.write()}
        if report:
            add_writer_output(report, writer)

    if report:
        report.set_statistics({
            "rows_by_flavor": counts,
            "files_by_flavor": {f: len(v) for f, v in files_by_flavor.items()},
            "field_directives_seen": field_sets_seen,
            "skipped_lines": skipped_lines,
            "timezone_assumption": "W3C date/time fields taken as UTC (format default)",
            "since": since,
            "until": until,
            "output_dir": output_dir,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    summary_items: dict[str, Any] = {
        "Files processed": str(total_files),
        "Field directives": str(field_sets_seen),
        "Unparseable lines": f"{skipped_lines:,}",
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
    }
    if output_dir:
        summary_items["Output directory"] = output_dir
    for flavor, count in counts.items():
        summary_items[f"Rows ({flavor})"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return counts


def _sniff_flavor(path: Path) -> str | None:
    """Read the file's ``#Software:`` directive to classify it."""
    state = _FileState()
    try:
        with _open_log(path) as fh:
            for index, line in enumerate(fh):
                stripped = line.strip()
                if stripped.startswith("#"):
                    match = _DIRECTIVE_RE.match(stripped)
                    if match:
                        state.apply_directive(match.group(1), match.group(2))
                if state.flavor or index >= 32:
                    break
    except OSError:
        return None
    return state.flavor
