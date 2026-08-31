#!/usr/bin/env python3
"""Microsoft Exchange Server protocol logs to Timesketch timeline converter.

Exchange writes most of its per-request protocol logs as CSV with a small
directive preamble::

    DateTime,RequestId,MajorVersion,...          <- bare duplicate of #Fields
    #Software: Microsoft Exchange Server
    #Version: 15.01.2507.060
    #Log-type: HttpProxy Logs
    #Date: 2026-07-25T18:00:14.352Z
    #Fields: DateTime,RequestId,MajorVersion,...
    2026-07-25T18:00:14.351Z,675a4875-...,15,1,...

The same shape is used by HttpProxy (per front-end protocol: Autodiscover,
Owa, Ews, Mapi, ActiveSync, Rpc, ...), ECP, RPC Client Access, IMAP4/POP3 and
the Autodiscover back end. This converter is generic over ``#Fields:`` and
carries a canonical mapping for the names those logs share, so an unmodelled
log type still converts with its own column names intact.

Two shapes are handled deliberately rather than by accident:

  * The **bare header line** before the preamble is Exchange's own doing, not
    a data row. It is recognized as a duplicate of the later ``#Fields:`` set
    and dropped; parsed as data it would produce one garbage event per file
    whose "timestamp" is the string ``DateTime``.
  * A **row with no DateTime** is real: Exchange emits periodic
    ``GlobalActivity`` metric rows with the timestamp column empty. Timesketch
    has no null timestamp, so such a row is anchored to the timestamp of the
    nearest preceding dated row in the same file and flagged
    ``timestamp_inferred``. Dropping it would silently discard the latency and
    error counters that explain the rows around it.
"""

from __future__ import annotations

import csv
import datetime
import gzip
import re
import sys
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

_DIRECTIVE_RE = re.compile(r"^#\s*([A-Za-z][A-Za-z-]*)\s*:\s*(.*)$")

# Exchange field names are CamelCase ("ClientIpAddress"), Pascal with runs of
# capitals ("HttpStatus", "TotalGlsLatency"), or hyphenated lowercase in the
# older message-tracking style ("client-ip").
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_SANITIZE_RE = re.compile(r"[^a-z0-9]+")

# Columns that may carry the row's timestamp, in preference order.
_TIMESTAMP_FIELDS = ("datetime", "date-time", "timestamp", "date", "time")


class ExchangeParseError(ConverterError):
    """Raised when an Exchange protocol log cannot be parsed."""


# ---------------------------------------------------------------------------
# Field naming
# ---------------------------------------------------------------------------

# Exchange field name (lowercased) -> canonical suite column.
_FIELD_MAP = {
    "clientipaddress": "src_ip",
    "clientip": "src_ip",
    "client-ip": "src_ip",
    "originalclientip": "x_forwarded_for",
    "serverip": "dst_ip",
    "server-ip": "dst_ip",
    "serverhostname": "server_name",
    "server-hostname": "server_name",
    "servername": "server_name",
    "authenticateduser": "username",
    "user": "username",
    "username": "username",
    "urlhost": "http_host",
    "urlstem": "http_uri",
    "urlquery": "http_query",
    "method": "http_method",
    "httpstatus": "status_code",
    "backendstatus": "backend_status",
    "useragent": "user_agent",
    "requestbytes": "request_size",
    "responsebytes": "response_size",
    "authenticationtype": "auth_type",
    "isauthenticated": "is_authenticated",
    "errorcode": "error_code",
    "totalrequesttime": "time_taken_ms",
    "protocol": "protocol",
    "targetserver": "target_server",
    "anchormailbox": "anchor_mailbox",
    "organization": "organization",
    "protocolaction": "protocol_action",
    "proxyaction": "proxy_action",
    "routingtype": "routing_type",
    "routingstatus": "routing_status",
    "requestid": "request_id",
    "clientrequestid": "client_request_id",
}

_INT_COLUMNS = {
    "status_code",
    "backend_status",
    "request_size",
    "response_size",
    "time_taken_ms",
    "error_code",
}


def _sanitize_field(name: str) -> str:
    """Return an Exchange field name as a lowercase snake_case column name."""
    spaced = _CAMEL_BOUNDARY_RE.sub("_", name.strip())
    return _SANITIZE_RE.sub("_", spaced.lower()).strip("_") or "field"


def canonical_field(name: str) -> str:
    """Map an Exchange field name to its suite column name."""
    return _FIELD_MAP.get(name.strip().lower()) or _sanitize_field(name)


def _decode_value(column: str, value: str) -> Any:
    """Decode one CSV value; empty columns are omitted from the row."""
    value = value.strip()
    if not value:
        return None
    if column in _INT_COLUMNS:
        try:
            return int(value)
        except ValueError:
            return value
    return value


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------

def parse_exchange_datetime(value: str) -> datetime.datetime | None:
    """Parse an Exchange timestamp into a UTC-aware datetime.

    Exchange writes ISO 8601 with a ``Z`` suffix in the newer logs and a
    localized ``M/D/YYYY h:mm:ss AM/PM`` in some older ones; both appear in
    the same estate after an in-place upgrade.
    """
    value = value.strip()
    if not value:
        return None
    iso = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
    try:
        dt = datetime.datetime.fromisoformat(iso)
    except ValueError:
        for fmt in (
            "%m/%d/%Y %I:%M:%S %p",
            "%m/%d/%Y %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                dt = datetime.datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


# ---------------------------------------------------------------------------
# File parsing
# ---------------------------------------------------------------------------

class _FileState:
    """Directive and column state carried across the lines of one file."""

    def __init__(self) -> None:
        self.fields: list[str] = []
        self.columns: list[str] = []
        self.software: str = ""
        self.version: str = ""
        self.log_type: str = ""
        self.field_sets: int = 0
        self.last_dt: datetime.datetime | None = None
        self.inferred_rows: int = 0

    def apply_directive(self, name: str, value: str) -> None:
        key = name.lower()
        value = value.strip()
        if key == "fields":
            self.fields = [f.strip() for f in value.split(",")]
            self.columns = [canonical_field(f) for f in self.fields]
            self.field_sets += 1
        elif key == "software":
            self.software = value
        elif key == "version":
            self.version = value
        elif key == "log-type":
            self.log_type = value


def _log_type_slug(log_type: str) -> str:
    """Turn "HttpProxy Logs" into "httpproxy" for data_type/grouping."""
    slug = _SANITIZE_RE.sub("_", log_type.lower()).strip("_")
    slug = re.sub(r"_?logs?$", "", slug)
    return slug or "protocol"


def parse_row(
    values: list[str], state: _FileState, source_file: str
) -> dict[str, Any] | None:
    """Build a timeline row from one parsed CSV record."""
    if not state.fields:
        return None

    raw = dict(zip(state.fields, values))
    lowered = {k.strip().lower(): v for k, v in raw.items()}

    dt: datetime.datetime | None = None
    for candidate in _TIMESTAMP_FIELDS:
        if candidate in lowered:
            dt = parse_exchange_datetime(lowered[candidate])
            if dt is not None:
                break

    inferred = False
    if dt is None:
        # A metric row with an empty timestamp column. Anchor it to the last
        # dated row so it keeps its place in the timeline instead of being
        # dropped; the flag makes the anchoring auditable.
        if state.last_dt is None:
            return None
        dt = state.last_dt
        inferred = True
        state.inferred_rows += 1
    else:
        state.last_dt = dt

    slug = _log_type_slug(state.log_type) if state.log_type else "protocol"
    row: dict[str, Any] = {
        "message": ",".join(values),
        "datetime": to_iso8601(to_unix_microseconds(dt), unit="us"),
        "timestamp": to_unix_microseconds(dt),
        "timestamp_desc": "Exchange Request Time",
        "data_type": f"exchange:{slug}:entry",
        "source": source_file,
        "log_type": slug,
        "src_ip": "",
        "dst_ip": "",
    }
    if state.software:
        row["software"] = state.software
    if state.version:
        row["server_version"] = state.version
    if state.log_type:
        row["exchange_log_type"] = state.log_type
    if inferred:
        row["timestamp_inferred"] = "true"

    for field, value in zip(state.fields, values):
        column = canonical_field(field)
        if column in ("date_time", "datetime", "timestamp", "date", "time"):
            continue
        if column in ("src_ip", "dst_ip"):
            address = value.strip().strip("[]")
            if not address:
                continue
            row[column] = normalize_ip(address) or address
            continue
        decoded = _decode_value(column, value)
        if decoded is not None:
            row[column] = decoded

    return row


# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------

_LOG_GLOBS = ["*.LOG", "*.log", "*.log.gz", "*.LOG.gz", "*.csv"]


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace", newline="")
    return open(path, "r", encoding="utf-8-sig", errors="replace", newline="")


def is_exchange_log(path: Path) -> bool:
    """Return True when the file's preamble names Exchange as its producer."""
    try:
        with _open_log(path) as fh:
            for index, line in enumerate(fh):
                stripped = line.strip()
                if stripped.startswith("#"):
                    match = _DIRECTIVE_RE.match(stripped)
                    if match:
                        key = match.group(1).lower()
                        value = match.group(2).lower()
                        if key == "software" and "exchange" in value:
                            return True
                        if key == "log-type":
                            return True
                if index >= 16:
                    break
    except OSError:
        return False
    return False


def find_log_files(input_path: str) -> list[Path]:
    """Resolve the input path into Exchange protocol log files.

    A directory is searched recursively: Exchange nests its logs one directory
    per protocol (``HttpProxy/Autodiscover``, ``HttpProxy/Owa``, ...), so the
    useful thing to point this at is the parent.
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
        found = sorted(p for p in seen if is_exchange_log(p))
        if not found:
            raise ConverterError(
                f"No Exchange protocol log files found in: {input_path} "
                "(no file carried a '#Software: Microsoft Exchange Server' or "
                "'#Log-type:' directive in its preamble)"
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


def convert_exchange(
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
    """Convert Exchange protocol log files to a Timesketch timeline.

    Returns:
        Mapping of log type -> number of rows written (or ``{"combined": n}``).
    """
    files = find_log_files(input_path)

    ui = get_terminal()
    ui.header(
        "exchange2timesketch",
        subtitle="Convert Exchange HttpProxy/ECP/RPC protocol logs → Timesketch timeline",
        badges=[("exchange", "accent"), (output_format, "muted")],
    )
    ui.step("Files found", str(len(files)))

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("exchange2timesketch", command_line or [])
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

    # Exchange nests one directory per protocol; group by that directory name
    # so --output-dir yields one timeline per protocol rather than one blob.
    files_by_group: dict[str, list[Path]] = {}
    for log_file in files:
        files_by_group.setdefault(log_file.parent.name.lower() or "exchange", []).append(log_file)

    total_files = len(files)
    processed_files = 0
    compute_hash = report_path is not None
    counts: dict[str, int] = {}
    stats = {"rows": 0, "inferred": 0, "skipped": 0, "field_sets": 0}

    def _stream_files(group: str, log_files: list[Path], writer: OutputWriter) -> None:
        nonlocal processed_files
        for log_file in log_files:
            processed_files += 1
            ui.step(f"[{processed_files}/{total_files}] {group}", str(log_file))
            state = _FileState()
            try:
                with _open_log(log_file) as fh:
                    source = str(log_file.resolve())
                    for values in csv.reader(fh):
                        if not values:
                            continue
                        first = values[0].lstrip()
                        if first.startswith("#"):
                            # A directive line: csv.reader splits it on the
                            # commas of the field list, so rejoin it first.
                            match = _DIRECTIVE_RE.match(",".join(values).strip())
                            if match:
                                state.apply_directive(match.group(1), match.group(2))
                            continue
                        if not state.fields:
                            # The bare header line Exchange writes before the
                            # preamble; the authoritative #Fields: follows.
                            continue
                        if values == state.fields:
                            continue
                        row = parse_row(values, state, source)
                        if row is None:
                            stats["skipped"] += 1
                            continue
                        if not _filter_by_time(row, since_dt, until_dt):
                            continue
                        writer.add({k: v for k, v in row.items() if v is not None})
                        stats["rows"] += 1
            except OSError as exc:
                raise ConverterError(f"Failed to read {log_file}: {exc}") from exc
            stats["inferred"] += state.inferred_rows
            stats["field_sets"] += state.field_sets

    if output_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for group, log_files in sorted(files_by_group.items()):
            dest = out_dir / f"timesketch_{group}.{output_format}"
            writer = OutputWriter(
                str(dest), output_format, compute_hash=compute_hash, split=split
            )
            _stream_files(group, log_files, writer)
            counts[group] = writer.write()
            if report:
                add_writer_output(report, writer)
            ui.success(f"Wrote {counts[group]:,} rows to {dest}")
    else:
        writer = OutputWriter(output, output_format, compute_hash=compute_hash, split=split)
        for group, log_files in sorted(files_by_group.items()):
            _stream_files(group, log_files, writer)
        counts = {"combined": writer.write()}
        if report:
            add_writer_output(report, writer)

    if stats["inferred"]:
        log(
            f"{stats['inferred']} row(s) had no timestamp column and were anchored "
            "to the preceding dated row (timestamp_inferred=true)",
            verbose,
        )

    if report:
        report.set_statistics({
            "rows_by_group": counts,
            "files_by_group": {g: len(v) for g, v in files_by_group.items()},
            "field_directives_seen": stats["field_sets"],
            "rows_with_inferred_timestamp": stats["inferred"],
            "skipped_rows": stats["skipped"],
            "timezone_assumption": (
                "Exchange DateTime values carry an explicit UTC offset and are "
                "honored; a naive value is taken as UTC"
            ),
            "since": since,
            "until": until,
            "output_dir": output_dir,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    summary_items: dict[str, Any] = {
        "Files processed": str(total_files),
        "Field directives": str(stats["field_sets"]),
        "Inferred timestamps": f"{stats['inferred']:,}",
        "Skipped rows": f"{stats['skipped']:,}",
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
    }
    if output_dir:
        summary_items["Output directory"] = output_dir
    for group, count in counts.items():
        summary_items[f"Rows ({group})"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return counts


# Exchange HttpProxy rows carry a GenericInfo column that can run to several
# kilobytes; the stdlib default field limit is generous but not unbounded.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
