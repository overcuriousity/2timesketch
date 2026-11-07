#!/usr/bin/env python3
"""conntrackd flow logs to Timesketch timeline converter.

``conntrackd`` writes one line per tracked connection when it is torn down::

    Tue Aug 25 16:19:13 2026\ttcp      6 TIME_WAIT src=10.0.0.5 dst=93.184.216.34 \\
      sport=60074 dport=443 packets=35 bytes=13734 src=93.184.216.34 \\
      dst=203.0.113.7 sport=443 dport=60074 packets=36 bytes=9954 [ASSURED] mark=1

Every line carries **two** tuples: the connection as the originator sent it,
and the reply as the kernel expects it back. That pairing is the reason this
log is worth converting rather than skimming — the reply tuple's destination
is the address the firewall NATted the client to, so a single line states the
private source, the public source, the real destination, and the byte counts
in both directions. This converter emits all four addresses as discrete
columns and derives ``nat_type`` (``snat``/``dnat``/``both``) from the
disagreement between them, which is what lets an analyst pivot from an
external observation back to the internal host.

``packets=0 bytes=0`` on the reply side together with ``[UNREPLIED]`` marks a
connection that was never answered — the shape a port scan or a blocked
egress attempt leaves behind.

**Timezone.** The ``ctime`` prefix carries no offset; it is the appliance's
local time. It is taken as UTC by default and ``--assume-tz`` overrides that
for the whole run, with the choice recorded in the audit report.
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
    expand_glob,
    log,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal

# "Tue Aug 25 16:19:13 2026" followed by a tab (or run of spaces) and the body.
_LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4})"
    r"[\t ]+(?P<body>.*)$"
)

# conntrackd/conntrack -E can prefix an event type: "[DESTROY] tcp 6 ...".
_EVENT_RE = re.compile(r"^\[(?P<event>[A-Z]+)\]\s+")

_FLAG_RE = re.compile(r"^\[(?P<flag>[A-Z_]+)\]$")

# Keys that describe the connection rather than one of its two tuples, so
# they must not be mistaken for the start of the reply tuple.
_CONNECTION_KEYS = {"mark", "use", "zone", "secctx", "timeout", "delta-time", "id-conn"}

# Tuple key -> (original column, reply column).
_TUPLE_COLUMNS = {
    "src": ("src_ip", "reply_src_ip"),
    "dst": ("dst_ip", "reply_dst_ip"),
    "sport": ("src_port", "reply_src_port"),
    "dport": ("dst_port", "reply_dst_port"),
    "packets": ("packets", "reply_packets"),
    "bytes": ("bytes", "reply_bytes"),
    "type": ("icmp_type", "reply_icmp_type"),
    "code": ("icmp_code", "reply_icmp_code"),
    "id": ("icmp_id", "reply_icmp_id"),
}

_INT_COLUMNS = {
    "src_port",
    "dst_port",
    "reply_src_port",
    "reply_dst_port",
    "packets",
    "bytes",
    "reply_packets",
    "reply_bytes",
    "icmp_type",
    "icmp_code",
    "icmp_id",
    "reply_icmp_type",
    "reply_icmp_code",
    "reply_icmp_id",
    "protocol_number",
    "conn_mark",
}

_EXTRA_FIELDS = sorted([
    "bytes",
    "conn_flags",
    "conn_mark",
    "dst_port",
    "event_type",
    "icmp_code",
    "icmp_id",
    "icmp_type",
    "log_type",
    "nat_type",
    "packets",
    "protocol",
    "protocol_number",
    "reply_bytes",
    "reply_dst_ip",
    "reply_dst_port",
    "reply_icmp_code",
    "reply_icmp_id",
    "reply_icmp_type",
    "reply_packets",
    "reply_src_ip",
    "reply_src_port",
    "src_port",
    "tcp_state",
    "total_bytes",
    "total_packets",
    "translated_dst_ip",
    "translated_src_ip",
    "unreplied",
])


class ConntrackdParseError(ConverterError):
    """Raised when a conntrackd log line cannot be parsed."""


def _fieldnames() -> list[str]:
    """Build the fixed CSV column order."""
    return list(COMMON_FIELDS) + _EXTRA_FIELDS


def parse_tz_offset(value: str | None) -> datetime.timezone:
    """Parse an ``--assume-tz`` value into a fixed-offset timezone."""
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


def _coerce(column: str, value: str) -> Any:
    if column in _INT_COLUMNS:
        try:
            return int(value)
        except ValueError:
            return value
    return value


def _derive_nat(row: dict[str, Any]) -> None:
    """Record the address translation implied by the two tuples.

    Without NAT the reply tuple is the exact mirror of the original one. A
    reply *destination* that differs from the original source means the
    source was rewritten on the way out (SNAT/masquerade), and a reply
    *source* that differs from the original destination means the destination
    was rewritten on the way in (DNAT/port forward).
    """
    src = row.get("src_ip")
    dst = row.get("dst_ip")
    reply_src = row.get("reply_src_ip")
    reply_dst = row.get("reply_dst_ip")
    if not (src and dst and reply_src and reply_dst):
        return

    snat = reply_dst != src
    dnat = reply_src != dst
    if snat:
        row["translated_src_ip"] = reply_dst
    if dnat:
        row["translated_dst_ip"] = reply_src
    if snat and dnat:
        row["nat_type"] = "both"
    elif snat:
        row["nat_type"] = "snat"
    elif dnat:
        row["nat_type"] = "dnat"


def parse_line(
    line: str, source_file: str, tz: datetime.timezone
) -> dict[str, Any] | None:
    """Parse one conntrackd flow line into a timeline row."""
    match = _LINE_RE.match(line)
    if not match:
        return None
    try:
        dt = datetime.datetime.strptime(match.group("ts"), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None
    dt = dt.replace(tzinfo=tz).astimezone(datetime.timezone.utc)

    body = match.group("body").strip()
    event = _EVENT_RE.match(body)
    event_type = None
    if event:
        event_type = event.group("event").lower()
        body = body[event.end():]

    tokens = body.split()
    if len(tokens) < 3:
        return None

    row: dict[str, Any] = {
        "message": line.rstrip(),
        "datetime": to_iso8601(to_unix_microseconds(dt), unit="us"),
        "timestamp": to_unix_microseconds(dt),
        "timestamp_desc": "Connection Tracking Event Time",
        "data_type": "conntrack:flow:entry",
        "source": source_file,
        "log_type": "conntrackd",
        "src_ip": "",
        "dst_ip": "",
        "protocol": tokens[0],
    }
    if event_type:
        row["event_type"] = event_type

    index = 1
    if index < len(tokens) and tokens[index].isdigit():
        row["protocol_number"] = int(tokens[index])
        index += 1
    # TCP carries its state as a bare uppercase word before the first tuple.
    if index < len(tokens) and "=" not in tokens[index] and not _FLAG_RE.match(tokens[index]):
        row["tcp_state"] = tokens[index]
        index += 1

    flags: list[str] = []
    reply = False
    seen: set[str] = set()
    for token in tokens[index:]:
        flag = _FLAG_RE.match(token)
        if flag:
            flags.append(flag.group("flag"))
            continue
        if "=" not in token:
            continue
        key, _, value = token.partition("=")
        key = key.lower()
        if key in _CONNECTION_KEYS:
            if key == "mark":
                row["conn_mark"] = _coerce("conn_mark", value)
            else:
                row[key.replace("-", "_")] = value
            continue
        columns = _TUPLE_COLUMNS.get(key)
        if columns is None:
            row.setdefault(key.replace("-", "_"), value)
            continue
        # The reply tuple begins at the first repeat of a tuple key.
        if key in seen:
            reply = True
            seen = {key}
        else:
            seen.add(key)
        column = columns[1] if reply else columns[0]
        if column.endswith("_ip"):
            row[column] = normalize_ip(value) or value
        else:
            row[column] = _coerce(column, value)

    if flags:
        row["conn_flags"] = ",".join(flags)
        if "UNREPLIED" in flags:
            row["unreplied"] = "true"

    packets = row.get("packets")
    reply_packets = row.get("reply_packets")
    if isinstance(packets, int) and isinstance(reply_packets, int):
        row["total_packets"] = packets + reply_packets
    orig_bytes = row.get("bytes")
    reply_bytes = row.get("reply_bytes")
    if isinstance(orig_bytes, int) and isinstance(reply_bytes, int):
        row["total_bytes"] = orig_bytes + reply_bytes

    _derive_nat(row)
    return row


# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------

_PATTERNS = ["conntrackd-stats.log*", "conntrackd*.log*", "conntrack*.log*"]


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def is_conntrackd_log(path: Path) -> bool:
    """Return True when the file's first lines look like conntrackd flow records."""
    try:
        with _open_log(path) as fh:
            for index, line in enumerate(fh):
                if not line.strip():
                    continue
                match = _LINE_RE.match(line)
                if match and "src=" in match.group("body"):
                    return True
                if index >= 16:
                    break
    except OSError:
        return False
    return False


def find_log_files(input_path: str) -> list[Path]:
    """Resolve the input path into conntrackd log files."""
    path = Path(input_path)

    if path.is_file():
        return [path]

    if path.is_dir():
        seen: set[Path] = set()
        for pattern in _PATTERNS:
            for match in path.glob(pattern):
                if match.is_file():
                    seen.add(match)
        found = sorted(p for p in seen if is_conntrackd_log(p))
        if not found:
            raise ConverterError(f"No conntrackd log files found in: {input_path}")
        return found

    matches = sorted(p for p in expand_glob(input_path) if p.is_file())
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


def convert_conntrackd(
    input_path: str,
    output: str,
    output_format: str,
    since: str | None = None,
    until: str | None = None,
    assume_tz: str | None = None,
    verbose: bool = True,
    split: str | None = None,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, int]:
    """Convert conntrackd flow logs to a Timesketch timeline."""
    files = find_log_files(input_path)
    tz = parse_tz_offset(assume_tz)

    ui = get_terminal()
    ui.header(
        "conntrackd2timesketch",
        subtitle="Convert conntrackd flow logs → Timesketch timeline",
        badges=[("conntrackd", "accent"), (output_format, "muted")],
    )
    ui.step("Files found", str(len(files)))
    ui.step("Naive timestamps", f"assumed {assume_tz or 'UTC'}")

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("conntrackd2timesketch", command_line or [])
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

    compute_hash = report_path is not None
    writer = OutputWriter(
        output,
        output_format,
        fieldnames=_fieldnames(),
        compute_hash=compute_hash,
        split=split,
    )

    skipped_lines = 0
    nat_rows = 0
    unreplied_rows = 0
    for index, log_file in enumerate(files, start=1):
        ui.step(f"[{index}/{len(files)}]", str(log_file))
        source = str(log_file.resolve())
        try:
            with _open_log(log_file) as fh:
                for raw in fh:
                    line = raw.rstrip("\n").rstrip("\r")
                    if not line.strip():
                        continue
                    row = parse_line(line, source, tz)
                    if row is None:
                        skipped_lines += 1
                        continue
                    if not _filter_by_time(row, since_dt, until_dt):
                        continue
                    if row.get("nat_type"):
                        nat_rows += 1
                    if row.get("unreplied"):
                        unreplied_rows += 1
                    writer.add({k: v for k, v in row.items() if v is not None})
        except OSError as exc:
            raise ConverterError(f"Failed to read {log_file}: {exc}") from exc

    total = writer.write()
    if report:
        add_writer_output(report, writer)

    log(f"{nat_rows} flow(s) show address translation", verbose)

    if report:
        report.set_statistics({
            "rows": total,
            "skipped_lines": skipped_lines,
            "translated_flows": nat_rows,
            "unreplied_flows": unreplied_rows,
            "timezone_assumption": (
                f"conntrackd ctime timestamps carry no offset; assumed {assume_tz or 'UTC'}"
            ),
            "since": since,
            "until": until,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    ui.summary("Result", {
        "Files processed": str(len(files)),
        "Rows": f"{total:,}",
        "Translated flows": f"{nat_rows:,}",
        "Unreplied flows": f"{unreplied_rows:,}",
        "Unparseable lines": f"{skipped_lines:,}",
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
    })

    return {"combined": total}
