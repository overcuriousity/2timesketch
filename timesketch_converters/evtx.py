#!/usr/bin/env python3
"""Windows Event Log (EVTX export) to Timesketch timeline converter.

Parses text exports of Windows event logs — the converter suite is
standard-library only, so binary ``.evtx`` files are not read directly.
Supported inputs:

- XML exports from ``wevtutil qe Security /f:xml`` (concatenated ``<Event>``
  elements without a document root) or ``evtx_dump --format xml`` (with
  ``Record NNN`` separators and per-record XML declarations).
- JSONL exports from ``evtx_dump -o jsonl`` (one ``{"Event": {...}}`` object
  per line, with ``#attributes``/``#text`` wrappers).

Well-known security-relevant event IDs (logons, process creation, service
installs, account management, log clearing, PowerShell script blocks) are
mapped onto the ``winevtx:<category>:<event>`` data_type taxonomy; every
other event falls back to ``winevtx:event:<event_id>`` so the ID stays
searchable. EventData values are promoted onto columns under their native
names (``TargetUserName``, ``LogonType``, ...), with ``IpAddress``/``IpPort``
additionally mapped onto the shared ``src_ip``/``src_port`` columns and
``Computer`` onto ``host``.
"""

from __future__ import annotations

import datetime
import gzip
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterator

from .common import (
    AuditReport,
    ConverterError,
    OutputWriter,
    add_writer_output,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal

_EVTX_MAGIC = b"ElfFile\x00"

# event_id -> (data_type, timestamp_desc, message template). Templates are
# rendered with str.format_map over the row; missing keys render as "".
_EVENT_MAP: dict[int, tuple[str, str, str]] = {
    4624: (
        "winevtx:logon:success",
        "Logon Time",
        "Logon success: {TargetDomainName}\\{TargetUserName} from {IpAddress} (LogonType {LogonType})",
    ),
    4625: (
        "winevtx:logon:failure",
        "Logon Failure Time",
        "Logon failure: {TargetDomainName}\\{TargetUserName} from {IpAddress} (LogonType {LogonType}, Status {Status})",
    ),
    4634: ("winevtx:logon:logoff", "Logoff Time", "Logoff: {TargetDomainName}\\{TargetUserName}"),
    4647: ("winevtx:logon:logoff", "Logoff Time", "User-initiated logoff: {TargetDomainName}\\{TargetUserName}"),
    4648: (
        "winevtx:logon:explicit_credentials",
        "Explicit Credential Logon Time",
        "Logon with explicit credentials: {SubjectUserName} as {TargetUserName} to {TargetServerName}",
    ),
    4672: (
        "winevtx:logon:special_privileges",
        "Special Privileges Assigned Time",
        "Special privileges assigned to {SubjectDomainName}\\{SubjectUserName}",
    ),
    4776: (
        "winevtx:logon:credential_validation",
        "Credential Validation Time",
        "Credential validation for {TargetUserName} from {Workstation}",
    ),
    4688: (
        "winevtx:process:create",
        "Process Creation Time",
        "Process created: {NewProcessName} ({CommandLine})",
    ),
    4689: ("winevtx:process:exit", "Process Exit Time", "Process exited: {ProcessName}"),
    7045: (
        "winevtx:service:installed",
        "Service Install Time",
        "Service installed: {ServiceName} ({ImagePath})",
    ),
    7036: (
        "winevtx:service:state_change",
        "Service State Change Time",
        "Service state change: {param1} {param2}",
    ),
    4720: ("winevtx:account:user_created", "User Created Time", "User account created: {TargetUserName}"),
    4722: ("winevtx:account:user_enabled", "User Enabled Time", "User account enabled: {TargetUserName}"),
    4723: (
        "winevtx:account:password_change",
        "Password Change Time",
        "Password change attempted for {TargetUserName}",
    ),
    4724: (
        "winevtx:account:password_reset",
        "Password Reset Time",
        "Password reset attempted for {TargetUserName} by {SubjectUserName}",
    ),
    4725: ("winevtx:account:user_disabled", "User Disabled Time", "User account disabled: {TargetUserName}"),
    4726: ("winevtx:account:user_deleted", "User Deleted Time", "User account deleted: {TargetUserName}"),
    4728: (
        "winevtx:account:group_member_added",
        "Group Member Added Time",
        "Member {MemberName} added to global group {TargetUserName}",
    ),
    4732: (
        "winevtx:account:group_member_added",
        "Group Member Added Time",
        "Member {MemberName} added to local group {TargetUserName}",
    ),
    4756: (
        "winevtx:account:group_member_added",
        "Group Member Added Time",
        "Member {MemberName} added to universal group {TargetUserName}",
    ),
    4740: ("winevtx:account:lockout", "Account Lockout Time", "Account locked out: {TargetUserName}"),
    4698: ("winevtx:task:created", "Scheduled Task Created Time", "Scheduled task created: {TaskName}"),
    4702: ("winevtx:task:updated", "Scheduled Task Updated Time", "Scheduled task updated: {TaskName}"),
    1102: ("winevtx:log:cleared", "Log Cleared Time", "Audit log cleared on {computer}"),
    4104: (
        "winevtx:powershell:script_block",
        "PowerShell Script Block Time",
        "PowerShell script block executed on {computer}",
    ),
}

# System-level keys promoted onto explicit row columns; EventData keys keep
# their native names alongside them.
_XML_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class EvtxParseError(ConverterError):
    """Raised when an EVTX export record cannot be parsed."""


class _Defaulting(dict):
    """format_map helper that renders missing template keys as ''."""

    def __missing__(self, key: str) -> str:
        return ""


def _local(tag: str) -> str:
    """Strip an XML namespace prefix from a tag name."""
    return tag.rsplit("}", 1)[-1]


def _safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _parse_system_time(ts: str) -> datetime.datetime | None:
    """Parse a TimeCreated SystemTime value into a UTC-aware datetime.

    Windows emits 7-digit fractional seconds, which fromisoformat rejects on
    some Python versions; the fraction is trimmed to microseconds first.
    """
    if not ts:
        return None
    value = re.sub(r"(\.\d{6})\d+", r"\1", ts.strip()).replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _build_row(
    system: dict[str, Any],
    event_data: dict[str, Any],
    rendered_message: str | None,
    source_file: str,
) -> dict[str, Any]:
    """Assemble a Timesketch row from parsed System and EventData fields."""
    event_id = _safe_int(system.get("EventID"))
    if event_id is None:
        raise EvtxParseError("record missing EventID")

    ts_str = system.get("SystemTime", "")
    dt = _parse_system_time(str(ts_str))
    if dt is None:
        raise EvtxParseError(f"unrecognised SystemTime: {ts_str!r}")
    ts_us = to_unix_microseconds(dt)

    computer = system.get("Computer", "")
    src_ip = normalize_ip(str(event_data.get("IpAddress", "")))
    src_port = _safe_int(event_data.get("IpPort"))

    mapped = _EVENT_MAP.get(event_id)
    if mapped:
        data_type, timestamp_desc, template = mapped
    else:
        data_type = f"winevtx:event:{event_id}"
        timestamp_desc = "Event Logged Time"
        template = ""

    row: dict[str, Any] = {
        "datetime": to_iso8601(ts_us, unit="us"),
        "timestamp_desc": timestamp_desc,
        "message": "",
        "data_type": data_type,
        "timestamp": ts_us,
        "source": source_file,
        "src_ip": src_ip,
        "event_id": event_id,
        "provider": system.get("Provider", ""),
        "channel": system.get("Channel", ""),
        "computer": computer,
        "host": computer,
        "record_number": _safe_int(system.get("EventRecordID")),
        "level": _safe_int(system.get("Level")),
        "task": _safe_int(system.get("Task")),
        "opcode": _safe_int(system.get("Opcode")),
        "process_id": _safe_int(system.get("ProcessID")),
        "thread_id": _safe_int(system.get("ThreadID")),
        "user_sid": system.get("UserID", ""),
        "qualifiers": _safe_int(system.get("Qualifiers")),
    }
    if src_port is not None:
        row["src_port"] = src_port

    for key, value in event_data.items():
        if key not in row and value is not None and value != "":
            row[key] = value

    if rendered_message:
        row["message"] = " ".join(rendered_message.split())
    elif template:
        context = _Defaulting(computer=computer)
        context.update({k: v for k, v in event_data.items() if v is not None})
        row["message"] = template.format_map(context).strip()
    if not row["message"]:
        provider = row["provider"] or "unknown provider"
        row["message"] = f"EventID {event_id} ({provider}) on {computer}"

    # Drop empty optional columns but keep the shared timeline columns.
    keep = {"datetime", "timestamp_desc", "message", "data_type", "timestamp", "source", "src_ip"}
    return {k: v for k, v in row.items() if k in keep or (v is not None and v != "")}


# ---------------------------------------------------------------------------
# XML input
# ---------------------------------------------------------------------------

def _iter_xml_events(fh: Any) -> Iterator[str]:
    """Yield raw <Event>...</Event> chunks from a wevtutil/evtx_dump export.

    Both tools emit event elements without a common document root (evtx_dump
    additionally interleaves "Record NNN" separators and per-record XML
    declarations), so events are scanned line-wise instead of parsed as one
    document. Memory use is bounded by the largest single event.
    """
    buffer: list[str] = []
    collecting = False
    for line in fh:
        if not collecting:
            idx = line.find("<Event")
            if idx == -1:
                continue
            collecting = True
            line = line[idx:]
        buffer.append(line)
        if "</Event>" in line:
            yield "".join(buffer)
            buffer = []
            collecting = False
    if buffer:
        raise EvtxParseError("truncated <Event> element at end of input")


def _parse_xml_event(chunk: str) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    """Parse one <Event> XML chunk into (system, event_data, rendered_message)."""
    try:
        root = ET.fromstring(chunk)
    except ET.ParseError as exc:
        raise EvtxParseError(f"invalid event XML: {exc}") from exc

    system: dict[str, Any] = {}
    event_data: dict[str, Any] = {}
    rendered_message: str | None = None

    for child in root:
        name = _local(child.tag)
        if name == "System":
            for elem in child:
                tag = _local(elem.tag)
                if tag == "Provider":
                    system["Provider"] = elem.get("Name", "")
                elif tag == "TimeCreated":
                    system["SystemTime"] = elem.get("SystemTime", "")
                elif tag == "Execution":
                    system["ProcessID"] = elem.get("ProcessID")
                    system["ThreadID"] = elem.get("ThreadID")
                elif tag == "Security":
                    system["UserID"] = elem.get("UserID", "")
                elif tag == "EventID":
                    system["EventID"] = elem.text
                    if elem.get("Qualifiers"):
                        system["Qualifiers"] = elem.get("Qualifiers")
                else:
                    system[tag] = elem.text
        elif name == "EventData":
            unnamed = 0
            for data in child:
                if _local(data.tag) != "Data":
                    continue
                key = data.get("Name")
                if not key:
                    key = f"data_{unnamed}"
                    unnamed += 1
                event_data[key] = data.text
        elif name == "UserData":
            for container in child:
                for elem in container:
                    event_data[_local(elem.tag)] = elem.text
        elif name == "RenderingInfo":
            for elem in child:
                if _local(elem.tag) == "Message" and elem.text:
                    rendered_message = elem.text

    return system, event_data, rendered_message


# ---------------------------------------------------------------------------
# JSONL input
# ---------------------------------------------------------------------------

def _text_or_value(value: Any) -> Any:
    """Unwrap evtx_dump's {"#text": ..., "#attributes": {...}} wrappers."""
    if isinstance(value, dict):
        if "#text" in value:
            return value["#text"]
        return value
    return value


def _flatten_data(prefix: str, value: Any, out: dict[str, Any]) -> None:
    """Flatten nested EventData/UserData values onto dot-joined columns."""
    value = _text_or_value(value)
    if isinstance(value, dict):
        for sub_key, sub_value in value.items():
            if sub_key == "#attributes":
                continue
            name = f"{prefix}.{sub_key}" if prefix else sub_key
            _flatten_data(name, sub_value, out)
    elif isinstance(value, list):
        out[prefix] = ",".join(str(_text_or_value(v)) for v in value)
    elif value is not None:
        out[prefix] = value


def _parse_jsonl_record(line: str) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    """Parse one evtx_dump JSONL record into (system, event_data, message)."""
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise EvtxParseError(f"invalid JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise EvtxParseError("JSON line is not an object")

    event = record.get("Event", record)
    if not isinstance(event, dict):
        raise EvtxParseError("record has no Event object")

    raw_system = event.get("System")
    if not isinstance(raw_system, dict):
        raise EvtxParseError("record has no System block")

    system: dict[str, Any] = {}
    for key, value in raw_system.items():
        if key == "#attributes":
            continue
        if key == "Provider":
            attrs = value.get("#attributes", {}) if isinstance(value, dict) else {}
            system["Provider"] = attrs.get("Name", "")
        elif key == "TimeCreated":
            attrs = value.get("#attributes", {}) if isinstance(value, dict) else {}
            system["SystemTime"] = attrs.get("SystemTime", "")
        elif key == "Execution":
            attrs = value.get("#attributes", {}) if isinstance(value, dict) else {}
            system["ProcessID"] = attrs.get("ProcessID")
            system["ThreadID"] = attrs.get("ThreadID")
        elif key == "Security":
            attrs = value.get("#attributes", {}) if isinstance(value, dict) else {}
            system["UserID"] = attrs.get("UserID", "")
        elif key == "EventID":
            if isinstance(value, dict):
                system["EventID"] = value.get("#text")
                attrs = value.get("#attributes", {})
                if attrs.get("Qualifiers") is not None:
                    system["Qualifiers"] = attrs.get("Qualifiers")
            else:
                system["EventID"] = value
        else:
            system[key] = _text_or_value(value)

    event_data: dict[str, Any] = {}
    for block in ("EventData", "UserData"):
        raw = event.get(block)
        if isinstance(raw, dict):
            for key, value in raw.items():
                if key == "#attributes":
                    continue
                _flatten_data(key, value, event_data)

    rendered = event.get("RenderingInfo")
    rendered_message: str | None = None
    if isinstance(rendered, dict):
        msg = _text_or_value(rendered.get("Message"))
        if isinstance(msg, str) and msg.strip():
            rendered_message = msg

    return system, event_data, rendered_message


# ---------------------------------------------------------------------------
# File handling
# ---------------------------------------------------------------------------

def _open_export(path: Path) -> Any:
    """Open an export file, handling gzip and UTF-16 encodings."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    with open(path, "rb") as probe:
        head = probe.read(4)
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return open(path, "r", encoding="utf-16", errors="replace")
    return open(path, "r", encoding="utf-8-sig", errors="replace")


def _detect_input_format(path: Path) -> str:
    """Detect whether an export file is XML or JSONL."""
    if path.suffix != ".gz":
        with open(path, "rb") as fh:
            head = fh.read(len(_EVTX_MAGIC))
        if head == _EVTX_MAGIC:
            raise ConverterError(
                f"{path} is a binary .evtx file, which this stdlib-only "
                "converter cannot read. Export it first, e.g. "
                "'wevtutil qe Security /f:xml > security.xml' on Windows or "
                "'evtx_dump -o jsonl -f security.jsonl Security.evtx' "
                "(https://github.com/omerbenamram/evtx) anywhere."
            )
    with _open_export(path) as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("{"):
                return "jsonl"
            if stripped.startswith("<"):
                return "xml"
            # evtx_dump XML mode interleaves "Record NNN" separators.
            if stripped.startswith("Record "):
                return "xml"
            break
    raise ConverterError(
        f"Could not determine input format for: {path} "
        "(expected an XML or JSONL event log export)"
    )


def _find_export_files(input_path: str) -> list[Path]:
    """Resolve the input path into a list of export files."""
    path = Path(input_path)

    if path.is_file():
        return [path]

    if path.is_dir():
        files: set[Path] = set()
        for pattern in ("*.xml", "*.jsonl", "*.json", "*.xml.gz", "*.jsonl.gz", "*.json.gz"):
            files.update(p for p in path.rglob(pattern) if p.is_file())
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


def _iter_raw_records(path: Path, input_format: str) -> Iterator[tuple[str, str]]:
    """Yield (format, raw_record) pairs from one export file.

    Raw records are unparsed XML chunks or JSONL lines, so a parse failure in
    one record does not abort the rest of the file.
    """
    fmt = input_format
    if fmt == "auto":
        fmt = _detect_input_format(path)
    with _open_export(path) as fh:
        if fmt == "xml":
            for chunk in _iter_xml_events(fh):
                yield "xml", chunk
        else:
            for line in fh:
                if not line.strip():
                    continue
                yield "jsonl", line


def convert_evtx(
    input_path: str,
    output: str,
    output_format: str,
    input_format: str = "auto",
    since: str | None = None,
    until: str | None = None,
    event_ids: set[int] | None = None,
    verbose: bool = True,
    split: str | None = None,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, Any]:
    """Convert Windows event log exports to a Timesketch timeline.

    Args:
        split: Optional split size for the output (e.g. ``"4"`` or ``"4M"``).

    Returns:
        Statistics dict with ``rows_written``, ``files_processed``,
        ``parse_errors``, ``rows_skipped_by_time``,
        ``rows_skipped_by_event_id``, and ``rows_by_event_id``.
    """
    files = _find_export_files(input_path)
    if not files:
        raise ConverterError(f"No event log export files found in: {input_path}")

    ui = get_terminal()
    ui.header(
        "evtx2timesketch",
        subtitle="Convert Windows event log exports → Timesketch timeline",
        badges=[("winevtx", "accent"), (output_format, "muted")],
    )
    ui.step("Files found", f"{len(files)} export file(s)")

    since_dt = _parse_since_until(since)
    until_dt = _parse_since_until(until)

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("evtx2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)

    writer = OutputWriter(output, output_format, compute_hash=report_path is not None, split=split)
    rows_written = 0
    files_processed = 0
    parse_errors = 0
    skipped_by_time = 0
    skipped_by_event_id = 0
    event_id_counts: dict[int, int] = {}
    _parse_error_samples: list[str] = []

    for idx, export_file in enumerate(files, start=1):
        ui.progress(idx, len(files), label=str(export_file))
        source_str = str(export_file.resolve())

        try:
            for record_fmt, raw in _iter_raw_records(export_file, input_format):
                try:
                    if record_fmt == "xml":
                        system, event_data, rendered_message = _parse_xml_event(raw)
                    else:
                        system, event_data, rendered_message = _parse_jsonl_record(raw)
                    row = _build_row(system, event_data, rendered_message, source_str)
                except EvtxParseError as exc:
                    parse_errors += 1
                    if len(_parse_error_samples) < 3:
                        _parse_error_samples.append(f"{export_file}: {exc}")
                    continue

                event_id = row["event_id"]
                if event_ids is not None and event_id not in event_ids:
                    skipped_by_event_id += 1
                    continue

                ts = row.get("timestamp", 0)
                if since_dt and ts and ts < to_unix_microseconds(since_dt):
                    skipped_by_time += 1
                    continue
                if until_dt and ts and ts > to_unix_microseconds(until_dt):
                    skipped_by_time += 1
                    continue

                event_id_counts[event_id] = event_id_counts.get(event_id, 0) + 1
                writer.add(row)
                rows_written += 1
        except EvtxParseError as exc:
            parse_errors += 1
            if len(_parse_error_samples) < 3:
                _parse_error_samples.append(f"{export_file}: {exc}")
        except OSError as exc:
            raise ConverterError(f"Failed to read {export_file}: {exc}") from exc

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
            "rows_skipped_by_event_id": skipped_by_event_id,
            "rows_by_event_id": {str(k): v for k, v in event_id_counts.items()},
            "since": since,
            "until": until,
            "event_ids": sorted(event_ids) if event_ids else None,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    summary_items: dict[str, Any] = {
        "Rows written": f"{written:,}",
        "Files processed": f"{files_processed}/{len(files)}",
        "Parse errors": f"{parse_errors:,}",
        "Skipped by time": f"{skipped_by_time:,}",
        "Skipped by event ID": f"{skipped_by_event_id:,}",
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
    }
    top_events = sorted(event_id_counts.items(), key=lambda kv: -kv[1])[:10]
    for event_id, count in top_events:
        summary_items[f"EventID {event_id}"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return {
        "rows_written": written,
        "files_processed": files_processed,
        "parse_errors": parse_errors,
        "rows_skipped_by_time": skipped_by_time,
        "rows_skipped_by_event_id": skipped_by_event_id,
        "rows_by_event_id": event_id_counts,
    }
