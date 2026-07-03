#!/usr/bin/env python3
"""AWS CloudTrail to Timesketch timeline converter.

Turns AWS CloudTrail log archives into Timesketch-compatible CSV/JSONL
timelines. Supports the standard CloudTrail S3 delivery layout: gzipped or
plain JSON files containing a top-level ``Records`` array. Nested objects
(``userIdentity``, ``requestParameters``, ``responseElements``, etc.) are
flattened into dot-notation columns.
"""

from __future__ import annotations

import datetime
import gzip
import json
from pathlib import Path
from typing import Any

from .common import (
    AuditReport,
    ConverterError,
    OutputWriter,
    log,
    normalize_ip,
    to_iso8601,
)
from .terminal import get_terminal

# Top-level scalar fields to promote directly into the row.
_TOP_LEVEL_FIELDS = (
    "eventVersion",
    "eventTime",
    "eventSource",
    "eventName",
    "awsRegion",
    "eventType",
    "readOnly",
    "managementEvent",
    "recipientAccountId",
    "requestID",
    "eventID",
    "errorCode",
    "errorMessage",
    "sharedEventID",
    "vpcEndpointId",
    "vpcEndpointAccountId",
)

# Nested objects that should be flattened with dot notation.
_FLATTEN_FIELDS = (
    "userIdentity",
    "requestParameters",
    "responseElements",
    "additionalEventData",
    "serviceEventDetails",
    "tlsDetails",
)

class CloudTrailParseError(ConverterError):
    """Raised when a CloudTrail file cannot be parsed."""


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Recursively flatten a nested dict into dot-notation keys.

    Lists and scalars are kept as-is under their dotted key.
    """
    result: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_key = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                result.update(_flatten(value, new_key))
            else:
                result[new_key] = value
    else:
        result[prefix] = obj
    return result


def _serialize(value: Any) -> str:
    """Serialize a non-scalar value to a compact JSON string."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _parse_event_time(value: str | None) -> int:
    """Parse a CloudTrail ISO 8601 timestamp to Unix microseconds.

    Returns 0 if the value is missing or unparseable.
    """
    if not value:
        return 0
    ts = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp() * 1_000_000)
    except ValueError:
        return 0


def _format_user(record: dict[str, Any]) -> str:
    """Return a concise user identity string for the message column."""
    user = record.get("userIdentity") or {}
    user_type = user.get("type", "Unknown")

    if user_type == "IAMUser":
        return user.get("userName") or user.get("arn") or user_type
    if user_type == "AssumedRole":
        session = user.get("sessionContext", {}).get("sessionIssuer", {})
        role = session.get("userName") or session.get("arn") or ""
        principal = user.get("principalId", "")
        if role:
            return f"{role} ({principal})" if principal else role
        return user.get("arn") or user_type
    if user_type == "AWSService":
        invoked = user.get("invokedBy") or ""
        return f"{user_type} ({invoked})" if invoked else user_type
    if user_type == "Root":
        return user.get("arn") or "Root"
    if user_type == "Federated":
        return user.get("principalId") or user_type

    return user.get("arn") or user.get("principalId") or user_type


def _build_message(record: dict[str, Any]) -> str:
    """Build a human-readable summary of a CloudTrail record."""
    event_type = record.get("eventType", "AwsApiCall")
    event_source = record.get("eventSource", "")
    event_name = record.get("eventName", "Unknown")
    user_str = _format_user(record)
    region = record.get("awsRegion", "")

    if event_source:
        action = f"{event_source}:{event_name}"
    else:
        action = event_name

    parts = [f"{event_type}: {action} by {user_str}"]
    if region:
        parts.append(f"in {region}")

    error_code = record.get("errorCode")
    if error_code:
        parts.append(f"[{error_code}]")

    return " ".join(parts)


def _build_row(record: dict[str, Any], source_file: str) -> dict[str, Any] | None:
    """Map a single CloudTrail record to a Timesketch row."""
    event_time = record.get("eventTime")
    timestamp_us = _parse_event_time(event_time)

    event_category = record.get("eventCategory", "unknown")
    data_type = f"cloudtrail:{str(event_category).lower()}:event"

    row: dict[str, Any] = {
        "timestamp": timestamp_us,
        "datetime": to_iso8601(timestamp_us, unit="us"),
        "timestamp_desc": "CloudTrail Event Time",
        "message": _build_message(record),
        "data_type": data_type,
        "source": source_file,
    }

    for field in _TOP_LEVEL_FIELDS:
        if field in record:
            row[field] = record[field]

    for field in _FLATTEN_FIELDS:
        value = record.get(field)
        if isinstance(value, dict):
            row.update(_flatten(value, field))

    resources = record.get("resources")
    if resources is not None:
        row["resources"] = _serialize(resources)

    # Promote sourceIPAddress and userAgent at the top level if present.
    # sourceIPAddress is not always a literal IP - AWS service principals
    # (e.g. "config.amazonaws.com") populate it with a DNS name instead, so
    # src_ip is only set when it validates as a real address.
    source_ip = record.get("sourceIPAddress")
    if source_ip is not None:
        row["sourceIPAddress"] = source_ip
        row["src_ip"] = normalize_ip(source_ip)
    # userAgent is kept verbatim (matching sourceIPAddress above) and also
    # exposed as the suite-wide "user_agent" column for cross-source queries.
    user_agent = record.get("userAgent")
    if user_agent is not None:
        row["userAgent"] = user_agent
        row["user_agent"] = user_agent

    return row


def _find_cloudtrail_files(input_path: str) -> list[Path]:
    """Resolve the input path into a list of CloudTrail JSON files."""
    path = Path(input_path)

    if path.is_file():
        if path.suffix in (".json", ".gz"):
            return [path]
        raise ConverterError(f"Unsupported file extension: {path}")

    if path.is_dir():
        files: list[Path] = []
        for ext in ("*.json.gz", "*.json"):
            files.extend(path.rglob(ext))
        # Exclude CloudTrail digest files; they have a different schema.
        files = [f for f in files if "CloudTrail-Digest" not in f.name]
        return sorted(set(files))

    raise ConverterError(f"Input path not found: {input_path}")


def _read_json_file(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Read a CloudTrail JSON file and return its Records plus parse-error count."""
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        raise CloudTrailParseError(f"Cannot parse {path}: {exc}") from exc

    if isinstance(data, dict) and "Records" in data:
        return data["Records"], 0

    if isinstance(data, list):
        return data, 0

    raise CloudTrailParseError(f"No Records array found in {path}")


def convert_cloudtrail(
    input_path: str,
    output: str,
    output_format: str,
    since: str | None = None,
    until: str | None = None,
    verbose: bool = True,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, Any]:
    """Convert AWS CloudTrail logs to a Timesketch timeline.

    Returns:
        Statistics dict with ``rows_written``, ``files_processed``,
        ``parse_errors``, and ``records_skipped_by_time``.
    """
    files = _find_cloudtrail_files(input_path)
    if not files:
        raise ConverterError(f"No CloudTrail JSON files found in: {input_path}")

    ui = get_terminal()
    ui.header(
        "cloudtrail2timesketch",
        subtitle="Convert AWS CloudTrail logs → Timesketch timeline",
        badges=[("cloudtrail", "info"), (output_format, "muted")],
    )
    ui.step("Files found", f"{len(files)} CloudTrail JSON file(s)")

    since_us = _parse_event_time(since) if since else 0
    until_us = _parse_event_time(until) if until else 0

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("cloudtrail2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)

    writer = OutputWriter(output, output_format, compute_hash=report_path is not None)
    rows_written = 0
    files_processed = 0
    parse_errors = 0
    skipped_by_time = 0

    for idx, file_path in enumerate(files, start=1):
        ui.progress(idx, len(files), label=str(file_path))
        try:
            records, err_count = _read_json_file(file_path)
        except CloudTrailParseError as exc:
            parse_errors += 1
            ui.warning(str(exc))
            continue

        parse_errors += err_count
        files_processed += 1
        source_str = str(file_path.resolve())

        for record in records:
            row = _build_row(record, source_str)
            if row is None:
                continue

            ts = row.get("timestamp", 0)
            if since_us and ts and ts < since_us:
                skipped_by_time += 1
                continue
            if until_us and ts and ts > until_us:
                skipped_by_time += 1
                continue

            writer.add(row)
            rows_written += 1

    ui.end_progress()
    written = writer.write()

    if report:
        if output == "-":
            report.add_stdout_output(writer.content_hash)
        else:
            report.add_output_file(output, writer.content_hash)
        stats = {
            "rows_written": written,
            "files_processed": files_processed,
            "parse_errors": parse_errors,
            "records_skipped_by_time": skipped_by_time,
            "since": since,
            "until": until,
        }
        report.set_statistics(stats)
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    ui.summary(
        "Result",
        {
            "Rows written": f"{written:,}",
            "Files processed": f"{files_processed}/{len(files)}",
            "Parse errors": f"{parse_errors:,}",
            "Skipped by time": f"{skipped_by_time:,}",
            "Output": output if output != "-" else "stdout",
            "Format": output_format,
        },
    )

    return {
        "rows_written": written,
        "files_processed": files_processed,
        "parse_errors": parse_errors,
        "records_skipped_by_time": skipped_by_time,
    }
