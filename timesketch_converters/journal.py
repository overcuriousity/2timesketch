#!/usr/bin/env python3
"""systemd journal to Timesketch timeline converter."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from .common import (
    AuditReport,
    ConverterError,
    OutputWriter,
    add_writer_output,
    first_ip,
    log,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal

TIMESKETCH_REQUIRED = ["datetime", "timestamp_desc", "message"]

PRIORITY_MAP = {
    "0": "emerg",
    "1": "alert",
    "2": "crit",
    "3": "err",
    "4": "warning",
    "5": "notice",
    "6": "info",
    "7": "debug",
}

EXTRA_FIELDS = [
    "_HOSTNAME",
    "_COMM",
    "_PID",
    "_UID",
    "_GID",
    "SYSLOG_IDENTIFIER",
    "_SYSTEMD_UNIT",
    "_SYSTEMD_SLICE",
    "_TRANSPORT",
    "_KERNEL_SUBSYSTEM",
    "UNIT",
    "CODE_FILE",
    "CODE_FUNC",
]


def build_journalctl_cmd(
    journal_dir: str,
    since: str | None,
    until: str | None,
    boot: str | None,
) -> list[str]:
    """Build the journalctl command used to stream JSON entries."""
    cmd = [
        "journalctl",
        "-D", journal_dir,
        "-o", "json",
        "--no-pager",
        "--utc",
    ]
    if since:
        cmd += ["--since", since]
    if until:
        cmd += ["--until", until]
    if boot is not None:
        cmd += ["-b", boot]
    return cmd


def _coerce(value: Any) -> Any:
    """Convert list values to space-separated strings, pass others through."""
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    return value


def build_message(entry: dict[str, Any]) -> str:
    """Build a human-readable message from a journal entry."""
    parts: list[str] = []
    ident = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM")
    if ident:
        pid = entry.get("_PID", "")
        parts.append(f"{ident}[{pid}]:" if pid else f"{ident}:")

    raw_msg = entry.get("MESSAGE") or ""
    if isinstance(raw_msg, list):
        raw_msg = " ".join(str(b) for b in raw_msg)
    parts.append(str(raw_msg))
    return " ".join(parts)


def build_row(entry: dict[str, Any], source: str) -> dict[str, Any]:
    """Map a single journalctl JSON entry to a Timesketch row."""
    row: dict[str, Any] = {}

    realtime_us = entry.get("__REALTIME_TIMESTAMP")
    if realtime_us:
        row["datetime"] = to_iso8601(realtime_us, unit="us")
        row["timestamp"] = int(realtime_us)
    else:
        row["datetime"] = ""
        row["timestamp"] = ""

    row["timestamp_desc"] = "Journal Entry"
    row["data_type"] = "journal:entry:log"
    row["source"] = source

    priority_num = entry.get("PRIORITY", "")
    row["priority"] = PRIORITY_MAP.get(str(priority_num), str(priority_num))
    row["priority_num"] = priority_num

    row["message"] = build_message(entry)

    for field in EXTRA_FIELDS:
        key = field.lstrip("_").lower()
        row[key] = _coerce(entry.get(field, ""))

    row["boot_id"] = entry.get("_BOOT_ID", "")
    row["cursor"] = entry.get("__CURSOR", "")
    # Journal messages have no dst concept; a literal IP found in free text
    # (e.g. "Failed password for root from 1.2.3.4 port 22") is the remote
    # peer connecting to this host, i.e. the source of the event.
    row["src_ip"] = first_ip(row["message"])

    return row


def fieldnames() -> list[str]:
    """Return the fixed CSV column order for journal output."""
    cols = list(TIMESKETCH_REQUIRED)
    cols += ["data_type", "timestamp", "source", "src_ip"]
    cols += ["priority", "priority_num"]
    cols += [f.lstrip("_").lower() for f in EXTRA_FIELDS]
    cols += ["boot_id", "cursor"]
    return cols


def convert_journal(
    journal_dir: str,
    output: str,
    output_format: str,
    since: str | None = None,
    until: str | None = None,
    boot: str | None = None,
    verbose: bool = True,
    split: str | None = None,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> tuple[int, int]:
    """Convert a systemd journal directory to a Timesketch timeline.

    Returns:
        Tuple of (number of rows written, number of JSON parse errors).
    """
    journal_path = Path(journal_dir)
    if not journal_path.exists():
        raise ConverterError(f"Journal directory not found: {journal_dir}")
    if not journal_path.is_dir():
        raise ConverterError(f"Input is not a directory: {journal_dir}")

    ui = get_terminal()
    ui.header(
        "journal2timesketch",
        subtitle="Convert systemd journal → Timesketch timeline",
        badges=[("journal", "accent"), (output_format, "muted")],
    )

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("journal2timesketch", command_line or [])
        report.add_input_path(journal_path)

    cmd = build_journalctl_cmd(journal_dir, since, until, boot)
    ui.step("Command", " ".join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise ConverterError("journalctl not found. Install systemd.") from exc

    writer = OutputWriter(
        output, output_format, fieldnames=fieldnames(), compute_hash=report_path is not None,
        split=split,
    )
    count = 0
    errors = 0

    with ui.spinner("Streaming journal entries…"):
        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                errors += 1
                continue
            writer.add(build_row(entry, str(journal_path.resolve())))
            count += 1

    proc.wait()
    stderr_output = proc.stderr.read()  # type: ignore[union-attr]

    written = writer.write()

    if proc.returncode not in (0, 1):  # 1 = no entries found, not fatal
        raise ConverterError(
            f"journalctl exited with code {proc.returncode}\n{stderr_output}"
        )

    if report:
        add_writer_output(report, writer)
        report.set_statistics({
            "rows_written": written,
            "json_parse_errors": errors,
            "journalctl_exit_code": proc.returncode,
            "since": since,
            "until": until,
            "boot": boot,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    ui.summary(
        "Result",
        {
            "Rows written": f"{written:,}",
            "JSON parse errors": f"{errors:,}",
            "Output": output if output != "-" else "stdout",
            "Format": output_format,
        },
    )
    return written, errors


