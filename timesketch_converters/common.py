#!/usr/bin/env python3
"""Shared helpers for the Timesketch converter suite.

This module provides common timestamp handling, IP extraction, output writing,
CLI building blocks, audit-report generation, and exception types used by all
source-specific converters.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import getpass
import hashlib
import io
import ipaddress
import json
import re
import socket
import sys
from pathlib import Path
from typing import Any

TIMESKETCH_REQUIRED = ["datetime", "timestamp_desc", "message"]

# Common columns that every converter emits first, in this order.
#
# src_ip / dst_ip form the suite-wide IP convention. Every converter emits
# these as discrete, single-value columns (never pipe-joined or otherwise
# combined) so that timeseries/graphing tools can filter and aggregate on
# them directly:
#   - src_ip: the IP that originated the event (the client, caller, or
#     connection initiator).
#   - dst_ip: the IP the event was directed at, when the source format
#     identifies a distinct destination (e.g. firewall logs).
# A converter leaves a column empty ("") for a given row when that role
# does not apply or cannot be determined - it never encodes multiple
# addresses into one field. See README.md for the per-source mapping.
COMMON_FIELDS = [
    "datetime",
    "timestamp_desc",
    "message",
    "data_type",
    "timestamp",
    "source",
    "src_ip",
    "dst_ip",
]


class ConverterError(Exception):
    """Base exception for converter failures."""


class ValidationError(ConverterError):
    """Raised when input validation fails."""


class BrowserDetectionError(ConverterError):
    """Raised when a browser type cannot be determined."""


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def to_iso8601(ts: int | float | None, unit: str = "us") -> str:
    """Convert a Unix timestamp to ISO 8601 UTC with millisecond precision.

    Args:
        ts: Unix timestamp. Integer or float.
        unit: Time unit of ``ts``: ``"us"`` (microseconds), ``"ms"``
            (milliseconds), or ``"s"`` (seconds).

    Returns:
        ISO 8601 UTC string such as ``2025-01-01T12:00:00.123Z``.
        Empty string if ``ts`` is None or zero.
    """
    if ts is None or ts == 0:
        return ""

    if unit == "us":
        seconds = int(ts) / 1_000_000
    elif unit == "ms":
        seconds = int(ts) / 1_000
    elif unit == "s":
        seconds = float(ts)
    else:
        raise ValueError(f"Unsupported timestamp unit: {unit}")

    dt = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_unix_microseconds(dt: datetime.datetime) -> int:
    """Return a timezone-aware datetime as Unix microseconds."""
    return int(dt.timestamp() * 1_000_000)


# ---------------------------------------------------------------------------
# IP extraction
# ---------------------------------------------------------------------------

_RE_IPV4_CANDIDATE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6_CANDIDATE = re.compile(r"\[?(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?")


def extract_ips(text: str | None) -> list[str]:
    """Extract validated IPv4/IPv6 addresses from free-form text.

    Returns a deduplicated list in the order of first appearance.
    """
    if not text:
        return []

    seen: dict[str, None] = {}
    for m in _RE_IPV4_CANDIDATE.finditer(text):
        cand = m.group(0)
        try:
            addr = ipaddress.IPv4Address(cand)
            seen.setdefault(str(addr), None)
        except ValueError:
            pass

    for m in _RE_IPV6_CANDIDATE.finditer(text):
        cand = m.group(0).strip("[]")
        try:
            addr = ipaddress.IPv6Address(cand)
            seen.setdefault(str(addr), None)
        except ValueError:
            pass

    return list(seen.keys())


def normalize_ip(value: str | None) -> str:
    """Validate and canonicalize a single IPv4/IPv6 address string.

    Returns the canonical string form (e.g. compressed IPv6), or ``""`` if
    ``value`` is missing or not a valid IP address.
    """
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return ""


def first_ip(text: str | None) -> str:
    """Return the first validated IP address found in free-form text.

    Used by sources with no reliable directionality, where only a single
    best-effort address can be attributed to a src_ip/dst_ip column.
    """
    ips = extract_ips(text)
    return ips[0] if ips else ""


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of a byte string."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Audit report
# ---------------------------------------------------------------------------

class AuditReport:
    """Forensic audit report for a converter run.

    The report captures system context, command-line invocation, cryptographic
    hashes of input and output artefacts, and runtime statistics. It is intended
    to be written to disk and may subsequently be PGP-signed to provide a
    tamper-evident audit trail.
    """

    def __init__(self, tool_name: str, command_line: list[str]):
        self.tool_name = tool_name
        self.command_line = command_line
        self.created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.input_files: list[dict[str, Any]] = []
        self.output_files: list[dict[str, Any]] = []
        self.statistics: dict[str, Any] = {}

    def add_input_path(self, path: str | Path) -> None:
        """Record an input path, hashing files and recursing into directories."""
        p = Path(path)
        if p.is_file():
            self.input_files.append({
                "path": str(p.resolve()),
                "type": "file",
                "sha256": sha256_file(p),
            })
        elif p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file():
                    self.input_files.append({
                        "path": str(child.resolve()),
                        "type": "file",
                        "sha256": sha256_file(child),
                    })
        else:
            self.input_files.append({
                "path": str(p),
                "type": "unknown",
                "sha256": None,
            })

    def add_output_file(self, path: str | Path, sha256: str | None = None) -> None:
        """Record an output file and its SHA-256 hash."""
        p = Path(path)
        self.output_files.append({
            "path": str(p.resolve()) if p.exists() else str(p),
            "type": "file",
            "sha256": sha256,
        })

    def add_stdout_output(self, sha256: str | None = None) -> None:
        """Record that output was written to stdout."""
        self.output_files.append({
            "path": "stdout",
            "type": "stdout",
            "sha256": sha256,
        })

    def set_statistics(self, stats: dict[str, Any]) -> None:
        """Set the runtime statistics block."""
        self.statistics = stats

    def to_dict(self) -> dict[str, Any]:
        """Return the report as a dictionary."""
        from . import __version__

        return {
            "tool": self.tool_name,
            "version": __version__,
            "created_at": self.created_at,
            "hostname": self.hostname,
            "username": self.username,
            "command_line": self.command_line,
            "input_files": self.input_files,
            "output_files": self.output_files,
            "statistics": self.statistics,
        }

    def write(self, path: str | Path) -> None:
        """Write the report as indented JSON."""
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
            fh.write("\n")


# ---------------------------------------------------------------------------
# Output writing
# ---------------------------------------------------------------------------

class OutputWriter:
    """Buffer rows and emit them as CSV or JSONL.

    The writer buffers all rows so that dynamic CSV field ordering (used by
    the browser converter) can be supported alongside fixed field ordering.
    When ``compute_hash`` is enabled, the writer records the SHA-256 digest of
    the serialized output content, which is useful for forensic audit reports
    even when writing to stdout.
    """

    def __init__(
        self,
        output: str,
        fmt: str,
        fieldnames: list[str] | None = None,
        compute_hash: bool = False,
    ):
        """Initialize the writer.

        Args:
            output: Destination path or ``"-"`` for stdout.
            fmt: ``"csv"`` or ``"jsonl"``.
            fieldnames: Fixed CSV column order. If omitted, columns are
                computed from all buffered rows, with :data:`COMMON_FIELDS`
                first.
            compute_hash: If True, compute and store the SHA-256 digest of the
                serialized output content.
        """
        self.output = output
        self.fmt = fmt.lower()
        self.fieldnames = fieldnames
        self.compute_hash = compute_hash
        self.content_hash: str | None = None
        self._rows: list[dict[str, Any]] = []
        self._fh: Any = None
        self._csv_writer: csv.DictWriter | None = None

        if self.fmt not in {"csv", "jsonl"}:
            raise ValueError(f"Unsupported output format: {fmt}")

    def add(self, row: dict[str, Any]) -> None:
        """Add a row to the buffer."""
        self._rows.append(row)

    def _collect_fieldnames(self) -> list[str]:
        all_fields: set[str] = set()
        for row in self._rows:
            all_fields.update(row.keys())

        fieldnames = [f for f in COMMON_FIELDS if f in all_fields]
        remaining = sorted(all_fields - set(COMMON_FIELDS) - set(fieldnames))
        fieldnames.extend(remaining)
        return fieldnames

    def _serialize(self) -> str:
        """Serialize all buffered rows to a string."""
        buf = io.StringIO()
        if self.fmt == "csv":
            fieldnames = self.fieldnames or self._collect_fieldnames()
            writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in self._rows:
                writer.writerow(row)
        else:  # jsonl
            for row in self._rows:
                buf.write(json.dumps(row, ensure_ascii=False) + "\n")
        return buf.getvalue()

    def _open_file(self) -> None:
        if self.output == "-":
            self._fh = sys.stdout
        else:
            out_path = Path(self.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(out_path, "w", newline="", encoding="utf-8")

    def write(self) -> int:
        """Write all buffered rows and return the number of rows written."""
        content = self._serialize()
        if self.compute_hash:
            self.content_hash = sha256_bytes(content.encode("utf-8"))

        self._open_file()
        try:
            self._fh.write(content)
        finally:
            if self._fh is not sys.stdout:
                self._fh.close()

        return len(self._rows)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def add_input_arg(parser: argparse.ArgumentParser, help_text: str) -> None:
    parser.add_argument("-i", "--input", required=True, help=help_text)


def add_output_arg(parser: argparse.ArgumentParser, default: str = "-") -> None:
    parser.add_argument(
        "-o",
        "--output",
        default=default,
        help="Output file path (default: stdout).",
    )


def add_format_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-f",
        "--format",
        choices=["csv", "jsonl"],
        default="csv",
        help="Output format (default: csv).",
    )


def add_report_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--report",
        help="Write a forensic audit report (JSON) to this path. The report "
             "can be PGP-signed afterwards to provide a tamper-evident audit trail.",
    )


def add_verbose_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print progress messages to stderr.",
    )


def log(message: str, verbose: bool = True) -> None:
    """Write a progress message to stderr when verbose mode is enabled."""
    if verbose:
        print(message, file=sys.stderr)
