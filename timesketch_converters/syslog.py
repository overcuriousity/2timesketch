#!/usr/bin/env python3
"""Linux syslog/auth.log to Timesketch timeline converter.

Parses traditional RFC 3164-style plain-text syslog files (``auth.log``,
``secure``, ``syslog``, ``messages``, ``cron.log``, including rotated and
gzip-compressed variants) into Timesketch-compatible timelines. Structured
events are extracted for the forensically relevant programs (sshd, sudo, su,
cron, systemd-logind, and account-management tools); every other line is kept
as a generic ``syslog:generic:message`` row so the timeline stays complete.

BSD-style syslog timestamps omit the year; like the filterlog converter, the
year is taken from ``--year`` (default: current year) and times are treated
as UTC.
"""

from __future__ import annotations

import datetime
import gzip
import re
from pathlib import Path
from typing import Any, Callable

from .common import (
    COMMON_FIELDS,
    AuditReport,
    ConverterError,
    OutputWriter,
    add_writer_output,
    first_ip,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal

# Header formats:
#   BSD (RFC 3164):  "Jul 12 06:25:01 host program[pid]: message"
#   ISO (rsyslog):   "2026-07-12T06:25:01.123456+02:00 host program[pid]: message"
# Both may carry an optional "<PRI>" prefix. The program token may lack a PID
# ("kernel:") and hostnames may contain dots or be IP addresses.
_BSD_HEADER_RE = re.compile(
    r"^(?:<\d+>\s*)?"
    r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"([^\s:\[]+)(?:\[(\d+)\])?:\s?"
    r"(.*)$"
)
_ISO_HEADER_RE = re.compile(
    r"^(?:<\d+>\s*)?"
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(\S+)\s+"
    r"([^\s:\[]+)(?:\[(\d+)\])?:\s?"
    r"(.*)$"
)


class SyslogParseError(ConverterError):
    """Raised when a syslog line cannot be parsed."""


def _safe_int(value: str | None) -> int | None:
    """Return ``value`` as int, or None if it is empty/non-numeric."""
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _parse_timestamp(ts: str, year: int | None) -> datetime.datetime | None:
    """Parse a BSD or ISO syslog timestamp into a UTC-aware datetime.

    rsyslog can be configured to emit sub-microsecond fractional precision,
    which fromisoformat() rejects on Python versions before 3.11; the
    fraction is trimmed to microseconds first, mirroring the same workaround
    in evtx.py for Windows' 7-digit fractional seconds.
    """
    if ts[:1].isdigit():
        value = re.sub(r"(\.\d{6})\d+", r"\1", ts).replace(" ", "T", 1).replace("Z", "+00:00")
        try:
            dt = datetime.datetime.fromisoformat(value)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)

    try:
        dt = datetime.datetime.strptime(ts, "%b %d %H:%M:%S")
    except ValueError:
        return None
    if year is None:
        year = datetime.datetime.now(datetime.timezone.utc).year
    try:
        return dt.replace(year=year, tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def _parse_header(
    line: str, year: int | None
) -> tuple[datetime.datetime, str, str, int | None, str] | None:
    """Split a syslog line into (datetime, hostname, program, pid, message)."""
    match = _BSD_HEADER_RE.match(line) or _ISO_HEADER_RE.match(line)
    if not match:
        return None
    ts_str, hostname, program, pid, msg = match.groups()
    dt = _parse_timestamp(ts_str, year)
    if dt is None:
        return None
    return dt, hostname, program, _safe_int(pid), msg


# ---------------------------------------------------------------------------
# Event classifiers
#
# Each handler receives the regex match and returns
# (data_type, timestamp_desc, extra_fields). The classifier table maps a
# normalized program name onto an ordered list of (compiled regex, handler).
# ---------------------------------------------------------------------------

_Handler = Callable[["re.Match[str]"], tuple[str, str, dict[str, Any]]]


def _sshd_accepted(m: re.Match) -> tuple[str, str, dict[str, Any]]:
    fields: dict[str, Any] = {
        "auth_method": m.group("method"),
        "username": m.group("user"),
        "src_ip": normalize_ip(m.group("ip")),
        "src_port": _safe_int(m.group("port")),
    }
    if m.group("fingerprint"):
        fields["key_fingerprint"] = m.group("fingerprint")
    return "syslog:sshd:login_success", "SSH Login Time", fields


def _sshd_failed(m: re.Match) -> tuple[str, str, dict[str, Any]]:
    fields: dict[str, Any] = {
        "auth_method": m.group("method"),
        "username": m.group("user"),
        "src_ip": normalize_ip(m.group("ip")),
        "src_port": _safe_int(m.group("port")),
    }
    if m.group("invalid"):
        fields["invalid_user"] = True
    return "syslog:sshd:login_failed", "SSH Login Failed Time", fields


def _sshd_invalid_user(m: re.Match) -> tuple[str, str, dict[str, Any]]:
    return "syslog:sshd:invalid_user", "SSH Invalid User Time", {
        "username": m.group("user"),
        "src_ip": normalize_ip(m.group("ip")),
        "src_port": _safe_int(m.group("port")),
    }


def _sshd_disconnect(m: re.Match) -> tuple[str, str, dict[str, Any]]:
    fields: dict[str, Any] = {
        "src_ip": normalize_ip(m.group("ip")),
        "src_port": _safe_int(m.group("port")),
    }
    user = m.group("user") or m.group("user2")
    if user:
        fields["username"] = user
    return "syslog:sshd:disconnect", "SSH Disconnect Time", fields


def _pam_session(program: str) -> _Handler:
    def handler(m: re.Match) -> tuple[str, str, dict[str, Any]]:
        state = "opened" if m.group("state") == "opened" else "closed"
        fields: dict[str, Any] = {"username": m.group("user")}
        if m.group("uid"):
            fields["uid"] = _safe_int(m.group("uid"))
        return (
            f"syslog:{program}:session_{state}",
            "Session Opened Time" if state == "opened" else "Session Closed Time",
            fields,
        )

    return handler


def _sudo_command(m: re.Match) -> tuple[str, str, dict[str, Any]]:
    return "syslog:sudo:command", "Sudo Command Time", {
        "username": m.group("user"),
        "tty": m.group("tty"),
        "pwd": m.group("pwd"),
        "target_username": m.group("target"),
        "command": m.group("command"),
    }


def _sudo_auth_failure(m: re.Match) -> tuple[str, str, dict[str, Any]]:
    fields: dict[str, Any] = {}
    if m.group("user"):
        fields["username"] = m.group("user")
    return "syslog:sudo:auth_failure", "Sudo Auth Failure Time", fields


def _su_success(m: re.Match) -> tuple[str, str, dict[str, Any]]:
    return "syslog:su:success", "Su Success Time", {
        "target_username": m.group("target"),
        "username": m.group("user"),
    }


def _su_failed(m: re.Match) -> tuple[str, str, dict[str, Any]]:
    return "syslog:su:failed", "Su Failed Time", {
        "target_username": m.group("target"),
        "username": m.group("user"),
    }


def _cron_command(m: re.Match) -> tuple[str, str, dict[str, Any]]:
    return "syslog:cron:command", "Cron Command Time", {
        "username": m.group("user"),
        "command": m.group("command"),
    }


def _logind_new(m: re.Match) -> tuple[str, str, dict[str, Any]]:
    return "syslog:logind:session_new", "Login Session Start Time", {
        "session_id": m.group("session"),
        "username": m.group("user"),
    }


def _logind_removed(m: re.Match) -> tuple[str, str, dict[str, Any]]:
    return "syslog:logind:session_removed", "Login Session End Time", {
        "session_id": m.group("session"),
    }


def _account_event(event: str, desc: str) -> _Handler:
    def handler(m: re.Match) -> tuple[str, str, dict[str, Any]]:
        fields: dict[str, Any] = {"username": m.group("user")}
        uid = m.groupdict().get("uid")
        if uid:
            fields["uid"] = _safe_int(uid)
        return f"syslog:account:{event}", desc, fields

    return handler


_SSHD_RULES: list[tuple[re.Pattern, _Handler]] = [
    (
        re.compile(
            r"^Accepted (?P<method>[\w-]+) for (?P<user>\S+) from (?P<ip>\S+)"
            r" port (?P<port>\d+)(?: ssh2)?(?::\s*\S+ (?P<fingerprint>SHA256:\S+))?"
        ),
        _sshd_accepted,
    ),
    (
        re.compile(
            r"^Failed (?P<method>[\w-]+) for (?P<invalid>invalid user )?(?P<user>\S+)"
            r" from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        _sshd_failed,
    ),
    (
        re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"),
        _sshd_invalid_user,
    ),
    (
        re.compile(
            r"^(?:Received disconnect from|Disconnected from"
            r"(?: authenticating| invalid)?(?: user (?P<user>\S+))?|"
            r"Connection closed by(?: authenticating| invalid)?(?: user (?P<user2>\S+))?)"
            r"\s*(?P<ip>\S+) port (?P<port>\d+)"
        ),
        _sshd_disconnect,
    ),
    (
        re.compile(
            r"^pam_unix\(sshd:session\): session (?P<state>opened|closed) for user "
            r"(?P<user>[^\s(]+)(?:\(uid=(?P<uid>\d+)\))?"
        ),
        _pam_session("sshd"),
    ),
]

_SUDO_RULES: list[tuple[re.Pattern, _Handler]] = [
    (
        re.compile(
            r"^\s*(?P<user>\S+) : TTY=(?P<tty>\S+) ; PWD=(?P<pwd>[^;]+) ; "
            r"USER=(?P<target>\S+) ; COMMAND=(?P<command>.*)$"
        ),
        _sudo_command,
    ),
    (
        re.compile(r"^\s*(?P<user>\S+) : .*incorrect password attempts?"),
        _sudo_auth_failure,
    ),
    (
        re.compile(
            r"^pam_unix\(sudo:auth\): authentication failure.*?"
            r"(?:user=(?P<user>\S+))?$"
        ),
        _sudo_auth_failure,
    ),
    (
        re.compile(
            r"^pam_unix\(sudo:session\): session (?P<state>opened|closed) for user "
            r"(?P<user>[^\s(]+)(?:\(uid=(?P<uid>\d+)\))?"
        ),
        _pam_session("sudo"),
    ),
]

_SU_RULES: list[tuple[re.Pattern, _Handler]] = [
    (
        re.compile(r"^Successful su for (?P<target>\S+) by (?P<user>\S+)"),
        _su_success,
    ),
    (
        re.compile(r"^\(to (?P<target>[^)]+)\) (?P<user>\S+) on "),
        _su_success,
    ),
    (
        re.compile(r"^FAILED (?:su|SU) (?:for (?P<target>\S+) )?(?:by (?P<user>\S+))?"),
        _su_failed,
    ),
    (
        re.compile(
            r"^pam_unix\(su(?:-l)?:session\): session (?P<state>opened|closed) for user "
            r"(?P<user>[^\s(]+)(?:\(uid=(?P<uid>\d+)\))?"
        ),
        _pam_session("su"),
    ),
]

_CRON_RULES: list[tuple[re.Pattern, _Handler]] = [
    (
        re.compile(r"^\((?P<user>[^)]+)\) CMD \((?P<command>.*)\)\s*$"),
        _cron_command,
    ),
    (
        re.compile(
            r"^pam_unix\(cron(?:d)?:session\): session (?P<state>opened|closed) for user "
            r"(?P<user>[^\s(]+)(?:\(uid=(?P<uid>\d+)\))?"
        ),
        _pam_session("cron"),
    ),
]

_LOGIND_RULES: list[tuple[re.Pattern, _Handler]] = [
    (
        re.compile(r"^New session (?P<session>\S+) of user (?P<user>\S+)\."),
        _logind_new,
    ),
    (
        re.compile(r"^Removed session (?P<session>\S+)\."),
        _logind_removed,
    ),
]

_USERADD_RULES: list[tuple[re.Pattern, _Handler]] = [
    (
        re.compile(r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)"),
        _account_event("user_created", "User Created Time"),
    ),
    (
        re.compile(r"^new group: name=(?P<user>[^,]+)"),
        _account_event("group_created", "Group Created Time"),
    ),
]

_USERDEL_RULES: list[tuple[re.Pattern, _Handler]] = [
    (
        re.compile(r"^delete user '(?P<user>[^']+)'"),
        _account_event("user_deleted", "User Deleted Time"),
    ),
]

_USERMOD_RULES: list[tuple[re.Pattern, _Handler]] = [
    (
        re.compile(r"^change user '(?P<user>[^']+)'"),
        _account_event("user_modified", "User Modified Time"),
    ),
]

_PASSWD_RULES: list[tuple[re.Pattern, _Handler]] = [
    (
        re.compile(r"^pam_unix\(passwd:chauthtok\): password changed for (?P<user>\S+)"),
        _account_event("password_changed", "Password Changed Time"),
    ),
    (
        re.compile(r"^password for '?(?P<user>[^'\s]+)'? changed"),
        _account_event("password_changed", "Password Changed Time"),
    ),
]

# Program name (lowercased, without instance suffixes) -> ordered rule list.
_CLASSIFIERS: dict[str, list[tuple[re.Pattern, _Handler]]] = {
    "sshd": _SSHD_RULES,
    "sudo": _SUDO_RULES,
    "su": _SU_RULES,
    "cron": _CRON_RULES,
    "crond": _CRON_RULES,
    "systemd-logind": _LOGIND_RULES,
    "useradd": _USERADD_RULES,
    "groupadd": _USERADD_RULES,
    "userdel": _USERDEL_RULES,
    "usermod": _USERMOD_RULES,
    "chage": _USERMOD_RULES,
    "passwd": _PASSWD_RULES,
}


def _classify(program: str, msg: str) -> tuple[str, str, dict[str, Any]] | None:
    """Match a message against the program's rules; None when unmatched."""
    rules = _CLASSIFIERS.get(program.lower())
    if not rules:
        return None
    for pattern, handler in rules:
        match = pattern.match(msg)
        if match:
            return handler(match)
    return None


def _parse_line(
    line: str, year: int | None, source_file: str, matched_only: bool
) -> dict[str, Any] | None:
    """Parse a single syslog line into a Timesketch row."""
    parsed = _parse_header(line, year)
    if parsed is None:
        return None
    dt, hostname, program, pid, msg = parsed

    classified = _classify(program, msg)
    if classified is None:
        if matched_only:
            return None
        data_type = "syslog:generic:message"
        timestamp_desc = "Syslog Entry Time"
        extra: dict[str, Any] = {"src_ip": first_ip(msg)}
    else:
        data_type, timestamp_desc, extra = classified

    ts_us = to_unix_microseconds(dt)
    row: dict[str, Any] = {
        "datetime": to_iso8601(ts_us, unit="us"),
        "timestamp_desc": timestamp_desc,
        "message": f"{program}: {msg}" if msg else program,
        "data_type": data_type,
        "timestamp": ts_us,
        "source": source_file,
        "src_ip": "",
        "hostname": hostname,
        "program": program,
        "pid": pid,
    }
    row.update({k: v for k, v in extra.items() if v is not None and v != ""})
    return row


# Fixed CSV column order (syslog has no destination address, so dst_ip is
# omitted like nginx does).
_FIELDNAMES = [f for f in COMMON_FIELDS if f != "dst_ip"] + sorted([
    "auth_method",
    "command",
    "hostname",
    "invalid_user",
    "key_fingerprint",
    "pid",
    "program",
    "pwd",
    "session_id",
    "src_port",
    "target_username",
    "tty",
    "uid",
    "username",
])


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _find_log_files(input_path: str) -> list[Path]:
    """Resolve the input path into a list of syslog files."""
    path = Path(input_path)

    if path.is_file():
        return [path]

    if path.is_dir():
        files: set[Path] = set()
        for pattern in ("auth.log*", "secure*", "syslog*", "messages*", "cron.log*"):
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


def convert_syslog(
    input_path: str,
    output: str,
    output_format: str,
    since: str | None = None,
    until: str | None = None,
    year: int | None = None,
    matched_only: bool = False,
    verbose: bool = True,
    split: str | None = None,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> dict[str, Any]:
    """Convert plain-text syslog/auth.log files to a Timesketch timeline.

    Returns:
        Statistics dict with ``rows_written``, ``files_processed``,
        ``rows_generic``, ``rows_unparseable``, ``rows_skipped_by_time``,
        and ``rows_by_data_type``.
    """
    files = _find_log_files(input_path)
    if not files:
        raise ConverterError(f"No syslog files found in: {input_path}")

    ui = get_terminal()
    ui.header(
        "syslog2timesketch",
        subtitle="Convert Linux syslog/auth.log → Timesketch timeline",
        badges=[("syslog", "accent"), (output_format, "muted")],
    )
    ui.step("Files found", f"{len(files)} syslog file(s)")

    since_dt = _parse_since_until(since)
    until_dt = _parse_since_until(until)

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("syslog2timesketch", command_line or [])
        input_path_obj = Path(input_path)
        if input_path_obj.is_dir() or input_path_obj.is_file():
            report.add_input_path(input_path_obj)

    writer = OutputWriter(
        output,
        output_format,
        fieldnames=_FIELDNAMES if output_format == "csv" else None,
        compute_hash=report_path is not None,
        split=split,
    )
    rows_written = 0
    rows_generic = 0
    rows_unparseable = 0
    rows_skipped_by_time = 0
    data_type_counts: dict[str, int] = {}

    for idx, log_file in enumerate(files, start=1):
        ui.progress(idx, len(files), label=str(log_file))
        source_str = str(log_file.resolve())

        try:
            with _open_log(log_file) as fh:
                for line in fh:
                    line = line.rstrip("\n\r")
                    if not line:
                        continue

                    row = _parse_line(line, year, source_str, matched_only)
                    if row is None:
                        if not matched_only:
                            rows_unparseable += 1
                        continue

                    ts = row.get("timestamp", 0)
                    if since_dt and ts and ts < to_unix_microseconds(since_dt):
                        rows_skipped_by_time += 1
                        continue
                    if until_dt and ts and ts > to_unix_microseconds(until_dt):
                        rows_skipped_by_time += 1
                        continue

                    data_type = row["data_type"]
                    data_type_counts[data_type] = data_type_counts.get(data_type, 0) + 1
                    if data_type == "syslog:generic:message":
                        rows_generic += 1

                    writer.add(row)
                    rows_written += 1
        except OSError as exc:
            raise ConverterError(f"Failed to read {log_file}: {exc}") from exc

    ui.end_progress()
    written = writer.write()

    if report:
        add_writer_output(report, writer)
        report.set_statistics({
            "rows_written": written,
            "files_processed": len(files),
            "rows_generic": rows_generic,
            "rows_unparseable": rows_unparseable,
            "rows_skipped_by_time": rows_skipped_by_time,
            "rows_by_data_type": data_type_counts,
            "since": since,
            "until": until,
            "year": year,
            "matched_only": matched_only,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    summary_items: dict[str, Any] = {
        "Rows written": f"{written:,}",
        "Files processed": f"{len(files)}",
        "Generic rows": f"{rows_generic:,}",
        "Unparseable": f"{rows_unparseable:,}",
        "Skipped by time": f"{rows_skipped_by_time:,}",
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
    }
    for data_type, count in sorted(data_type_counts.items()):
        if data_type != "syslog:generic:message":
            summary_items[f"Event: {data_type}"] = f"{count:,}"
    ui.summary("Result", summary_items)

    return {
        "rows_written": written,
        "files_processed": len(files),
        "rows_generic": rows_generic,
        "rows_unparseable": rows_unparseable,
        "rows_skipped_by_time": rows_skipped_by_time,
        "rows_by_data_type": data_type_counts,
    }
