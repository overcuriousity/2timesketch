#!/usr/bin/env python3
"""HAProxy log to Timesketch timeline converter.

Two layers are detected per line, independently and without a flag:

  * the **envelope** the line arrived in — a Docker ``json-file`` record
    (``{"log": ..., "stream": ..., "time": ...}``), a BSD syslog prefix
    (``May 15 08:02:22 lb01 haproxy[1234]: ...``), or none at all;
  * the **HAProxy payload** shape — HTTP log format, TCP log format, a
    connection/SSL error line, or a startup/reload admin line.

Timestamps: HAProxy's own ``accept_date`` carries no UTC offset, so it never
sets the event timestamp when a UTC-anchored clock is available. A Docker
envelope's ``time`` field is RFC 3339 with an explicit zone and wins; each row
records which clock it used in ``timestamp_desc`` ("Log Write Time" vs "HTTP
Request Time"), and ``accept_date`` survives verbatim in the
``haproxy_accept_date`` column. Rather than assert that the source ran UTC,
the converter *measures* it: the smallest observed
``envelope_clock - accept_date`` skew is reported in the run summary and in
the ``--report`` audit JSON, where a whole-hour value is the tell that it did
not. The smallest is used rather than the median because the difference is
session duration plus write latency — a tarpit or a slow backend inflates
every other statistic while the clocks stay aligned.

A startup/reload line or an unmodeled shape in a bare envelope has no clock of
its own at all. Rather than drop the evidence ("Server app02 is DOWN" is
exactly the line an investigation wants), it is anchored to its nearest dated
neighbour and marked: ``timestamp_inferred`` is ``true``, ``timestamp_desc``
says which neighbour it borrowed from, and the run summary counts how many
rows that applied to.
"""

from __future__ import annotations

import datetime
import gzip
import json
import random
import re
import statistics
import urllib.parse
from pathlib import Path
from typing import Any

from .common import (
    COMMON_FIELDS,
    AuditReport,
    ConverterError,
    OutputWriter,
    add_writer_output,
    expand_glob,
    normalize_ip,
    to_iso8601,
    to_unix_microseconds,
)
from .terminal import get_terminal

# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_RE_ACCEPT_DATE = re.compile(r"^(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?$")


def parse_accept_date(value: str) -> datetime.datetime | None:
    """Parse HAProxy's ``accept_date``, treating it as UTC.

    The format carries no offset. Callers that have a UTC-anchored clock use
    this only to measure the skew against it; callers that do not use it as
    the timestamp and say so in the run summary.
    """
    m = _RE_ACCEPT_DATE.match(value.strip())
    if not m:
        return None
    month = _MONTHS.get(m.group(2).lower())
    if month is None:
        return None
    frac = (m.group(7) or "").ljust(6, "0")
    try:
        return datetime.datetime(
            int(m.group(3)),
            month,
            int(m.group(1)),
            int(m.group(4)),
            int(m.group(5)),
            int(m.group(6)),
            int(frac),
            tzinfo=datetime.timezone.utc,
        )
    except ValueError:
        return None


def parse_rfc3339(value: str) -> datetime.datetime | None:
    """Parse a Docker ``time`` field (RFC 3339, up to nanosecond precision).

    ``fromisoformat`` rejects more than six fractional digits, which is
    exactly what the Docker json-file driver writes, so the fraction is
    truncated to microseconds first.
    """
    text = value.strip()
    if not text:
        return None
    text = re.sub(r"\.(\d+)", lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    try:
        dt = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _parse_syslog_time(
    month: str, day: str, clock: str, year: int
) -> datetime.datetime | None:
    """Build a UTC datetime from a BSD syslog prefix and an assumed year."""
    month_num = _MONTHS.get(month.lower())
    if month_num is None:
        return None
    hour, minute, second = clock.split(":")
    try:
        return datetime.datetime(
            year,
            month_num,
            int(day),
            int(hour),
            int(minute),
            int(second),
            tzinfo=datetime.timezone.utc,
        )
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Envelope layer
# ---------------------------------------------------------------------------

# BSD syslog: "May 15 08:02:22 lb01 haproxy[1234]: <payload>", optionally
# preceded by an RFC 3164 priority such as "<134>".
_RE_SYSLOG = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: (?P<payload>.*)$"
)


def unwrap(line: str) -> tuple[str, dict[str, str], datetime.datetime | None] | None:
    """Strip a transport envelope off one raw file line.

    Returns ``(payload, envelope_attributes, utc_timestamp_or_None)``, or
    ``None`` when the line claims to be an envelope but is malformed (a
    truncated Docker JSON record) and must be counted as skipped. Only a
    Docker envelope yields a timestamp here: the syslog prefix carries no
    year and no offset, so it is recorded but used as the clock only as a
    last resort, by the caller.
    """
    stripped = line.strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
        except ValueError:
            return None
        if isinstance(obj, dict) and "log" in obj:
            attrs = {"envelope": "docker"}
            if obj.get("stream"):
                attrs["docker_stream"] = str(obj["stream"])
            ts = None
            if obj.get("time"):
                attrs["docker_time"] = str(obj["time"])
                ts = parse_rfc3339(str(obj["time"]))
            return str(obj.get("log") or "").rstrip("\r\n"), attrs, ts
        return None

    m = _RE_SYSLOG.match(line)
    if m:
        attrs = {
            "envelope": "syslog",
            "syslog_host": m.group("host"),
            "syslog_program": m.group("prog"),
        }
        if m.group("pid"):
            attrs["syslog_pid"] = m.group("pid")
        attrs["syslog_time"] = f"{m.group('mon')} {m.group('day')} {m.group('time')}"
        return m.group("payload"), attrs, None

    return line, {"envelope": "raw"}, None


# ---------------------------------------------------------------------------
# HAProxy payload layer
# ---------------------------------------------------------------------------

# HTTP log format:
#   client_ip:client_port [accept_date] frontend_name backend_name/server_name
#   TR/Tw/Tc/Tr/Ta status_code bytes_read captured_request_cookie
#   captured_response_cookie termination_state
#   actconn/feconn/beconn/srv_conn/retries srv_queue/backend_queue
#   {captured_request_headers} {captured_response_headers} "http_request"
_RE_HTTP = re.compile(
    r"^(?P<client_ip>\S+):(?P<client_port>\d+) \[(?P<accept>[^\]]+)\] "
    r"(?P<frontend>\S+) (?P<backend>[^\s/]+)/(?P<server>\S+) "
    r"(?P<t1>[+-]?\d+)/(?P<t2>[+-]?\d+)/(?P<t3>[+-]?\d+)/(?P<t4>[+-]?\d+)/(?P<t5>[+-]?\d+) "
    r"(?P<status>-?\d+) (?P<bytes>\+?\d+) "
    r"(?P<req_cookie>\S+) (?P<resp_cookie>\S+) (?P<term>[A-Za-z-]{4}) "
    r"(?P<actconn>\d+)/(?P<feconn>\d+)/(?P<beconn>\d+)/(?P<srvconn>\d+)/(?P<retries>\+?\d+) "
    r"(?P<srvq>\d+)/(?P<beq>\d+)"
    r"(?P<captures>(?: \{[^}]*\}){0,2}) "
    r'"(?P<request>.*)"$'
)

# TCP log format: three timers, no status code, no cookies, no request.
_RE_TCP = re.compile(
    r"^(?P<client_ip>\S+):(?P<client_port>\d+) \[(?P<accept>[^\]]+)\] "
    r"(?P<frontend>\S+) (?P<backend>[^\s/]+)/(?P<server>\S+) "
    r"(?P<t1>[+-]?\d+)/(?P<t2>[+-]?\d+)/(?P<t3>[+-]?\d+) "
    r"(?P<bytes>\+?\d+) (?P<term>[A-Za-z-]{2,4}) "
    r"(?P<actconn>\d+)/(?P<feconn>\d+)/(?P<beconn>\d+)/(?P<srvconn>\d+)/(?P<retries>\+?\d+) "
    r"(?P<srvq>\d+)/(?P<beq>\d+)$"
)

# Connection/SSL error line:
#   client_ip:client_port [accept_date] frontend/bind_id: message
_RE_CONN_ERROR = re.compile(
    r"^(?P<client_ip>\S+):(?P<client_port>\d+) \[(?P<accept>[^\]]+)\] "
    r"(?P<frontend>[^\s/]+)/(?P<bind>[^\s:]+): (?P<message>.+)$"
)

# Startup/reload line: "[NOTICE]   (1) : New worker (8) forked"
_RE_ADMIN = re.compile(r"^\[(?P<level>[A-Z]+)\]\s*\((?P<pid>\d+)\)\s*:\s*(?P<message>.*)$")

_RE_CAPTURE_GROUP = re.compile(r"\{([^}]*)\}")

# Character 1 of the termination state: what ended the session.
_TERM_EVENT = {
    "C": "client aborted the connection",
    "S": "server aborted the connection or returned an error",
    "P": "proxy intercepted the session",
    "L": "proxy locally processed and closed the session",
    "R": "a resource was exhausted on the proxy",
    "I": "internal error on the proxy",
    "D": "session killed because the server was down",
    "U": "session killed in the queue because the backend went down",
    "K": "session actively killed by an administrator",
    "c": "client-side timeout expired",
    "s": "server-side timeout expired",
    "-": "normal session completion",
}

# Character 2 of the termination state: the phase the session was in.
_TERM_SESSION_STATE = {
    "R": "waiting for a complete valid request",
    "Q": "waiting in the queue for a server slot",
    "C": "waiting for the connection to the server to establish",
    "H": "waiting for or processing the server response headers",
    "D": "data phase transfer",
    "L": "pushing the last data to the client",
    "T": "request was tarpitted",
    "t": "request was tarpitted and a response was sent",
    "-": "normal session completion",
}

# kind -> (data_type, timestamp_desc when accept_date is the clock)
_KINDS = {
    "http": ("web:access:request", "HTTP Request Time"),
    "tcp": ("network:proxy:session", "Session Accept Time"),
    "error": ("web:error:log", "Connection Error Time"),
    "admin": ("service:daemon:log", "Log Write Time"),
    "message": ("service:daemon:log", "Log Write Time"),
}

# Shapes that prove the file really is HAProxy (the catch-all does not).
_STRUCTURED_KINDS = frozenset({"http", "tcp", "error", "admin"})


def _counter(value: str, attrs: dict[str, Any], flag: str) -> str:
    """Strip HAProxy's ``+`` truncation marker, recording that it was there."""
    if value.startswith("+"):
        attrs[flag] = "true"
        return value[1:]
    return value


def _split_captures(text: str, attrs: dict[str, Any]) -> None:
    """Split the ``{...}`` capture groups off an HTTP log line.

    HAProxy emits the request capture first and the response capture second;
    with only a response capture configured it still emits an empty request
    group, so a single group is always the request one.
    """
    groups = _RE_CAPTURE_GROUP.findall(text)
    if not groups:
        return
    attrs["captured_request_headers"] = groups[0]
    if len(groups) > 1:
        attrs["captured_response_headers"] = groups[1]
    # A capture that is a bare IP is the real client behind this proxy — the
    # overwhelmingly common capture (an X-Forwarded-For header).
    real_ip = normalize_ip(groups[0])
    if real_ip:
        attrs["client_real_ip"] = real_ip


def _decode_termination(state: str, attrs: dict[str, Any]) -> None:
    """Expand the termination state's characters into readable attributes."""
    attrs["termination_state"] = state
    if len(state) >= 1:
        attrs["term_event"] = state[0]
        attrs["term_event_desc"] = _TERM_EVENT.get(state[0], "")
    if len(state) >= 2:
        attrs["term_session_state"] = state[1]
        attrs["term_session_state_desc"] = _TERM_SESSION_STATE.get(state[1], "")
    # The persistence-cookie characters are kept raw: their meaning depends on
    # the backend's cookie configuration, so a fixed gloss would be a guess.
    if len(state) >= 3:
        attrs["term_cookie_client"] = state[2]
    if len(state) >= 4:
        attrs["term_cookie_server"] = state[3]


def _split_request(request: str, attrs: dict[str, Any]) -> None:
    """Split the quoted HTTP request line into method / URI / protocol."""
    attrs["http_request"] = request
    parts = request.split(" ")
    if parts and parts[0]:
        attrs["http_method"] = parts[0]
    if len(parts) < 2:
        return
    uri = parts[1]
    attrs["http_uri"] = uri
    if len(parts) > 2:
        attrs["http_protocol"] = parts[2]
    try:
        split = urllib.parse.urlsplit(uri)
    except ValueError:
        return
    if split.netloc:
        attrs["http_host"] = split.netloc
    if split.path:
        attrs["http_path"] = split.path
    if split.query:
        attrs["http_query"] = split.query


def _frontend(name: str, attrs: dict[str, Any]) -> None:
    """Record the frontend, splitting off HAProxy's ``~`` SSL marker."""
    if name.endswith("~"):
        attrs["frontend"] = name[:-1]
        attrs["frontend_ssl"] = "true"
    else:
        attrs["frontend"] = name


def parse_payload(payload: str) -> tuple[str, dict[str, Any], str] | None:
    """Parse one unwrapped HAProxy line.

    Returns ``(kind, attributes, accept_date)`` — ``accept_date`` is the raw
    string, empty when the shape has none. Returns ``None`` for an empty line.
    """
    text = payload.strip()
    if not text:
        return None

    m = _RE_HTTP.match(text)
    if m:
        attrs: dict[str, Any] = {
            "src_ip": normalize_ip(m.group("client_ip")) or m.group("client_ip"),
            "src_port": m.group("client_port"),
            "backend": m.group("backend"),
            "backend_server": m.group("server"),
            "time_request_ms": m.group("t1"),
            "time_queue_ms": m.group("t2"),
            "time_connect_ms": m.group("t3"),
            "time_response_ms": m.group("t4"),
            "status_code": m.group("status"),
            "conn_active": m.group("actconn"),
            "conn_frontend": m.group("feconn"),
            "conn_backend": m.group("beconn"),
            "conn_server": m.group("srvconn"),
            "queue_server": m.group("srvq"),
            "queue_backend": m.group("beq"),
        }
        _frontend(m.group("frontend"), attrs)
        attrs["time_total_ms"] = _counter(m.group("t5"), attrs, "time_total_truncated")
        attrs["bytes_read"] = _counter(m.group("bytes"), attrs, "bytes_read_truncated")
        attrs["retries"] = _counter(m.group("retries"), attrs, "retries_truncated")
        if m.group("req_cookie") != "-":
            attrs["request_cookie"] = m.group("req_cookie")
        if m.group("resp_cookie") != "-":
            attrs["response_cookie"] = m.group("resp_cookie")
        _decode_termination(m.group("term"), attrs)
        _split_captures(m.group("captures"), attrs)
        _split_request(m.group("request"), attrs)
        return "http", attrs, m.group("accept")

    m = _RE_TCP.match(text)
    if m:
        attrs = {
            "src_ip": normalize_ip(m.group("client_ip")) or m.group("client_ip"),
            "src_port": m.group("client_port"),
            "backend": m.group("backend"),
            "backend_server": m.group("server"),
            "time_queue_ms": m.group("t1"),
            "time_connect_ms": m.group("t2"),
            "conn_active": m.group("actconn"),
            "conn_frontend": m.group("feconn"),
            "conn_backend": m.group("beconn"),
            "conn_server": m.group("srvconn"),
            "queue_server": m.group("srvq"),
            "queue_backend": m.group("beq"),
        }
        _frontend(m.group("frontend"), attrs)
        attrs["time_total_ms"] = _counter(m.group("t3"), attrs, "time_total_truncated")
        attrs["bytes_read"] = _counter(m.group("bytes"), attrs, "bytes_read_truncated")
        attrs["retries"] = _counter(m.group("retries"), attrs, "retries_truncated")
        _decode_termination(m.group("term"), attrs)
        return "tcp", attrs, m.group("accept")

    m = _RE_CONN_ERROR.match(text)
    if m:
        attrs = {
            "src_ip": normalize_ip(m.group("client_ip")) or m.group("client_ip"),
            "src_port": m.group("client_port"),
            "frontend": m.group("frontend"),
            "bind_id": m.group("bind"),
            "error_message": m.group("message"),
        }
        return "error", attrs, m.group("accept")

    m = _RE_ADMIN.match(text)
    if m:
        return (
            "admin",
            {
                "log_level": m.group("level"),
                "worker_pid": m.group("pid"),
                "admin_message": m.group("message"),
            },
            "",
        )

    # Inside a file that sniffed as HAProxy, a shape we do not model is still
    # evidence. Keep it whole rather than dropping it.
    return "message", {}, ""


def line_kind(line: str) -> str | None:
    """Classify a raw line for sniffing; ``None`` for a malformed envelope."""
    unwrapped = unwrap(line)
    if unwrapped is None:
        return None
    parsed = parse_payload(unwrapped[0])
    return parsed[0] if parsed else None


def parse_line(
    line: str, source_file: str, year: int
) -> tuple[dict[str, Any] | None, int | None]:
    """Parse one raw file line into a Timesketch row.

    Returns ``(row, skew_ms)`` where ``skew_ms`` is the measured
    ``envelope_clock - accept_date`` difference for this line, or ``None``
    when the line has no such pair. ``row`` is ``None`` when the line is a
    malformed envelope or empty. A row whose ``timestamp`` is ``None`` had no
    derivable clock at all; anchoring it to a neighbour is the caller's job,
    since only the caller sees the surrounding lines.
    """
    unwrapped = unwrap(line)
    if unwrapped is None:
        return None, None
    payload, envelope_attrs, envelope_ts = unwrapped

    parsed = parse_payload(payload)
    if parsed is None:
        return None, None
    kind, attrs, accept_raw = parsed

    accept_dt = parse_accept_date(accept_raw) if accept_raw else None
    skew_ms: int | None = None
    if accept_raw:
        attrs["haproxy_accept_date"] = accept_raw
    if envelope_ts is not None and accept_dt is not None:
        skew_ms = round((envelope_ts - accept_dt).total_seconds() * 1000)

    data_type, accept_desc = _KINDS[kind]
    if envelope_ts is not None:
        event_dt: datetime.datetime | None = envelope_ts
        timestamp_desc = "Log Write Time"
    elif accept_dt is not None:
        event_dt = accept_dt
        timestamp_desc = accept_desc
    elif envelope_attrs.get("syslog_time"):
        # Last resort: the syslog prefix has no year and no offset, but for an
        # admin or unmodeled line it is the only clock there is.
        month, day, clock = str(envelope_attrs["syslog_time"]).split()
        event_dt = _parse_syslog_time(month, day, clock, year)
        timestamp_desc = "Log Write Time" if event_dt is not None else ""
    else:
        event_dt = None
        timestamp_desc = ""

    row: dict[str, Any] = {
        "datetime": to_iso8601(to_unix_microseconds(event_dt)) if event_dt else "",
        "timestamp_desc": timestamp_desc,
        "message": payload.strip(),
        "data_type": data_type,
        "timestamp": to_unix_microseconds(event_dt) if event_dt else None,
        "source": source_file,
        "log_type": kind,
    }
    row.update(envelope_attrs)
    row.update(attrs)
    return row, skew_ms


# ---------------------------------------------------------------------------
# Output columns
# ---------------------------------------------------------------------------

# Fields beyond the shared timeline columns. Fixed so CSV output can be
# streamed without buffering rows; HAProxy interleaves every line kind in one
# stream, so the header is the union across kinds rather than per-kind.
_EXTRA_FIELDS = sorted([
    "admin_message",
    "backend",
    "backend_server",
    "bind_id",
    "bytes_read",
    "bytes_read_truncated",
    "captured_request_headers",
    "captured_response_headers",
    "client_real_ip",
    "conn_active",
    "conn_backend",
    "conn_frontend",
    "conn_server",
    "docker_stream",
    "docker_time",
    "envelope",
    "error_message",
    "frontend",
    "frontend_ssl",
    "haproxy_accept_date",
    "http_host",
    "http_method",
    "http_path",
    "http_protocol",
    "http_query",
    "http_request",
    "http_uri",
    "log_level",
    "log_type",
    "queue_backend",
    "queue_server",
    "request_cookie",
    "response_cookie",
    "retries",
    "retries_truncated",
    "src_port",
    "status_code",
    "syslog_host",
    "syslog_pid",
    "syslog_program",
    "syslog_time",
    "term_cookie_client",
    "term_cookie_server",
    "term_event",
    "term_event_desc",
    "term_session_state",
    "term_session_state_desc",
    "termination_state",
    "time_connect_ms",
    "time_queue_ms",
    "time_request_ms",
    "time_response_ms",
    "time_total_ms",
    "time_total_truncated",
    "timestamp_inferred",
    "worker_pid",
])


def _fieldnames() -> list[str]:
    """Build the fixed CSV column order."""
    # HAProxy names a backend *server*, not an address, so no row ever yields
    # a destination IP and dst_ip is omitted from the header.
    base = [f for f in COMMON_FIELDS if f != "dst_ip"]
    return base + _EXTRA_FIELDS


# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------

SNIFF_LINES = 200

# Undated lines held while waiting for the first dated row to anchor them to.
MAX_PENDING_UNDATED = 10_000


def _open_log(path: Path) -> Any:
    """Open a plain or gzipped log file for reading text lines."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def sniff_haproxy(path: Path) -> bool:
    """Return True when the file's first lines contain a real HAProxy shape.

    The payload parser has a catch-all, so without this gate any text file at
    all would convert "successfully" into rows of unstructured messages.
    """
    sampled = 0
    try:
        with _open_log(path) as fh:
            for line in fh:
                if not line.strip():
                    continue
                if line_kind(line) in _STRUCTURED_KINDS:
                    return True
                sampled += 1
                if sampled >= SNIFF_LINES:
                    break
    except OSError:
        return False
    return False


def _find_log_files(input_path: str) -> list[Path]:
    """Resolve the input into a list of HAProxy log files."""
    path = Path(input_path)
    if path.is_file():
        if not sniff_haproxy(path):
            raise ConverterError(
                f"{input_path} does not look like a HAProxy log — none of its "
                f"first {SNIFF_LINES} lines matched the HTTP log, TCP log, connection "
                "error, or startup/reload format (in a Docker json-file, syslog, or "
                "bare envelope)."
            )
        return [path]
    if path.is_dir():
        found = [p for p in sorted(path.iterdir()) if p.is_file() and sniff_haproxy(p)]
        if not found:
            raise ConverterError(f"No HAProxy log files found in: {input_path}")
        return found

    matches = expand_glob(input_path)
    found = [p for p in matches if p.is_file() and sniff_haproxy(p)]
    if not found:
        raise ConverterError(f"No HAProxy log files matched: {input_path}")
    return found


# ---------------------------------------------------------------------------
# Timezone measurement
# ---------------------------------------------------------------------------

# Samples kept for the percentile statistics. The minimum — the only figure
# the timezone conclusion rests on — is tracked exactly, over every line.
SKEW_SAMPLE_CAP = 50_000


class _SkewSampler:
    """Exact minimum plus a bounded reservoir sample of the skews."""

    def __init__(self, cap: int = SKEW_SAMPLE_CAP):
        self.cap = cap
        self.samples: list[int] = []
        self.minimum: int | None = None
        self.seen = 0
        self._rng = random.Random(0)

    def add(self, skew_ms: int) -> None:
        self.seen += 1
        if self.minimum is None or skew_ms < self.minimum:
            self.minimum = skew_ms
        if len(self.samples) < self.cap:
            self.samples.append(skew_ms)
            return
        slot = self._rng.randrange(self.seen)
        if slot < self.cap:
            self.samples[slot] = skew_ms


def _percentile(values: list[int], fraction: float) -> int:
    """Nearest-rank percentile of an already-collected sample."""
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def _skew_stats(sampler: _SkewSampler) -> dict[str, int | None]:
    """Summarize the measured ``envelope_clock - accept_date`` differences.

    The difference is *session duration plus write latency*: HAProxy logs an
    HTTP session when it ends, but stamps ``accept_date`` when it began. It is
    therefore bounded below by the clock offset and unbounded above — a proxy
    that tarpits requests for ten seconds pushes the median ten seconds out
    while its clock is perfectly aligned.

    Only the minimum is bounded by the offset, so that is what the timezone
    conclusion rests on; ``p05`` and ``median`` are reported beside it so a
    reader can see whether that minimum is an isolated outlier. A low
    percentile is not enough on its own — a log where every session is
    tarpitted has no fast session for it to land on.
    """
    if not sampler.samples:
        return {"p05": None, "median": None, "min": None, "samples": 0}
    return {
        "p05": _percentile(sampler.samples, 0.05),
        "median": round(statistics.median(sampler.samples)),
        "min": sampler.minimum,
        "samples": sampler.seen,
    }


def _timezone_note(stats: dict[str, int | None]) -> str:
    """Describe what the measured skew says about the source's clock."""
    floor = stats["min"]
    if floor is None:
        return (
            "no UTC-anchored clock in this input: HAProxy's accept_date carries no "
            "offset and is assumed UTC. If the host logged local time, every "
            "timestamp is off by that offset."
        )
    median = stats["median"]
    tail = (
        f" (the median is {median} ms, inflated by session duration — HAProxy "
        "stamps accept_date when a session begins and logs it when it ends)"
        if median is not None and abs(median - floor) >= 1000
        else ""
    )
    if abs(floor) < 60_000:
        return (
            f"timestamps come from the envelope's UTC clock. The smallest observed "
            f"envelope-minus-accept_date skew is {floor} ms, i.e. sub-minute, so "
            f"HAProxy's accept_date was being written on the same UTC clock{tail}."
        )
    return (
        f"timestamps come from the envelope's UTC clock. The smallest observed "
        f"envelope-minus-accept_date skew is {floor} ms ({floor / 3_600_000:.2f} h), "
        f"so HAProxy's accept_date was NOT written in UTC — read the "
        f"haproxy_accept_date column with that offset in mind{tail}."
    )


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------

def convert_haproxy(
    input_path: str,
    output: str,
    output_format: str,
    since: str | None = None,
    until: str | None = None,
    year: int | None = None,
    verbose: bool = True,
    split: str | None = None,
    report_path: str | None = None,
    command_line: list[str] | None = None,
) -> int:
    """Convert HAProxy log files to a Timesketch timeline.

    Returns:
        Number of rows written.
    """
    log_files = _find_log_files(input_path)
    assumed_year = year if year is not None else datetime.datetime.now(datetime.timezone.utc).year

    ui = get_terminal()
    ui.header(
        "haproxy2timesketch",
        subtitle="Convert HAProxy logs → Timesketch timeline",
        badges=[("haproxy", "accent"), (output_format, "muted")],
    )
    ui.step("Files found", str(len(log_files)))

    report: AuditReport | None = None
    if report_path:
        report = AuditReport("haproxy2timesketch", command_line or [])
        for log_file in log_files:
            report.add_input_path(log_file)

    since_dt = _parse_bound(since)
    until_dt = _parse_bound(until)
    since_us = to_unix_microseconds(since_dt) if since_dt else None
    until_us = to_unix_microseconds(until_dt) if until_dt else None

    writer = OutputWriter(
        output,
        output_format,
        fieldnames=_fieldnames(),
        compute_hash=report_path is not None,
        split=split,
    )

    sampler = _SkewSampler()
    counts_by_kind: dict[str, int] = {}
    skipped = 0
    inferred = 0
    undated = 0
    filtered = 0

    # A line with no clock of its own — a startup/reload line or an unmodeled
    # shape in a bare envelope — is still evidence ("Server app02 is DOWN"),
    # so it is anchored to its nearest dated neighbour rather than dropped.
    # The anchor is always disclosed: timestamp_inferred marks the row, the
    # description names what the timestamp actually is, and the summary counts
    # them. Leading undated lines wait for the first dated row; if the file
    # never produces one, there is nothing to anchor to and they are dropped.
    pending: list[dict[str, Any]] = []
    last_timestamp: int | None = None

    def _emit(row: dict[str, Any]) -> None:
        """Apply the time filter and write one row."""
        nonlocal filtered
        timestamp = row["timestamp"]
        if since_us is not None and timestamp < since_us:
            filtered += 1
            return
        if until_us is not None and timestamp > until_us:
            filtered += 1
            return
        kind = row["log_type"]
        counts_by_kind[kind] = counts_by_kind.get(kind, 0) + 1
        writer.add({k: v for k, v in row.items() if v is not None})

    def _anchor(row: dict[str, Any], timestamp: int, desc: str) -> None:
        """Stamp an undated row with a neighbour's timestamp, saying so."""
        nonlocal inferred
        row["timestamp"] = timestamp
        row["datetime"] = to_iso8601(timestamp)
        row["timestamp_desc"] = desc
        row["timestamp_inferred"] = "true"
        inferred += 1
        _emit(row)

    for index, log_file in enumerate(log_files, start=1):
        ui.step(f"[{index}/{len(log_files)}]", str(log_file))
        try:
            with _open_log(log_file) as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    row, skew_ms = parse_line(line, str(log_file.resolve()), assumed_year)
                    if skew_ms is not None:
                        sampler.add(skew_ms)
                    if row is None:
                        skipped += 1
                        continue
                    timestamp = row.get("timestamp")
                    if timestamp is None:
                        if last_timestamp is not None:
                            _anchor(row, last_timestamp, "Preceding Log Write Time")
                        elif len(pending) < MAX_PENDING_UNDATED:
                            pending.append(row)
                        else:
                            undated += 1
                        continue
                    last_timestamp = timestamp
                    while pending:
                        _anchor(pending.pop(0), timestamp, "Following Log Write Time")
                    _emit(row)
        except OSError as exc:
            raise ConverterError(f"Failed to read {log_file}: {exc}") from exc

    undated += len(pending)
    pending.clear()

    total = writer.write()
    stats = _skew_stats(sampler)
    note = _timezone_note(stats)

    if report:
        add_writer_output(report, writer)
        report.set_statistics({
            "rows": total,
            "rows_by_type": counts_by_kind,
            "lines_skipped": skipped,
            "rows_with_inferred_timestamp": inferred,
            "lines_dropped_without_timestamp": undated,
            "rows_filtered_by_time": filtered,
            "since": since,
            "until": until,
            "assumed_year": assumed_year,
            "clock_skew_ms": stats,
            "timezone_assumption": note,
        })
        report.write(report_path)
        ui.success(f"Audit report written to {report_path}")

    summary_items: dict[str, Any] = {
        "Files processed": str(len(log_files)),
        "Output": output if output != "-" else "stdout",
        "Format": output_format,
        "Rows": f"{total:,}",
    }
    for kind, count in sorted(counts_by_kind.items()):
        summary_items[f"Rows ({kind})"] = f"{count:,}"
    if skipped:
        summary_items["Lines skipped"] = f"{skipped:,}"
    if inferred:
        summary_items["Rows anchored to a neighbour"] = f"{inferred:,}"
    if undated:
        summary_items["Lines dropped (no clock to anchor to)"] = f"{undated:,}"
    if filtered:
        summary_items["Rows outside --since/--until"] = f"{filtered:,}"
    summary_items["Clock"] = note
    ui.summary("Result", summary_items)

    return total


def _parse_bound(value: str | None) -> datetime.datetime | None:
    """Parse an ISO 8601 ``--since``/``--until`` value to a UTC-aware datetime."""
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConverterError(f"Invalid ISO 8601 timestamp: {value}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)
