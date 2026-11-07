# 2timesketch — Unified Timesketch Converters

A small suite of interoperable converters that turn forensically relevant logs
into [Timesketch](https://timesketch.org/)-compatible timelines.

Supported sources:

- **systemd journals** (`journal2timesketch.py`)
- **Browser histories** (`browser2timesketch.py`) — Firefox/Gecko,
  Chrome/Chromium/Edge/Brave, Safari/WebKit
- **nginx logs** (`nginx2timesketch.py`) — access, error, redirect
- **AWS CloudTrail** (`cloudtrail2timesketch.py`) — management, data, and insight events
- **pfSense/OPNsense filterlog** (`filterlog2timesketch.py`) — IPv4/IPv6 TCP/UDP/ICMP firewall logs
- **HAProxy logs** (`haproxy2timesketch.py`) — HTTP and TCP log formats,
  connection/SSL errors, and startup/reload lines, in a Docker `json-file`,
  syslog, or bare envelope (auto-detected per line), with the termination
  state decoded and the source's clock offset measured rather than assumed
- **Suricata IDS/IPS logs** (`suricata2timesketch.py`) — EVE JSON, fast.log, and OPNsense syslog exports
- **Packet captures** (`pcap2timesketch.py`) — pcap and pcapng files from
  Wireshark/tcpdump, decoded to Ethernet/Linux-SLL/raw-IP, IPv4/IPv6, and
  TCP/UDP/ICMP/ARP headers; optional `--reassemble http` adds one row per
  reassembled HTTP/1.x request/response transaction
- **Cowrie SSH/Telnet honeypot logs** (`cowrie2timesketch.py`) — `cowrie.json`
  session, auth, command, client fingerprint, direct-tcpip, and TTY log events
- **DShield webhoneypot logs** (`webhoneypot2timesketch.py`) —
  `webhoneypot_YYYY-MM-DD.json` HTTP request records from the DShield web
  honeypot (isc-agent), incl. reverse-proxy `X-Forwarded-For`/`X-Real-Ip`
  client resolution, matched signature metadata, promoted well-known
  header columns, URL path/query splitting with SSRF fetch-target
  extraction, and JSON-RPC/MCP request-body parsing
- **Linux syslog/auth.log** (`syslog2timesketch.py`) — plain-text syslog files
  (auth.log, secure, syslog, messages, cron.log) in RFC 3164 BSD, year-first
  BSD (`2026 Aug 23 00:17:04 …`, as several appliance firmwares emit) or
  rsyslog ISO form, with structured extraction of sshd, sudo, su, cron,
  systemd-logind, and account-management events. `--assume-tz` names the
  timezone for the header forms that record no offset
- **Apache HTTP Server logs** (`apache2timesketch.py`) — access (combined and
  common/CLF format, incl. `other_vhosts_access.log`) and error logs (2.4 and
  2.2 formats)
- **Windows event log exports** (`evtx2timesketch.py`) — XML exports from
  `wevtutil qe /f:xml` or `evtx_dump`, and JSONL exports from
  `evtx_dump -o jsonl` (binary `.evtx` must be exported first)
- **Zeek NSM logs** (`zeek2timesketch.py`) — conn, dns, http, ssl, files,
  notice, weird, and any other Zeek/Bro TSV log (parsed generically via the
  `#fields` headers, incl. rotated and gzip-compressed logs), merged into one
  globally time-sorted timeline
- **W3C Extended logs** (`w3c2timesketch.py`) — IIS site logs (`u_ex*.log`),
  http.sys `HTTPERR` logs, and any other `#Fields:`-described W3C log. The
  field directive is honoured per occurrence, so a column set that changes
  mid-file (an IIS restart or config change) is parsed against the block it
  actually describes rather than silently shifting every later column
- **Microsoft Exchange protocol logs** (`exchange2timesketch.py`) — HttpProxy
  (Autodiscover, Owa, Ews, Mapi, ActiveSync, Rpc), ECP, RPC Client Access and
  IMAP4/POP3 CSV logs, generic over their `#Fields:` header, with the
  timestamp-less `GlobalActivity` metric rows anchored to their neighbours
  rather than dropped
- **Squid proxy logs** (`squid2timesketch.py`) — `access.log` in the native
  `logformat squid` or the httpd-style `common`/`combined` formats (detected
  from the data, not assumed), `cache.log` incl. helper output and wrapped
  continuation lines, and `icap.log`
- **conntrackd flow logs** (`conntrackd2timesketch.py`) — `conntrackd-stats.log`
  connection records, with both the original and reply tuples as discrete
  columns and the address translation between them derived into `nat_type`,
  `translated_src_ip` and `translated_dst_ip`

## Requirements

- Python 3.9+
- Standard library only — no third-party packages required
- `journalctl` (systemd) is required for the journal converter

## Common conventions

All converters share:

- A uniform CLI (`-i/--input`, `-o/--output`, `-f/--format`, `-v/--verbose`, `--report`, `--split`, `--no-color`).
- CSV output by default (`-f jsonl` is also supported).
- Styled terminal output (headers, progress bars, badges, result panels) on stderr;
  pass `--no-color` or set `NO_COLOR` to disable ANSI colors and Unicode box drawing.
- The same common columns at the start of every row:

| Column | Description |
|---|---|
| `datetime` | ISO 8601 UTC timestamp (Timesketch date field) |
| `timestamp_desc` | Meaning of the timestamp |
| `message` | Human-readable event summary |
| `data_type` | Taxonomy value: `<source>:<category>:<event>` |
| `timestamp` | Unix microseconds since epoch |
| `source` | Path to the input file/directory |
| `src_ip` | The IP that originated the event (client/caller/connection initiator) |
| `dst_ip` | The IP the event was directed at, when the source identifies one |

A converter that reads its address out of a field whose format does not
guarantee one (Apache/nginx `%h`, CloudTrail's `sourceIPAddress`) leaves
`src_ip` empty rather than putting a non-address there, and keeps the raw
token in a column of its own (`client_host`, `sourceIPAddress`). Discarding
it would leave the row with no record at all of who made the request.

`data_type` examples:

- `journal:entry:log`
- `browser:page:visit`
- `browser:download:start`
- `web:access:request`
- `web:error:log`
- `web:redirect:request`
- `cloudtrail:management:event`
- `cloudtrail:data:event`
- `firewall:filterlog:block`
- `firewall:filterlog:pass`
- `network:packet:tcp`
- `network:packet:udp`
- `network:packet:icmp`
- `network:packet:arp`
- `network:http:transaction`
- `cowrie:session:connect`
- `cowrie:login:failed`
- `cowrie:command:input`
- `cowrie:direct-tcpip:data`
- `webhoneypot:http:request`
- `syslog:sshd:login_failed`
- `syslog:sudo:command`
- `syslog:account:user_created`
- `syslog:generic:message`
- `winevtx:logon:success`
- `winevtx:process:create`
- `winevtx:service:installed`
- `winevtx:event:<event_id>` (unmapped event IDs)
- `zeek:conn:connection`
- `zeek:dns:query`
- `zeek:http:request`
- `zeek:ssl:connection`
- `zeek:notice:alert`
- `zeek:<path>:log` (any other Zeek log type)

The Apache converter deliberately reuses the nginx converter's `web:*`
data_type values (`web:access:request`, `web:error:log`), so saved Timesketch
queries work across both web servers; rows are distinguished by the `source`
column and the Apache-specific extra columns.

### Splitting output files

Every converter can split its output into multiple files with `--split`,
which has two modes:

- **Number of parts** — `--split 4` distributes the rows evenly across 4
  files (sequential chunks of `ceil(total/4)` rows each).
- **Part size** — `--split 4M` rotates to a new file whenever the current
  part reaches the given size. The suffixes `K`, `M`, and `G` mean
  KiB/MiB/GiB (1024-based; `4M` = 4 MiB), and explicit `KiB`/`MiB`/`GiB`
  spellings are accepted as well. Rows are never divided across parts, so a
  part may exceed the size limit by up to one row.

Rules that apply to both modes:

- `-o/--output` must be a file path — stdout cannot be split.
- Parts are named by inserting a counter before the extension:
  `-o output.csv` → `output.part001.csv`, `output.part002.csv`, …
- Every CSV part is a self-contained CSV file with its own header row; JSONL
  parts are plain line ranges. Each part can be imported into Timesketch on
  its own.
- Parts that would end up empty are not created.
- With nginx/apache `--output-dir`, splitting applies to each generated
  per-log-type file.
- With `--report`, every part file is listed individually in the audit
  report with its own SHA-256 hash.

```bash
# Split a large timeline into 4 parts with an equal number of rows
python3 suricata2timesketch.py -i /var/log/suricata/eve.json -o suricata.csv --split 4

# Rotate to a new file every 256 MiB
python3 pcap2timesketch.py -i /captures/ -o capture.jsonl -f jsonl --split 256M
```

## Entity taxonomy

Field names for the same real-world entity are kept identical across every
converter, so a Timesketch query or a saved view works unchanged regardless
of which source produced the event. The naming follows the role-based
attribute convention used by [MISP](https://www.misp-project.org/)'s network
objects (`ip-src`/`ip-dst`, `src-port`/`dst-port`): a *source* and a
*destination* role rather than source-specific names like
`remote_addr` or `client_ip`. MISP's attribute names use hyphens; this suite
uses `snake_case` instead so every column name is a valid CSV header and
Python identifier, but the semantic split (`src_*` = originator, `dst_*` =
recipient) is the same one MISP uses.

| Concept | Column(s) | Used by |
|---|---|---|
| IP address | `src_ip`, `dst_ip` | journal, browser, nginx, CloudTrail, filterlog, HAProxy, Suricata, pcap, Cowrie, webhoneypot, syslog, Apache, EVTX, Zeek |
| Port | `src_port`, `dst_port` | filterlog, HAProxy (`src_port` only), Suricata, pcap, Cowrie, syslog, Apache (error `[client ip:port]`), EVTX, Zeek |
| MAC address | `src_mac`, `dst_mac` | pcap |
| Hostname/domain | `host` | browser, EVTX (`Computer`), Zeek (`http.log`) |
| URL | `url` | browser, Suricata (`http` events), Zeek (`http.log`: `host` + `uri`) |
| User agent | `user_agent` | nginx, CloudTrail, Suricata (`http` events), Apache, webhoneypot, Zeek (`http` events) |

Where a source's native field is a well-known, distinctly-cased key of its
own schema (CloudTrail's `sourceIPAddress`/`userAgent`), that raw column is
kept **as well as** the canonical `src_ip`/`user_agent` alias, so both the
original AWS field name and the cross-source query both work. Suricata's
EVE JSON nests HTTP fields as `http.url`/`http.http_user_agent`; those are
promoted (renamed, not duplicated) to the top-level `url`/`user_agent`
columns instead of being left under Suricata's own dotted names.

Any converter-specific field that does not fit one of these shared roles
(e.g. `icmp_destination_ip` — the destination address embedded inside an
ICMP error payload, distinct from the ICMP packet's own `dst_ip`, or
browser's many role-specific `*_url` columns such as `referrer_url`/
`opener_url`/`tab_url`, which each carry a distinct meaning within a single
row) keeps its source-native name rather than being forced into the shared
taxonomy. Cowrie already emits `src_ip`/`dst_ip`/`src_port`/`dst_port`/
`protocol` under those exact names, so those are promoted as-is; its
honeypot-specific fields (`session`, `username`, `password`, `input`,
`hassh`, ...) keep their native names since they don't map onto any shared
role.

## IP address convention

Every converter agrees on the same two columns for IP addresses: `src_ip`
and `dst_ip`. Both are always single, canonicalized addresses (normalized
with Python's `ipaddress` module) — **never** a combined or pipe-separated
list. This is a deliberate design choice: a field like `"45.148.10.67 |
192.168.178.100"` cannot be filtered, grouped, or plotted by any timeseries
or graphing tool, whereas discrete `src_ip`/`dst_ip` columns can be used
directly for that purpose (e.g. "group events by `dst_ip`", "plot `src_ip`
over time").

A row leaves a column as an empty string (`""`) when that role does not
apply, or cannot be determined, for that event. Sources that can only
observe one side of a connection populate one column and leave the other
empty; sources with no real network connection (e.g. browser history) fall
back to a best-effort, single-address heuristic. No column ever contains
more than one address.

| Source | `src_ip` | `dst_ip` |
|---|---|---|
| journal | First IP literal found in the log message (the remote peer connecting to this host, e.g. `sshd` auth failures) | — (always empty; journal entries have no destination concept) |
| browser | — (always empty; the browser is always the local client) | First IP literal found in the visited URL / related URL fields (the remote resource the browser connected to) |
| nginx access/redirect | The client address (`$remote_addr`), when the logged token really is one. A comma-joined `X-Forwarded-For` chain logged in that slot yields its leftmost entry (the original client); the whole token is always kept in `client_host`. A `log_format` that prepends the virtual host (`$server_name $remote_addr …`, with or without the `-` ident slot) is recognised by which reading puts an address in the client slot; the vhost goes to `vhost` (Apache: `%v`/`%v:%p` the same way) | — (nginx logs don't record the server's own address) |
| nginx error | The client address parsed from `client: ...`, when present | — |
| CloudTrail | `sourceIPAddress`, only when it is a literal IP (AWS service principals populate this with a DNS name instead, e.g. `config.amazonaws.com` — in that case `src_ip` is empty and the raw value stays in the `sourceIPAddress` column) | — (CloudTrail records an AWS API endpoint, not a destination IP) |
| filterlog (firewall) | The packet's source address | The packet's destination address |
| HAProxy | The connecting client address; a `{...}` capture that is a bare IP (the usual `X-Forwarded-For` capture) is additionally exposed as `client_real_ip` | — (HAProxy names a backend *server*, not an address) |
| pcap | The packet's source address | The packet's destination address |
| Cowrie | The connecting client address (`src_ip`, as emitted natively by Cowrie) | The honeypot's own address for `session.connect`, or the forwarding target for `direct-tcpip.*` events; empty for events with no destination concept (logins, commands, TTY log closure) |
| webhoneypot | The effective client address: first valid IP from `X-Real-Ip` / `X-Forwarded-For`, falling back to the socket peer (`sip`). The raw socket peer is always kept in `socket_src_ip` | The honeypot's own address (`dip`) |
| syslog | The remote peer address for sshd events; first IP literal in the message for generic rows | — (syslog entries have no destination concept) |
| Apache access | The client address (`%h`), when the logged token really is one. `%h` is documented as "remote hostname (**or** IP address)", so it is empty under `HostnameLookups On`; a comma-joined `X-Forwarded-For` chain logged in that slot yields its leftmost entry. Either way the whole token is kept in `client_host` | — (Apache logs don't record the server's own address) |
| Apache error | The client address from `[client ip:port]`, when present; the host token is kept in `client_host` even when it is a hostname | — |
| EVTX | The `IpAddress` EventData value (e.g. logon source workstation) | — (event logs record the local computer in `host`, not a destination IP) |
| Zeek | The connection originator (`id.orig_h`) | The connection responder (`id.resp_h`) |
| W3C (IIS/HTTPERR) | The client address (`c-ip`); a Windows scope/zone index is split off into `src_ip_zone` | The server address the request landed on (`s-ip`), with `dst_ip_zone` likewise |
| Exchange | The client address (`ClientIpAddress`) | The server address, when the log type records one |
| Squid access | The client address (a hostname under `log_fqdn` stays in `client_host` instead) | The upstream peer from `HIER_DIRECT/<peer>`, when it is a literal IP |
| Squid cache | First IP literal found in the message (typically a helper's connect target) | — (cache.log entries have no destination concept) |
| conntrackd | The originating tuple's source | The originating tuple's destination. The reply tuple is kept separately in `reply_src_ip`/`reply_dst_ip`, and `translated_src_ip`/`translated_dst_ip` name the NATted addresses |

Note that filterlog, pcap, Zeek, conntrackd, W3C, and Cowrie's
session/direct-tcpip events are the sources with both columns populated for a single event, because they're the
ones that observe a full network flow (packet-in vs. packet-out, or a
connection and its forwarding target). ICMP "destination unreachable" style
messages additionally carry an `icmp_destination_ip` column — the
destination address of the *original* packet embedded in the ICMP payload,
which is a distinct value from the ICMP packet's own `dst_ip` and is kept
separate rather than overloading it into `dst_ip`.

If you need to search across both roles at once in Timesketch (e.g. "any
event touching 45.148.10.67"), search `src_ip:45.148.10.67 OR
dst_ip:45.148.10.67` — Timesketch indexes every column, so this works
without a combined field.

The same `src_*`/`dst_*` role split applies to ports: filterlog and Suricata
both emit `src_port`/`dst_port` (never `source_port`/`destination_port` or
other source-specific spellings).

## Forensic audit reports

Every converter can write a JSON audit report with `--report <path>`. The
report captures:

- The current system time (UTC)
- Hostname and username of the analyst
- The exact command-line invocation
- SHA-256 hashes of all input files
- SHA-256 hashes of all output files (or the generated content hash when
  writing to stdout)
- Runtime statistics (row counts, browser type, filter parameters, etc.)

This produces a rigid audit trail for chain-of-custody documentation. Because
reports are plain JSON files, you can PGP-sign them after creation, e.g.:

```bash
gpg --detach-sign --armor -o report.json.asc report.json
```

### Example

```bash
python3 browser2timesketch.py \
    -i ~/.mozilla/firefox/abc123.default/places.sqlite \
    -o firefox.csv \
    --report firefox.csv.report.json
```

## Usage

### journal2timesketch

```bash
# Write CSV to stdout
python3 journal2timesketch.py /path/to/acquired/journal

# Write to file
python3 journal2timesketch.py /path/to/acquired/journal -o output.csv

# Filter by time range or boot
python3 journal2timesketch.py /path/to/acquired/journal \
    --since "2025-01-01 00:00:00" \
    --until "2025-01-02 00:00:00" \
    -o output.csv

python3 journal2timesketch.py /path/to/acquired/journal --boot 0 -o output.csv
```

### browser2timesketch

```bash
# Auto-detect browser type
python3 browser2timesketch.py -i ~/.mozilla/firefox/abc123.default/places.sqlite

# Specify browser and output
python3 browser2timesketch.py -b firefox -i places.sqlite -o firefox.csv

# Custom browser name (e.g. Brave, Edge)
python3 browser2timesketch.py --browser-name "Brave" -i ~/.config/BraveSoftware/Brave-Browser/Default/History
```

### nginx2timesketch

```bash
# Combined timeline from a directory of logs (default: stdout CSV)
python3 nginx2timesketch.py -i /var/log/nginx

# Filter by time range
python3 nginx2timesketch.py -i /var/log/nginx --since "2025-01-01T00:00:00" --until "2025-01-02T00:00:00"

# Split into one file per log type
python3 nginx2timesketch.py -i /var/log/nginx --output-dir ./output -f csv

# Single file JSONL
python3 nginx2timesketch.py -i /var/log/nginx/access.log -f jsonl -o access.jsonl
```

A directory is searched recursively and files are classified by name, so
per-vhost layouts (`<vhost>/access.log`, `<vhost>.access.log`) are found. Fields
a custom `log_format` appends after the user agent beyond the first
(`additional_field`) are kept verbatim in `trailing_fields`; the run summary and
the audit report count those rows, the vhost-prefixed rows and every line that
matched no format. Input must be a file, directory or glob (relative or
absolute); a pipe such as `/dev/stdin` is refused, since the input is read more
than once.

### cloudtrail2timesketch

```bash
# Recursively process a CloudTrail archive (default: stdout CSV)
python3 cloudtrail2timesketch.py -i /path/to/CloudTrail

# Write to file with verbose progress
python3 cloudtrail2timesketch.py -i /path/to/CloudTrail -o cloudtrail.csv -v

# Filter by event time range and write JSONL
python3 cloudtrail2timesketch.py -i /path/to/CloudTrail \
    --since "2026-06-01T00:00:00Z" \
    --until "2026-06-18T00:00:00Z" \
    -f jsonl -o cloudtrail.jsonl

# Generate an audit report
python3 cloudtrail2timesketch.py -i /path/to/CloudTrail -o cloudtrail.csv \
    --report cloudtrail.csv.report.json
```

### filterlog2timesketch

```bash
# Convert an OPNsense export or raw pfSense filterlog file (default: stdout CSV)
python3 filterlog2timesketch.py -i /path/to/filter.log

# Write to file with verbose progress
python3 filterlog2timesketch.py -i /path/to/filter.log -o filterlog.csv -v

# Filter by event time range and write JSONL
python3 filterlog2timesketch.py -i /path/to/filter.log \
    --since "2026-07-01T00:00:00Z" \
    --until "2026-07-01T23:59:59Z" \
    -f jsonl -o filterlog.jsonl

# Raw pfSense BSD syslog timestamps omit the year; supply it explicitly
python3 filterlog2timesketch.py -i /var/log/filter.log --year 2026 -o filterlog.csv

# Generate an audit report
python3 filterlog2timesketch.py -i /path/to/filter.log -o filterlog.csv \
    --report filterlog.csv.report.json
```

### haproxy2timesketch

```bash
# Convert a HAProxy log (plain or .gz; default: stdout CSV)
python3 haproxy2timesketch.py -i /var/log/haproxy.log

# A directory of rotated logs, or a Docker json-file log
python3 haproxy2timesketch.py -i /var/log/haproxy/ -o haproxy.csv -v
python3 haproxy2timesketch.py -i /var/lib/docker/containers/<id>/<id>-json.log -o haproxy.csv

# Filter by event time range and write JSONL
python3 haproxy2timesketch.py -i /var/log/haproxy.log \
    --since "2026-07-01T00:00:00Z" \
    --until "2026-07-01T23:59:59Z" \
    -f jsonl -o haproxy.jsonl

# Startup/reload lines behind a BSD syslog prefix carry no year; supply it
python3 haproxy2timesketch.py -i /var/log/haproxy.log --year 2026 -o haproxy.csv

# Generate an audit report (records the measured clock skew, see below)
python3 haproxy2timesketch.py -i /var/log/haproxy.log -o haproxy.csv \
    --report haproxy.csv.report.json
```

HAProxy's `accept_date` carries no UTC offset, so it never sets the timestamp
when a UTC-anchored clock is available: a Docker envelope's RFC 3339 `time`
wins, `accept_date` is the fallback, and a syslog prefix plus `--year` is the
last resort. Which one a row used is recorded in its `timestamp_desc`, and
`accept_date` always survives verbatim in `haproxy_accept_date`.

Rather than assert that the source ran UTC, the converter measures it. The
smallest observed `envelope_clock - accept_date` skew is reported in the run
summary and in the `--report` JSON; a whole-hour value is the tell that the
proxy was logging local time. The *smallest* is the figure that matters
because the difference is session duration plus write latency — HAProxy stamps
`accept_date` when a session begins and logs it when it ends, so a tarpit or a
slow backend inflates every other statistic while the clocks stay aligned.

A startup/reload line or an unmodeled shape in a bare envelope has no clock at
all. Rather than drop it, the converter anchors it to its nearest dated
neighbour and says so: `timestamp_inferred` is `true`, `timestamp_desc` names
which neighbour it borrowed from, and the summary counts the affected rows.

### suricata2timesketch

```bash
# Convert a Suricata log (EVE JSON, fast.log, or OPNsense syslog export)
python3 suricata2timesketch.py -i /var/log/suricata/eve.json

# Convert an OPNsense syslog export
python3 suricata2timesketch.py -i /path/to/suricata.log -o suricata.csv -v

# Filter by event time range and write JSONL
python3 suricata2timesketch.py -i /var/log/suricata/eve.json \
    --since "2026-07-01T00:00:00Z" \
    --until "2026-07-01T23:59:59Z" \
    -f jsonl -o suricata.jsonl

# Generate an audit report
python3 suricata2timesketch.py -i /var/log/suricata/eve.json -o suricata.csv \
    --report suricata.csv.report.json
```

### pcap2timesketch

```bash
# Convert a single capture (pcap or pcapng, default: stdout CSV)
python3 pcap2timesketch.py -i /path/to/capture.pcap

# Recursively find every capture under a directory and merge them into one
# globally time-sorted timeline
python3 pcap2timesketch.py -i /path/to/captures/ -o combined.csv -v

# Filter by packet time range and write JSONL
python3 pcap2timesketch.py -i /path/to/capture.pcapng \
    --since "2026-07-01T00:00:00Z" \
    --until "2026-07-01T23:59:59Z" \
    -f jsonl -o capture.jsonl

# Generate an audit report
python3 pcap2timesketch.py -i /path/to/capture.pcap -o capture.csv \
    --report capture.csv.report.json

# Additionally reassemble HTTP/1.x transactions from the TCP streams
python3 pcap2timesketch.py -i /path/to/capture.pcap -o capture.csv \
    --reassemble http
```

#### HTTP reassembly (`--reassemble http`)

Off by default. When enabled, the converter reassembles the TCP streams and
emits one extra `network:http:transaction` row per HTTP/1.x request/response
pair, **in addition to** the per-packet rows — never instead of them. The
packet rows stay the forensic floor: a capture converted with and without the
flag yields the same packet rows, and every transaction row carries
`reassembled=true` so the two kinds are never confused.

Transaction row fields: `http_method`, `http_uri`, `http_protocol`,
`http_request_full`, `http_request_bytes`, `http_request_body_bytes`,
`status_code`, `http_status_reason`, `http_response_bytes`,
`http_response_body_bytes`, `http_content_encoding`,
`http_response_body_decoded_bytes` (gzip/deflate, or
`http_response_body_decode_failed=true`), `http_transaction_index` (position
within its connection), `packet_count`, `duration_ms`. The row is stamped with
the capture time of the request's first captured byte, and `src_ip`/`src_port`
are always the client, `dst_ip`/`dst_port` always the server.

Anything the capture could not fully support is flagged rather than hidden:
`http_incomplete`, `http_request_missing`, `http_response_missing`,
`reassembly_gap` (a hole in the stream was skipped), and
`reassembly_truncated_capture` (snaplen shorter than the frame).

Limits, by design:

- Cleartext HTTP/1.0 and HTTP/1.1 only. HTTPS is not decrypted, so most
  real-world traffic yields nothing; HTTP/2 and HTTP/3 are not parsed (binary
  framing plus HPACK/QPACK).
- A capture recording only one direction, or taken with a snaplen shorter than
  the frames, produces incomplete transactions or none at all.
- Bodies are measured, not stored — no payload bytes ever reach the timeline.
- Every enabled capture file is read a second time (the derived rows are
  produced at response-completion time and must be sorted back into timestamp
  order before the global merge).
- Hostile inputs bound the run rather than abort it: per-flow ceilings on
  buffered stream bytes, header size, body size, decompressed size, pending
  out-of-order segments and unanswered requests. Exceeding one kills that flow
  only — its packet rows still get written.

### cowrie2timesketch

```bash
# Convert a single cowrie.json file (default: stdout CSV)
python3 cowrie2timesketch.py -i /path/to/cowrie.json

# Recursively find every cowrie.json / rotated log under a directory
python3 cowrie2timesketch.py -i /var/log/cowrie/ -o cowrie.csv -v

# Filter by event time range and write JSONL
python3 cowrie2timesketch.py -i /path/to/cowrie.json \
    --since "2026-07-01T00:00:00Z" \
    --until "2026-07-01T23:59:59Z" \
    -f jsonl -o cowrie.jsonl

# Generate an audit report
python3 cowrie2timesketch.py -i /path/to/cowrie.json -o cowrie.csv \
    --report cowrie.csv.report.json
```

### webhoneypot2timesketch

```bash
# Convert a single webhoneypot log file (default: stdout CSV)
python3 webhoneypot2timesketch.py -i /path/to/webhoneypot_2026-07-13.json

# Recursively find every webhoneypot_*.json under a directory
python3 webhoneypot2timesketch.py -i /srv/log/ -o webhoneypot.csv -v

# Filter by event time range and write JSONL
python3 webhoneypot2timesketch.py -i /srv/log/ \
    --since "2026-07-01T00:00:00Z" \
    --until "2026-07-01T23:59:59Z" \
    -f jsonl -o webhoneypot.jsonl

# Generate an audit report
python3 webhoneypot2timesketch.py -i /srv/log/ -o webhoneypot.csv \
    --report webhoneypot.csv.report.json
```

Besides the raw `http_uri`, `http_data` and `http_headers` (compact JSON)
columns, each row carries granular hunt columns:

- **Promoted headers** — `http_accept`, `http_accept_encoding`,
  `http_accept_language`, `http_authorization`, `http_connection`,
  `http_content_length`, `http_content_type`, `http_cookie`, `http_origin`,
  `http_x_forwarded_for` (case-insensitive lookup; the full header dict
  stays in `http_headers`)
- **URL split** — `url_path`, `url_query` (kept percent-encoded),
  `url_query_params` (sorted unique parameter names), and
  `url_fetch_target`: the percent-decoded value of the first SSRF-style
  parameter (`url`, `uri`, `path`, `dest`, `destination`, `redirect`,
  `target`, `next`, `fetch`) — e.g. cloud-metadata SSRF probes like
  `/fetch?url=http%3A%2F%2F169.254.169.254%2F...` become directly huntable
- **JSON-RPC / MCP bodies** — when the request body is a JSON object:
  `jsonrpc_version`, `jsonrpc_method`, and for Model Context Protocol
  handshakes `mcp_protocol_version`, `mcp_client_name`,
  `mcp_client_version` (e.g. `POST /mcp` `initialize` scans)

### syslog2timesketch

```bash
# Convert a single auth.log (default: stdout CSV)
python3 syslog2timesketch.py -i /var/log/auth.log

# Recursively find auth.log/secure/syslog/messages/cron.log (incl. rotated
# and .gz) under a directory
python3 syslog2timesketch.py -i /var/log -o syslog.csv -v

# BSD syslog timestamps omit the year; supply it explicitly for archives
python3 syslog2timesketch.py -i /path/to/auth.log --year 2025 -o auth.csv

# Only recognized events (sshd, sudo, su, cron, logind, account changes),
# skipping generic syslog messages
python3 syslog2timesketch.py -i /var/log/auth.log --matched-only -o auth.csv

# Filter by event time range and write JSONL
python3 syslog2timesketch.py -i /var/log/auth.log \
    --since "2026-07-01T00:00:00Z" \
    --until "2026-07-01T23:59:59Z" \
    -f jsonl -o auth.jsonl

# Generate an audit report
python3 syslog2timesketch.py -i /var/log/auth.log -o auth.csv \
    --report auth.csv.report.json
```

### apache2timesketch

```bash
# Combined timeline from a directory of logs (default: stdout CSV)
python3 apache2timesketch.py -i /var/log/apache2

# Split into one file per log type
python3 apache2timesketch.py -i /var/log/apache2 --output-dir ./output -f csv

# Single file JSONL, filtered by time range
python3 apache2timesketch.py -i /var/log/apache2/access.log \
    --since "2026-07-01T00:00:00Z" \
    --until "2026-07-01T23:59:59Z" \
    -f jsonl -o access.jsonl

# Generate an audit report
python3 apache2timesketch.py -i /var/log/apache2 -o apache.csv \
    --report apache.csv.report.json
```

### evtx2timesketch

Binary `.evtx` files are not read directly (the suite is standard-library
only). Export them first:

```
# On Windows:
wevtutil qe Security /f:xml > security.xml

# Anywhere, with evtx_dump (https://github.com/omerbenamram/evtx):
evtx_dump -o jsonl -f security.jsonl Security.evtx
```

```bash
# Convert an XML or JSONL export (format auto-detected; default: stdout CSV)
python3 evtx2timesketch.py -i security.xml

# Recursively convert every .xml/.jsonl/.json export under a directory
python3 evtx2timesketch.py -i /path/to/exports -o events.csv -v

# Only specific event IDs (e.g. logons and logon failures)
python3 evtx2timesketch.py -i security.xml --event-ids 4624,4625 -o logons.csv

# Filter by event time range and write JSONL
python3 evtx2timesketch.py -i security.jsonl \
    --since "2026-07-01T00:00:00Z" \
    --until "2026-07-01T23:59:59Z" \
    -f jsonl -o events.jsonl

# Generate an audit report
python3 evtx2timesketch.py -i security.xml -o events.csv \
    --report events.csv.report.json
```

### zeek2timesketch

```bash
# Merge every Zeek log in a directory into one time-sorted timeline
# (default: stdout CSV; .log.gz and rotated logs included)
python3 zeek2timesketch.py -i /opt/zeek/logs/current

# Split into one file per Zeek log type (timesketch_conn.csv, ...)
python3 zeek2timesketch.py -i /opt/zeek/logs/ --output-dir ./output -f csv

# Filter by event time range and write JSONL
python3 zeek2timesketch.py -i /opt/zeek/logs/current \
    --since "2026-07-01T00:00:00Z" \
    --until "2026-07-01T23:59:59Z" \
    -f jsonl -o zeek.jsonl

# Generate an audit report
python3 zeek2timesketch.py -i /opt/zeek/logs/current -o zeek.csv \
    --report zeek.csv.report.json
```

The Zeek parser is generic: it reads the `#fields`/`#types`/`#path` headers
of each file, so any Zeek log type — including custom scripts — is converted
without a built-in schema. The connection 4-tuple (`id.orig_h`/`id.resp_h`/
`id.orig_p`/`id.resp_p`) is promoted onto the shared `src_ip`/`dst_ip`/
`src_port`/`dst_port` columns, http.log's `host`+`uri` become `host`/`url`,
and every other field keeps its Zeek-native name.

## Repository layout

```
2timesketch/
├── README.md
├── LICENSE
├── journal2timesketch.py      # journal CLI wrapper
├── browser2timesketch.py      # browser CLI wrapper
├── nginx2timesketch.py        # nginx CLI wrapper
├── cloudtrail2timesketch.py   # CloudTrail CLI wrapper
├── filterlog2timesketch.py    # pfSense/OPNsense filterlog CLI wrapper
├── haproxy2timesketch.py      # HAProxy CLI wrapper
├── suricata2timesketch.py     # Suricata IDS/IPS CLI wrapper
├── pcap2timesketch.py         # pcap/pcapng CLI wrapper
├── cowrie2timesketch.py       # Cowrie honeypot CLI wrapper
├── webhoneypot2timesketch.py  # DShield webhoneypot CLI wrapper
├── syslog2timesketch.py       # Linux syslog/auth.log CLI wrapper
├── apache2timesketch.py       # Apache CLI wrapper
├── evtx2timesketch.py         # Windows event log export CLI wrapper
├── zeek2timesketch.py         # Zeek NSM log CLI wrapper
├── w3c2timesketch.py          # IIS / HTTPERR / W3C Extended CLI wrapper
├── exchange2timesketch.py     # Exchange protocol log CLI wrapper
├── squid2timesketch.py        # Squid proxy log CLI wrapper
├── conntrackd2timesketch.py   # conntrackd flow log CLI wrapper
└── timesketch_converters/
    ├── __init__.py
    ├── common.py              # shared helpers
    ├── journal.py             # journal converter core
    ├── browser.py             # browser converter core
    ├── nginx.py               # nginx converter core
    ├── cloudtrail.py          # CloudTrail converter core
    ├── filterlog.py           # filterlog converter core
    ├── haproxy.py             # HAProxy converter core
    ├── suricata.py            # Suricata converter core
    ├── pcap.py                # pcap/pcapng converter core
    ├── cowrie.py              # Cowrie converter core
    ├── webhoneypot.py         # DShield webhoneypot converter core
    ├── syslog.py              # syslog/auth.log converter core
    ├── apache.py              # Apache converter core
    ├── evtx.py                # Windows event log export converter core
    ├── zeek.py                # Zeek NSM log converter core
    ├── w3c.py                 # W3C Extended (IIS/HTTPERR) converter core
    ├── exchange.py            # Exchange protocol log converter core
    ├── squid.py               # Squid proxy log converter core
    └── conntrackd.py          # conntrackd flow log converter core
```

### w3c2timesketch

```bash
# An IIS log root: every W3SVC<n>/ site directory plus HTTPERR, searched recursively
python3 w3c2timesketch.py -i C:/inetpub/logs/LogFiles -o iis.csv

# One timeline file per flavor (iis, httperr, w3c)
python3 w3c2timesketch.py -i ./LogFiles --output-dir ./output -f csv

# A single file, JSONL, narrowed to one day
python3 w3c2timesketch.py -i u_ex260101.log -f jsonl -o day1.jsonl \
    --since 2026-01-01T00:00:00Z --until 2026-01-01T23:59:59Z
```

### exchange2timesketch

```bash
# The HttpProxy tree: one directory per front-end protocol
python3 exchange2timesketch.py -i "C:/Program Files/Microsoft/Exchange Server/V15/Logging/HttpProxy" -o proxy.csv

# One timeline per protocol directory
python3 exchange2timesketch.py -i ./HttpProxy --output-dir ./output
```

### squid2timesketch

```bash
# access.log, cache.log and icap.log together, with rotated/gzipped parts
python3 squid2timesketch.py -i /var/log/squid -o squid.csv

# cache.log timestamps carry no offset; name the appliance's timezone
python3 squid2timesketch.py -i /var/log/squid --assume-tz +02:00 -o squid.csv
```

### conntrackd2timesketch

```bash
python3 conntrackd2timesketch.py -i /var/log/conntrackd-stats.log \
    --assume-tz +02:00 -o flows.csv
```

## Importing into Timesketch

1. Open or create a sketch.
2. Click **Upload timeline** → **CSV file**.
3. Select the generated CSV. Timesketch auto-detects `datetime`, `timestamp_desc`, and `message`.
4. Additional columns become searchable attributes on each event.

## License

MIT
