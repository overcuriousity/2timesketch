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
- **Suricata IDS/IPS logs** (`suricata2timesketch.py`) — EVE JSON, fast.log, and OPNsense syslog exports
- **Packet captures** (`pcap2timesketch.py`) — pcap and pcapng files from
  Wireshark/tcpdump, decoded to Ethernet/Linux-SLL/raw-IP, IPv4/IPv6, and
  TCP/UDP/ICMP/ARP headers
- **Cowrie SSH/Telnet honeypot logs** (`cowrie2timesketch.py`) — `cowrie.json`
  session, auth, command, client fingerprint, direct-tcpip, and TTY log events
- **Linux syslog/auth.log** (`syslog2timesketch.py`) — plain-text RFC 3164
  syslog files (auth.log, secure, syslog, messages, cron.log) with structured
  extraction of sshd, sudo, su, cron, systemd-logind, and account-management
  events
- **Apache HTTP Server logs** (`apache2timesketch.py`) — access (combined and
  common/CLF format, incl. `other_vhosts_access.log`) and error logs (2.4 and
  2.2 formats)
- **Windows event log exports** (`evtx2timesketch.py`) — XML exports from
  `wevtutil qe /f:xml` or `evtx_dump`, and JSONL exports from
  `evtx_dump -o jsonl` (binary `.evtx` must be exported first)

## Requirements

- Python 3.9+
- Standard library only — no third-party packages required
- `journalctl` (systemd) is required for the journal converter

## Common conventions

All converters share:

- A uniform CLI (`-i/--input`, `-o/--output`, `-f/--format`, `-v/--verbose`, `--report`, `--no-color`).
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
- `cowrie:session:connect`
- `cowrie:login:failed`
- `cowrie:command:input`
- `cowrie:direct-tcpip:data`
- `syslog:sshd:login_failed`
- `syslog:sudo:command`
- `syslog:account:user_created`
- `syslog:generic:message`
- `winevtx:logon:success`
- `winevtx:process:create`
- `winevtx:service:installed`
- `winevtx:event:<event_id>` (unmapped event IDs)

The Apache converter deliberately reuses the nginx converter's `web:*`
data_type values (`web:access:request`, `web:error:log`), so saved Timesketch
queries work across both web servers; rows are distinguished by the `source`
column and the Apache-specific extra columns.

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
| IP address | `src_ip`, `dst_ip` | journal, browser, nginx, CloudTrail, filterlog, Suricata, pcap, Cowrie, syslog, Apache, EVTX |
| Port | `src_port`, `dst_port` | filterlog, Suricata, pcap, Cowrie, syslog, Apache (error `[client ip:port]`), EVTX |
| MAC address | `src_mac`, `dst_mac` | pcap |
| Hostname/domain | `host` | browser, EVTX (`Computer`) |
| URL | `url` | browser, Suricata (`http` events) |
| User agent | `user_agent` | nginx, CloudTrail, Suricata (`http` events), Apache |

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
| nginx access/redirect | The client address (`$remote_addr`) | — (nginx logs don't record the server's own address) |
| nginx error | The client address parsed from `client: ...`, when present | — |
| CloudTrail | `sourceIPAddress`, only when it is a literal IP (AWS service principals populate this with a DNS name instead, e.g. `config.amazonaws.com` — in that case `src_ip` is empty and the raw value stays in the `sourceIPAddress` column) | — (CloudTrail records an AWS API endpoint, not a destination IP) |
| filterlog (firewall) | The packet's source address | The packet's destination address |
| pcap | The packet's source address | The packet's destination address |
| Cowrie | The connecting client address (`src_ip`, as emitted natively by Cowrie) | The honeypot's own address for `session.connect`, or the forwarding target for `direct-tcpip.*` events; empty for events with no destination concept (logins, commands, TTY log closure) |
| syslog | The remote peer address for sshd events; first IP literal in the message for generic rows | — (syslog entries have no destination concept) |
| Apache access | The client address (`%h`, empty when HostnameLookups logs a hostname instead) | — (Apache logs don't record the server's own address) |
| Apache error | The client address from `[client ip:port]`, when present | — |
| EVTX | The `IpAddress` EventData value (e.g. logon source workstation) | — (event logs record the local computer in `host`, not a destination IP) |

Note that filterlog, pcap, and Cowrie's session/direct-tcpip events are the
sources with both columns populated for a single event, because they're the
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
```

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
├── suricata2timesketch.py     # Suricata IDS/IPS CLI wrapper
├── pcap2timesketch.py         # pcap/pcapng CLI wrapper
├── cowrie2timesketch.py       # Cowrie honeypot CLI wrapper
├── syslog2timesketch.py       # Linux syslog/auth.log CLI wrapper
├── apache2timesketch.py       # Apache CLI wrapper
├── evtx2timesketch.py         # Windows event log export CLI wrapper
└── timesketch_converters/
    ├── __init__.py
    ├── common.py              # shared helpers
    ├── journal.py             # journal converter core
    ├── browser.py             # browser converter core
    ├── nginx.py               # nginx converter core
    ├── cloudtrail.py          # CloudTrail converter core
    ├── filterlog.py           # filterlog converter core
    ├── suricata.py            # Suricata converter core
    ├── pcap.py                # pcap/pcapng converter core
    ├── cowrie.py              # Cowrie converter core
    ├── syslog.py              # syslog/auth.log converter core
    ├── apache.py              # Apache converter core
    └── evtx.py                # Windows event log export converter core
```

## Importing into Timesketch

1. Open or create a sketch.
2. Click **Upload timeline** → **CSV file**.
3. Select the generated CSV. Timesketch auto-detects `datetime`, `timestamp_desc`, and `message`.
4. Additional columns become searchable attributes on each event.

## License

MIT
