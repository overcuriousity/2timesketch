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

## Requirements

- Python 3.9+
- Standard library only — no third-party packages required
- `journalctl` (systemd) is required for the journal converter

## Common conventions

All converters share:

- A uniform CLI (`-i/--input`, `-o/--output`, `-f/--format`, `-v/--verbose`, `--report`).
- CSV output by default (`-f jsonl` is also supported).
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

Note that filterlog is the only source with both columns populated for a
single event, because it is the only source that observes a full network
flow (packet-in vs. packet-out). ICMP "destination unreachable" style
messages additionally carry an `icmp_destination_ip` column — the
destination address of the *original* packet embedded in the ICMP payload,
which is a distinct value from the ICMP packet's own `dst_ip` and is kept
separate rather than overloading it into `dst_ip`.

If you need to search across both roles at once in Timesketch (e.g. "any
event touching 45.148.10.67"), search `src_ip:45.148.10.67 OR
dst_ip:45.148.10.67` — Timesketch indexes every column, so this works
without a combined field.

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
└── timesketch_converters/
    ├── __init__.py
    ├── common.py              # shared helpers
    ├── journal.py             # journal converter core
    ├── browser.py             # browser converter core
    ├── nginx.py               # nginx converter core
    ├── cloudtrail.py          # CloudTrail converter core
    └── filterlog.py           # filterlog converter core
```

## Importing into Timesketch

1. Open or create a sketch.
2. Click **Upload timeline** → **CSV file**.
3. Select the generated CSV. Timesketch auto-detects `datetime`, `timestamp_desc`, and `message`.
4. Additional columns become searchable attributes on each event.

## License

MIT
