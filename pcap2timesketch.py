#!/usr/bin/env python3
"""CLI entry point for the pcap/pcapng to Timesketch converter."""

from __future__ import annotations

import argparse
import sys

from timesketch_converters.common import (
    ConverterError,
    add_no_color_arg,
    add_report_arg,
    add_split_arg,
)
from timesketch_converters.pcap import convert_pcap
from timesketch_converters.terminal import get_terminal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert pcap/pcapng packet captures to a "
                    "Timesketch-compatible timeline."
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to a pcap/pcapng file or a directory to search recursively.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="Output file path (default: stdout).",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["csv", "jsonl"],
        default="csv",
        help="Output format (default: csv).",
    )
    parser.add_argument(
        "--since",
        help="Only packets at or after this ISO 8601 timestamp "
             "(e.g. 2026-07-01T00:00:00Z).",
    )
    parser.add_argument(
        "--until",
        help="Only packets at or before this ISO 8601 timestamp "
             "(e.g. 2026-07-01T23:59:59Z).",
    )
    parser.add_argument(
        "--reassemble",
        choices=["http"],
        metavar="http",
        help="Also emit one derived network:http:transaction row per HTTP/1.x "
             "request/response, reassembled from the TCP streams. Packet rows "
             "are still emitted in full — transaction rows are added, never "
             "substituted. Limits: cleartext HTTP/1.0 and 1.1 only. HTTPS is "
             "not decrypted (so most real traffic yields nothing), HTTP/2 and "
             "HTTP/3 are not parsed (binary framing + HPACK/QPACK), and a "
             "capture taken with a snaplen shorter than the frame or recording "
             "only one direction cannot be reassembled — such transactions come "
             "out flagged incomplete or not at all. Each capture file is read a "
             "second time when this is enabled.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print progress messages to stderr.",
    )
    add_report_arg(parser)
    add_split_arg(parser)
    add_no_color_arg(parser)

    args = parser.parse_args(argv)
    if args.no_color:
        get_terminal(force_color=False)

    try:
        convert_pcap(
            input_path=args.input,
            output=args.output,
            output_format=args.format,
            since=args.since,
            until=args.until,
            verbose=args.verbose,
            split=args.split,
            reassemble=args.reassemble,
            report_path=args.report,
            command_line=sys.argv,
        )
    except ConverterError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
