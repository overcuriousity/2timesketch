#!/usr/bin/env python3
"""CLI entry point for the Suricata IDS/IPS log to Timesketch converter."""

from __future__ import annotations

import argparse
import sys

from timesketch_converters.common import ConverterError, add_no_color_arg, add_report_arg, add_split_arg
from timesketch_converters.suricata import convert_suricata
from timesketch_converters.terminal import get_terminal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert Suricata IDS/IPS logs (EVE JSON, fast.log, "
                    "OPNsense syslog export) to a Timesketch-compatible timeline."
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to a Suricata log file or directory.",
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
        help="Only records at or after this ISO 8601 timestamp "
             "(e.g. 2026-07-01T00:00:00Z).",
    )
    parser.add_argument(
        "--until",
        help="Only records at or before this ISO 8601 timestamp "
             "(e.g. 2026-07-01T23:59:59Z).",
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
        convert_suricata(
            input_path=args.input,
            output=args.output,
            output_format=args.format,
            since=args.since,
            until=args.until,
            verbose=args.verbose,
            split=args.split,
            report_path=args.report,
            command_line=sys.argv,
        )
    except ConverterError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
