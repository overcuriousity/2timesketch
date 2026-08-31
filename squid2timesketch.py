#!/usr/bin/env python3
"""CLI entry point for the Squid proxy log to Timesketch converter."""

from __future__ import annotations

import argparse
import sys

from timesketch_converters.common import (
    ConverterError,
    add_no_color_arg,
    add_report_arg,
    add_split_arg,
)
from timesketch_converters.squid import convert_squid
from timesketch_converters.terminal import get_terminal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert Squid proxy access/cache/icap logs to a Timesketch-compatible timeline."
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Input file, directory, or glob pattern for Squid logs.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="Output file path for combined output (default: stdout).",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["csv", "jsonl"],
        default="csv",
        help="Output format (default: csv).",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        help="Write one timeline file per log type into this directory.",
    )
    parser.add_argument(
        "--assume-tz",
        dest="assume_tz",
        metavar="TZ",
        help="Timezone for timestamps that carry no offset (cache.log and the "
             "httpd-style access formats): UTC (default), local, or an "
             "explicit offset such as +02:00. access.log epoch timestamps are "
             "absolute and are never affected.",
    )
    parser.add_argument(
        "--since",
        help="Only entries at or after this ISO 8601 timestamp.",
    )
    parser.add_argument(
        "--until",
        help="Only entries at or before this ISO 8601 timestamp.",
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
        convert_squid(
            input_path=args.input,
            output=args.output,
            output_format=args.format,
            output_dir=args.output_dir,
            since=args.since,
            until=args.until,
            assume_tz=args.assume_tz,
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
