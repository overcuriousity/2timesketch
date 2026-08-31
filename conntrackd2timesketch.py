#!/usr/bin/env python3
"""CLI entry point for the conntrackd flow log to Timesketch converter."""

from __future__ import annotations

import argparse
import sys

from timesketch_converters.common import (
    ConverterError,
    add_no_color_arg,
    add_report_arg,
    add_split_arg,
)
from timesketch_converters.conntrackd import convert_conntrackd
from timesketch_converters.terminal import get_terminal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert conntrackd flow logs (conntrackd-stats.log) to a "
            "Timesketch-compatible timeline, with both connection tuples and "
            "the address translation they imply."
        )
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Input file, directory, or glob pattern for conntrackd logs.",
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
        "--assume-tz",
        dest="assume_tz",
        metavar="TZ",
        help="Timezone for the ctime timestamps, which carry no offset: UTC "
             "(default), local, or an explicit offset such as +02:00.",
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
        convert_conntrackd(
            input_path=args.input,
            output=args.output,
            output_format=args.format,
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
