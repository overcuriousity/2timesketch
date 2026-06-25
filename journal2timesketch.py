#!/usr/bin/env python3
"""CLI entry point for the systemd journal to Timesketch converter."""

from __future__ import annotations

import argparse
import sys

from timesketch_converters.common import ConverterError, add_report_arg
from timesketch_converters.journal import convert_journal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert a systemd journal directory to a Timesketch-compatible timeline."
    )
    parser.add_argument(
        "journal_dir",
        nargs="?",
        help="Path to the journal directory (passed to journalctl -D).",
    )
    parser.add_argument(
        "-i",
        "--input",
        dest="journal_dir_alt",
        help="Alternative to the positional journal_dir argument.",
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
        default=None,
        help="Only entries after this timestamp (journalctl --since format).",
    )
    parser.add_argument(
        "--until",
        default=None,
        help="Only entries before this timestamp (journalctl --until format).",
    )
    parser.add_argument(
        "--boot",
        default=None,
        help="Limit to a specific boot ID or offset (journalctl -b format).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print progress messages to stderr.",
    )
    add_report_arg(parser)

    args = parser.parse_args(argv)

    journal_dir = args.journal_dir or args.journal_dir_alt
    if not journal_dir:
        parser.error("the following arguments are required: journal_dir (or use -i/--input)")

    try:
        convert_journal(
            journal_dir=journal_dir,
            output=args.output,
            output_format=args.format,
            since=args.since,
            until=args.until,
            boot=args.boot,
            verbose=args.verbose,
            report_path=args.report,
            command_line=sys.argv,
        )
    except ConverterError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
