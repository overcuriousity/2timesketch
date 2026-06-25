#!/usr/bin/env python3
"""CLI entry point for the browser history to Timesketch converter."""

from __future__ import annotations

import argparse
import sys

from timesketch_converters.browser import convert_browser
from timesketch_converters.common import ConverterError, add_report_arg


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert ALL browser events to Timesketch CSV/JSONL format."
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to browser history SQLite database.",
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
        "-b",
        "--browser",
        choices=["auto", "gecko", "firefox", "chromium", "webkit", "safari"],
        default="auto",
        help="Browser engine type (default: auto-detect).",
    )
    parser.add_argument(
        "--browser-name",
        help='Custom browser name for the browser field (e.g., "Brave", "Edge").',
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print progress messages to stderr.",
    )
    add_report_arg(parser)

    args = parser.parse_args(argv)

    try:
        convert_browser(
            input_path=args.input,
            output=args.output,
            output_format=args.format,
            browser_type=args.browser,
            browser_name=args.browser_name,
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
