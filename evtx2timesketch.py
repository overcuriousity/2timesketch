#!/usr/bin/env python3
"""CLI entry point for the Windows event log export to Timesketch converter."""

from __future__ import annotations

import argparse
import sys

from timesketch_converters.common import ConverterError, add_no_color_arg, add_report_arg
from timesketch_converters.evtx import convert_evtx
from timesketch_converters.terminal import get_terminal


def _parse_event_ids(value: str) -> set[int]:
    """Parse a comma-separated event ID list (e.g. "4624,4625")."""
    ids: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ids.add(int(part))
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid event ID: {part!r}")
    if not ids:
        raise argparse.ArgumentTypeError("no event IDs given")
    return ids


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert Windows event log exports (XML from 'wevtutil qe "
                    "/f:xml', XML/JSONL from 'evtx_dump') to a "
                    "Timesketch-compatible timeline. Binary .evtx files must "
                    "be exported first."
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to an event log export file (.xml/.jsonl/.json, plain or "
             ".gz) or a directory containing them.",
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
        "--input-format",
        choices=["auto", "xml", "jsonl"],
        default="auto",
        help="Export format of the input files (default: auto-detect).",
    )
    parser.add_argument(
        "--event-ids",
        type=_parse_event_ids,
        help="Only convert these event IDs (comma-separated, e.g. 4624,4625).",
    )
    parser.add_argument(
        "--since",
        help="Only entries at or after this ISO 8601 timestamp "
             "(e.g. 2026-07-01T00:00:00Z).",
    )
    parser.add_argument(
        "--until",
        help="Only entries at or before this ISO 8601 timestamp "
             "(e.g. 2026-07-01T23:59:59Z).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print progress messages to stderr.",
    )
    add_report_arg(parser)
    add_no_color_arg(parser)

    args = parser.parse_args(argv)
    if args.no_color:
        get_terminal(force_color=False)

    try:
        convert_evtx(
            input_path=args.input,
            output=args.output,
            output_format=args.format,
            input_format=args.input_format,
            since=args.since,
            until=args.until,
            event_ids=args.event_ids,
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
