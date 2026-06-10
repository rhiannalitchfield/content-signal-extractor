"""
CLI for content-signal-extractor.

Usage:
    content-signals "Your text here"
    content-signals --file input.txt
    content-signals --file input.txt --format json
    content-signals --file input.txt --output report.txt
    content-signals --stdin
"""

from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from .extractor import extract
from .report import generate_report


def main():
    parser = argparse.ArgumentParser(
        prog="content-signals",
        description="Extract Trust & Safety signals from text.",
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("text", nargs="?", help="Text to analyze (inline)")
    input_group.add_argument("--file", "-f", help="Path to text file to analyze")
    input_group.add_argument("--stdin", action="store_true", help="Read text from stdin")

    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output", "-o", help="Write output to file path (default: stdout)",
    )
    parser.add_argument(
        "--no-preview", action="store_true",
        help="Omit text preview from report",
    )
    parser.add_argument(
        "--flags-only", action="store_true",
        help="Print only the flags list (useful for pipeline use)",
    )

    args = parser.parse_args()

    # ── Load input ────────────────────────────────────────────────────────
    if args.stdin:
        text = sys.stdin.read()
    elif args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: file not found: {path}", file=sys.stderr)
            sys.exit(1)
        text = path.read_text(encoding="utf-8")
    else:
        text = args.text

    if not text or not text.strip():
        print("Error: input text is empty.", file=sys.stderr)
        sys.exit(1)

    # ── Extract ───────────────────────────────────────────────────────────
    try:
        result = extract(text)
    except Exception as e:
        print(f"Error during extraction: {e}", file=sys.stderr)
        sys.exit(1)

    # ── Output ────────────────────────────────────────────────────────────
    if args.flags_only:
        output = "\n".join(result.flags) if result.flags else "NO_FLAGS"

    elif args.format == "json":
        output = json.dumps(result.to_dict(), indent=2)

    else:
        output = generate_report(
            result,
            text_preview=None if args.no_preview else text,
            output_path=args.output,
        )

    if args.output and args.format != "text":
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Output written to {args.output}")
    elif not args.output:
        print(output)


if __name__ == "__main__":
    main()
