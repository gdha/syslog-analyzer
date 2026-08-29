"""CLI entry point: python -m syslog_analyzer"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from syslog_analyzer.allowlist import (
    DEFAULT_ALLOWLIST_PATH,
    init_allowlist,
    load_allowlist,
)
from syslog_analyzer.analyzer import analyze_paths
from syslog_analyzer.logs import default_log_paths, resolve_log_paths
from syslog_analyzer.patterns import DEFAULT_LOG_PATHS
from syslog_analyzer.report import format_json, format_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="syslog-analyzer",
        description="Scan system logs for serious errors and security-related activity.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help=f"Log files to scan (default: {', '.join(DEFAULT_LOG_PATHS)})",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write report to FILE instead of stdout",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of human-readable text",
    )
    parser.add_argument(
        "--include-info",
        action="store_true",
        help="Include informational security events (e.g. successful SSH logins)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="low",
        help="Only report events at or above this severity (default: low)",
    )
    parser.add_argument(
        "--max-per-category",
        type=int,
        default=10,
        metavar="N",
        help="Max sample lines shown per category in text output (default: 10)",
    )
    parser.add_argument(
        "--no-rotated",
        action="store_true",
        help="Scan only the active log files, not rotated archives (.1, .2.gz, …)",
    )
    parser.add_argument(
        "--max-rotations",
        type=int,
        default=None,
        metavar="N",
        help="Limit rotated archives per log (e.g. 2 → active + .1 + .2.gz)",
    )
    parser.add_argument(
        "--allowlist",
        metavar="FILE",
        default=None,
        help=(
            "Path to a custom allowlist file with suppression patterns "
            f"(default: {DEFAULT_ALLOWLIST_PATH})"
        ),
    )
    parser.add_argument(
        "--allowlist-init",
        action="store_true",
        help="Create the default allowlist file with example content, then exit",
    )

    args = parser.parse_args(argv)

    # Handle --allowlist-init early exit
    if args.allowlist_init:
        created = init_allowlist()
        print(f"Allowlist file ready at: {created}")
        return 0

    # Load user allowlist patterns
    allowlist_path = Path(args.allowlist) if args.allowlist else None
    allowlist_patterns = load_allowlist(allowlist_path)

    include_rotated = not args.no_rotated

    if args.paths:
        paths = resolve_log_paths(
            args.paths,
            include_rotated=include_rotated,
            max_rotations=args.max_rotations,
        )
    else:
        paths = default_log_paths(
            include_rotated=include_rotated,
            max_rotations=args.max_rotations,
        )

    report = analyze_paths(
        paths,
        include_info=args.include_info,
        min_severity=args.min_severity,
        allowlist_patterns=allowlist_patterns,
    )

    if args.json:
        body = format_json(report)
    else:
        body = format_text(report, max_per_category=args.max_per_category)

    if args.output:
        Path(args.output).write_text(body + "\n", encoding="utf-8")
    else:
        print(body)

    if report.attack_indicators():
        return 2
    if report.highest_serious_severity() in ("critical", "high"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
