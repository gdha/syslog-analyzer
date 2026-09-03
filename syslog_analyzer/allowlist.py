"""User-configurable allowlist for suppressing false positives.

The allowlist file is a plain-text file with one regex pattern per line.
Blank lines and lines starting with '#' are ignored.

Default location: ~/.config/syslog-analyzer/allowlist.conf
Override via --allowlist CLI flag.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

DEFAULT_ALLOWLIST_PATH = Path.home() / ".config" / "syslog-analyzer" / "allowlist.conf"

# Shipped example content (written when user runs --allowlist-init)
_EXAMPLE_CONTENT = """\
# syslog-analyzer allowlist — one regex per line
# Lines starting with '#' and blank lines are ignored.
#
# Each pattern is matched case-insensitively against the full log line.
# If any pattern matches, the line is treated as benign (suppressed).
#
# Examples:
# my_custom_app.*starting up
# systemd-resolved.*Cache flush
# kernel:.*ACPI.*Thermal
"""


def load_allowlist(path: Path | None = None) -> list[str]:
    """Load user allowlist patterns from *path* (or the default location).

    Returns an empty list if the file does not exist.
    Raises SystemExit with a helpful message on syntax errors.
    """
    if path is None:
        path = DEFAULT_ALLOWLIST_PATH

    if not path.is_file():
        return []

    patterns: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Validate the regex early so users get clear feedback
            try:
                re.compile(line)
            except re.error as exc:
                print(
                    f"allowlist:{path}:{lineno}: invalid regex: {line!r} — {exc}",
                    file=sys.stderr,
                )
                sys.exit(1)
            patterns.append(line)

    return patterns


def init_allowlist(path: Path | None = None) -> Path:
    """Create the default allowlist file with example content.

    Returns the path that was written. Does not overwrite an existing file.
    """
    if path is None:
        path = DEFAULT_ALLOWLIST_PATH

    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(_EXAMPLE_CONTENT, encoding="utf-8")
    return path


def is_allowlisted(line: str, patterns: list[str]) -> bool:
    """Return True if *line* matches any user allowlist pattern."""
    return any(re.search(p, line, re.I) for p in patterns)
