"""Log path discovery and reading (including rotated and gzip-compressed files)."""

from __future__ import annotations

import gzip
import re
from pathlib import Path

from .patterns import DEFAULT_LOG_PATHS

# Debian-style: syslog.1, auth.log.2.gz
_ROTATED_NUMERIC_RE = re.compile(r"^(.+)\.(\d+)(\.gz)?$")
# RHEL-style (dateext): messages-20250608, messages-20250608.gz
_ROTATED_DATE_RE = re.compile(r"^(.+)-(\d{8})(\.gz)?$")


def is_rotated_name(name: str) -> bool:
    """True if filename looks like a rotated log archive."""
    return bool(_ROTATED_NUMERIC_RE.match(name) or _ROTATED_DATE_RE.match(name))


def base_log_name(path: Path) -> str:
    """Active log basename (syslog.3.gz → syslog, messages-20250608.gz → messages)."""
    for pattern in (_ROTATED_NUMERIC_RE, _ROTATED_DATE_RE):
        m = pattern.match(path.name)
        if m:
            return m.group(1)
    return path.name


def _rotation_sort_key(stem: str, path: Path) -> tuple[int, int]:
    """Lower key = newer. Active log uses (0, 0) when matched separately."""
    name = path.name
    m_num = re.match(rf"^{re.escape(stem)}\.(\d+)", name)
    if m_num:
        return (1, int(m_num.group(1)))
    m_date = re.match(rf"^{re.escape(stem)}-(\d{{8}})", name)
    if m_date:
        # Negate YYYYMMDD so newer dates sort before older ones.
        return (2, -int(m_date.group(1)))
    return (0, 0)


def discover_rotated(base: Path, *, max_rotations: int | None = None) -> list[Path]:
    """Return base log plus rotated siblings, newest first (active, then archives)."""
    if not base.name or base.name == "/":
        return []

    stem = base.name
    parent = base.parent
    found: list[Path] = []

    if base.is_file():
        found.append(base)

    if parent.is_dir():
        numeric_re = re.compile(rf"^{re.escape(stem)}\.(\d+)(\.gz)?$")
        date_re = re.compile(rf"^{re.escape(stem)}-(\d{{8}})(\.gz)?$")
        archives: list[Path] = []
        for entry in parent.iterdir():
            if not entry.is_file():
                continue
            if numeric_re.match(entry.name) or date_re.match(entry.name):
                archives.append(entry)
        archives.sort(key=lambda p: _rotation_sort_key(stem, p))
        found.extend(archives)

    if max_rotations is not None and found:
        # Active log (if present) plus up to N rotated archives.
        active = found[0] if found[0].name == stem else None
        archives = found[1:] if active else found
        capped = archives[:max_rotations]
        found = ([active] if active else []) + capped

    return found


def resolve_log_paths(
    bases: list[str | Path],
    *,
    include_rotated: bool = True,
    max_rotations: int | None = None,
) -> list[Path]:
    """Expand base log paths to include rotated archives when requested."""
    resolved: list[Path] = []
    seen: set[Path] = set()

    for raw in bases:
        path = Path(raw)
        if include_rotated and not is_rotated_name(path.name):
            candidates = discover_rotated(path, max_rotations=max_rotations)
        else:
            candidates = [path] if path.is_file() else []

        for candidate in candidates:
            canonical = candidate.resolve()
            if canonical not in seen:
                seen.add(canonical)
                resolved.append(candidate)

    return resolved


def default_log_paths(
    *,
    include_rotated: bool = True,
    max_rotations: int | None = None,
) -> list[Path]:
    return resolve_log_paths(
        DEFAULT_LOG_PATHS,
        include_rotated=include_rotated,
        max_rotations=max_rotations,
    )


def read_log_lines(path: Path) -> list[str]:
    if path.suffix == ".gz" or path.name.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    return path.read_text(encoding="utf-8", errors="replace").splitlines()
