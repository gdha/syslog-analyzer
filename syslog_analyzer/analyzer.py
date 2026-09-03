"""Core log analysis engine."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .logs import default_log_paths, read_log_lines
from .patterns import (
    SEVERITY_ORDER,
    Match,
    SECURITY_PATTERNS,
    SERIOUS_PATTERNS,
    _first_match,
    is_benign,
)


# ------------------------------------------------------------------ #
# Timestamp parsing helpers                                           #
# ------------------------------------------------------------------ #

# Ordered list of strptime formats tried for ISO-8601 strings.
_TS_FORMATS: list[tuple[str, bool]] = [
    ("%Y-%m-%dT%H:%M:%S.%f%z", True),   # 2026-09-02T06:04:25.123456+02:00
    ("%Y-%m-%dT%H:%M:%S%z", True),       # 2026-09-02T06:04:25+02:00
]

# Captures the timestamp from any of the three log flavours we care about.
_TS_RE = re.compile(
    r"""
    # ISO-8601 (with optional fractional seconds and optional tz offset)
    (?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)
    |
    # server-monitor: [Wed Sep  2 06:03:06 AM CEST 2026]
    \[(?:\w+)\s+(?P<mon2>\w+)\s+(?P<day2>\s*\d+)\s+(?P<hms2>\d{2}:\d{2}:\d{2})\s+(?P<ampm>AM|PM)\s+\w+\s+(?P<yr2>\d{4})\]
    |
    # Traditional syslog without year: Sep  2 06:04:25
    (?P<mon>\w{3})\s+(?P<day>\s*\d+)\s+(?P<hms>\d{2}:\d{2}:\d{2})
    """,
    re.VERBOSE,
)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _extract_datetime(line: str, ref_year: int = 2026) -> datetime | None:
    """Return a timezone-aware datetime for the first timestamp found in *line*."""
    m = _TS_RE.search(line)
    if not m:
        return None

    if m.group("iso"):
        raw = m.group("iso")
        for fmt, _ in _TS_FORMATS:
            try:
                dt = datetime.strptime(raw, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        return None

    if m.group("mon2"):
        # server-monitor: [Wed Sep  2 06:03:06 AM CEST 2026]
        mon = _MONTH_MAP.get(m.group("mon2"), 0)
        day = int(m.group("day2").strip())
        yr = int(m.group("yr2"))
        hh, mm, ss = map(int, m.group("hms2").split(":"))
        ampm = m.group("ampm")
        if ampm == "PM" and hh != 12:
            hh += 12
        elif ampm == "AM" and hh == 12:
            hh = 0
        try:
            return datetime(yr, mon, day, hh, mm, ss, tzinfo=timezone.utc)
        except ValueError:
            return None

    # Traditional syslog without year: Sep  2 06:04:25
    mon = _MONTH_MAP.get(m.group("mon"), 0)
    if mon == 0:
        return None
    day = int(m.group("day").strip())
    hh, mm, ss = map(int, m.group("hms").split(":"))
    try:
        return datetime(ref_year, mon, day, hh, mm, ss, tzinfo=timezone.utc)
    except ValueError:
        return None


# ------------------------------------------------------------------ #
# Gap detection                                                       #
# ------------------------------------------------------------------ #

_SHUTDOWN_RE = re.compile(
    r"systemd-logind.*Power(?:ing off|ing down)"
    r"|systemd\[1\].*Reached target.*poweroff"
    r"|systemd-journald.*Journal stopped"
    r"|Power key pressed"
    r"|Shutting down\.",
    re.I,
)
_BOOT_RE = re.compile(
    r"kernel:.*Linux version"
    r"|kernel:.*BIOS-provided"
    r"|systemd\[1\].*Reached target.*basic\.target",
    re.I,
)
_MONITOR_UNREACHABLE_RE = re.compile(
    r"Monitor unreachable"
    r"|HTTP 000"
    r"|Could not fetch.*monitor",
    re.I,
)
_NET_FAILURE_RE = re.compile(
    r"Network is unreachable"
    r"|Temporary failure in name resolution",
    re.I,
)


def _guess_gap_cause(
    lines_before: Sequence[str],
    lines_after: Sequence[str],
) -> str:
    """Heuristically identify why a log gap occurred."""
    ctx_before = list(lines_before[-200:])
    ctx_after = list(lines_after[:200])

    has_shutdown = any(_SHUTDOWN_RE.search(l) for l in ctx_before)
    has_boot = any(_BOOT_RE.search(l) for l in ctx_after)
    has_monitor_err = any(_MONITOR_UNREACHABLE_RE.search(l) for l in ctx_before)
    has_net_err = any(_NET_FAILURE_RE.search(l) for l in ctx_before)

    if has_shutdown and has_boot:
        return "system reboot / power-off (shutdown + boot sequence detected)"
    if has_shutdown:
        return "system shutdown (poweroff detected; no subsequent boot in this log)"
    if has_boot:
        return "system reboot (boot sequence detected; no preceding shutdown in this log)"
    if has_monitor_err:
        return "monitoring agent lost connectivity (HTTP 000 / monitor unreachable)"
    if has_net_err:
        return "network failure (DNS or connectivity errors detected)"
    return "unknown — no surrounding context matched a known cause"


@dataclass(frozen=True)
class LogGap:
    """A detected silence / interruption in the log stream."""
    source: str                 # log file where the gap was found
    gap_start: str              # last log line before the gap (truncated)
    gap_end: str                # first log line after the gap (truncated)
    duration_seconds: float
    likely_cause: str

    @property
    def duration_human(self) -> str:
        secs = int(self.duration_seconds)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h {m:02d}m {s:02d}s"
        if m:
            return f"{m}m {s:02d}s"
        return f"{s}s"


def detect_gaps(
    lines: list[str],
    source: str,
    *,
    threshold_seconds: float = 300,
    ref_year: int = 2026,
) -> list[LogGap]:
    """Return all timestamp gaps in *lines* that exceed *threshold_seconds*.

    Timestamps are parsed from ISO-8601, traditional syslog, and the
    server-monitor bracket format.  Non-parseable lines are skipped.
    """
    gaps: list[LogGap] = []
    prev_dt: datetime | None = None
    prev_line: str = ""
    prev_idx: int = 0

    for i, line in enumerate(lines):
        dt = _extract_datetime(line, ref_year=ref_year)
        if dt is None:
            continue

        if prev_dt is not None:
            delta = (dt - prev_dt).total_seconds()
            if delta > threshold_seconds:
                cause = _guess_gap_cause(lines[: prev_idx + 1], lines[i:])
                gaps.append(
                    LogGap(
                        source=source,
                        gap_start=prev_line[:120],
                        gap_end=line.strip()[:120],
                        duration_seconds=delta,
                        likely_cause=cause,
                    )
                )

        prev_dt = dt
        prev_line = line.strip()
        prev_idx = i

    return gaps


# ------------------------------------------------------------------ #
# Core dataclasses                                                    #
# ------------------------------------------------------------------ #

@dataclass
class AnalysisReport:
    sources: list[str] = field(default_factory=list)
    total_lines: int = 0
    time_range: tuple[str, str] | None = None
    host: str | None = None
    serious: list[Match] = field(default_factory=list)
    security: list[Match] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    gaps: list[LogGap] = field(default_factory=list)

    @property
    def serious_by_category(self) -> dict[str, list[Match]]:
        grouped: dict[str, list[Match]] = defaultdict(list)
        for m in self.serious:
            grouped[m.category].append(m)
        return dict(grouped)

    @property
    def security_by_category(self) -> dict[str, list[Match]]:
        grouped: dict[str, list[Match]] = defaultdict(list)
        for m in self.security:
            grouped[m.category].append(m)
        return dict(grouped)

    def highest_serious_severity(self) -> str | None:
        if not self.serious:
            return None
        return min(self.serious, key=lambda m: SEVERITY_ORDER[m.severity]).severity

    def attack_indicators(self) -> list[Match]:
        attack_cats = {
            "ssh_auth_failure",
            "ssh_suspicious",
            "sudo_failure",
            "pam_failure",
            "auth_failure",
            "intrusion",
            "fail2ban",
            "firewall_block",
        }
        return [m for m in self.security if m.category in attack_cats]


# ------------------------------------------------------------------ #
# Internal helpers                                                    #
# ------------------------------------------------------------------ #

def _parse_timestamp(line: str) -> str | None:
    m = re.match(r"^(\S+)", line)
    return m.group(1) if m else None


def _parse_host(line: str) -> str | None:
    m = re.match(r"^\S+\s+(\S+)", line)
    return m.group(1) if m else None


def _message_body(line: str) -> str:
    """Normalise a log line for deduplication (strip timestamp, host, PID noise)."""
    body = re.sub(r"^\S+\s+\S+\s+", "", line)
    body = re.sub(r"\[\d+\]", "[PID]", body)
    return body


def _update_time_range(report: AnalysisReport, timestamp: str) -> None:
    if report.time_range is None:
        report.time_range = (timestamp, timestamp)
        return
    start, end = report.time_range
    if timestamp < start:
        start = timestamp
    if timestamp > end:
        end = timestamp
    report.time_range = (start, end)


# ------------------------------------------------------------------ #
# Public API                                                          #
# ------------------------------------------------------------------ #

def analyze_paths(
    paths: list[str | Path],
    *,
    include_info: bool = False,
    min_severity: str = "low",
    gap_threshold: float = 300,
) -> AnalysisReport:
    """Analyse *paths* and return an :class:`AnalysisReport`.

    Parameters
    ----------
    paths:
        List of log files to scan.
    include_info:
        If ``True``, include informational security events (e.g. accepted logins).
    min_severity:
        Ignore events below this severity level.
    gap_threshold:
        Minimum silence in seconds that is reported as a :class:`LogGap`.
        Set to ``0`` to disable gap detection.
    """
    report = AnalysisReport()
    min_rank = SEVERITY_ORDER[min_severity]
    seen_serious: set[tuple[str, str]] = set()
    seen_security: set[tuple[str, str]] = set()

    for raw_path in paths:
        path = Path(raw_path)
        if not path.is_file():
            report.unreadable.append(str(path))
            continue

        report.sources.append(str(path))
        try:
            lines = read_log_lines(path)
        except OSError:
            report.unreadable.append(str(path))
            continue

        source = path.name
        report.total_lines += len(lines)

        # --- Gap detection ---
        if gap_threshold > 0:
            file_gaps = detect_gaps(lines, source, threshold_seconds=gap_threshold)
            report.gaps.extend(file_gaps)

        # --- Error / security scanning ---
        for i, line in enumerate(lines, start=1):
            line = line.rstrip()
            if not line:
                continue

            ts = _parse_timestamp(line)
            if ts:
                _update_time_range(report, ts)

            host = _parse_host(line)
            if host and report.host is None:
                report.host = host

            serious_hit = _first_match(line, SERIOUS_PATTERNS)
            if serious_hit:
                category, severity = serious_hit
                if SEVERITY_ORDER[severity] <= min_rank:
                    key = (category, _message_body(line))
                    if key not in seen_serious:
                        seen_serious.add(key)
                        report.serious.append(
                            Match(line, source, category, severity, i)
                        )

            security_hit = _first_match(line, SECURITY_PATTERNS, skip_benign=False)
            if security_hit:
                category, severity = security_hit
                if category == "apparmor_denied" and is_benign(line):
                    continue
                if not include_info and severity == "info":
                    continue
                if SEVERITY_ORDER[severity] <= min_rank:
                    key = (category, _message_body(line))
                    if key not in seen_security:
                        seen_security.add(key)
                        report.security.append(
                            Match(line, source, category, severity, i)
                        )

    report.serious.sort(key=lambda m: (SEVERITY_ORDER[m.severity], m.source, m.line_number))
    report.security.sort(key=lambda m: (SEVERITY_ORDER[m.severity], m.source, m.line_number))
    report.gaps.sort(key=lambda g: g.duration_seconds, reverse=True)
    return report


def analyze_default_logs(
    *,
    include_rotated: bool = True,
    max_rotations: int | None = None,
    **kwargs,
) -> AnalysisReport:
    paths = default_log_paths(
        include_rotated=include_rotated,
        max_rotations=max_rotations,
    )
    return analyze_paths(paths, **kwargs)


def apparmor_profile_summary(matches: list[Match]) -> list[tuple[str, int]]:
    profiles: Counter[str] = Counter()
    for m in matches:
        if m.category != "apparmor_denied":
            continue
        hit = re.search(r'profile="([^"]+)"', m.line)
        if hit:
            profiles[hit.group(1)] += 1
    return profiles.most_common()
