"""Core log analysis engine."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
<<<<<<< HEAD
from datetime import datetime, timezone
=======
from datetime import date, datetime, timedelta
>>>>>>> 16e3676e89c86ad86ff272fa655001a247d2802a
from pathlib import Path
from typing import Sequence

from .allowlist import is_allowlisted
from .logs import default_log_paths, read_log_lines
from .patterns import (
    SEVERITY_ORDER,
    Match,
    SECURITY_PATTERNS,
    SERIOUS_PATTERNS,
    _first_match,
    is_benign,
)


# Ordered list of timestamp formats tried when parsing log lines.
# Each entry is (strptime_format, has_timezone_info).
_TS_FORMATS: list[tuple[str, bool]] = [
    # ISO-8601 with timezone offset, e.g. 2026-09-02T06:04:25.123456+02:00
    ("%Y-%m-%dT%H:%M:%S.%f%z", True),
    # ISO-8601 without fractional seconds, e.g. 2026-09-02T06:04:25+02:00
    ("%Y-%m-%dT%H:%M:%S%z", True),
    # syslog RFC3164 with year, e.g. Sep 02 06:04:25  (no year — handled specially)
    # Traditional syslog without year, e.g. "Sep  2 06:04:25"
]

# Regex that captures the timestamp portion from common log formats.
_TS_RE = re.compile(
    r"""
    # ISO-8601
    (?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)
    |
    # server-monitor style: [Wed Sep  2 06:03:06 AM CEST 2026]
    \[(?P<dow>\w+)\s+(?P<mon2>\w+)\s+(?P<day2>\s*\d+)\s+(?P<hms2>\d{2}:\d{2}:\d{2})\s+(?P<ampm>AM|PM)\s+\w+\s+(?P<yr2>\d{4})\]
    |
    # Traditional syslog without year: Sep  2 06:04:25  (assume current year)
    (?P<mon>\w{3})\s+(?P<day>\s*\d+)\s+(?P<hms>\d{2}:\d{2}:\d{2})
    """,
    re.VERBOSE,
)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _extract_datetime(line: str, ref_year: int = 2026) -> datetime | None:
    """Parse the first recognisable timestamp in *line* and return a timezone-aware datetime."""
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
        # server-monitor format: Wed Sep  2 06:03:06 AM CEST 2026
        mon = _MONTH_MAP.get(m.group("mon2"), 0)
        day = int(m.group("day2").strip())
        yr = int(m.group("yr2"))
        hms = m.group("hms2")
        ampm = m.group("ampm")
        hh, mm, ss = map(int, hms.split(":"))
        if ampm == "PM" and hh != 12:
            hh += 12
        elif ampm == "AM" and hh == 12:
            hh = 0
        try:
            return datetime(yr, mon, day, hh, mm, ss, tzinfo=timezone.utc)
        except ValueError:
            return None

    # Traditional syslog without year
    mon = _MONTH_MAP.get(m.group("mon"), 0)
    day = int(m.group("day").strip())
    hh, mm, ss = map(int, m.group("hms").split(":"))
    if mon == 0:
        return None
    try:
        return datetime(ref_year, mon, day, hh, mm, ss, tzinfo=timezone.utc)
    except ValueError:
        return None


@dataclass(frozen=True)
class LogGap:
    """A detected silence / interruption in the log stream."""
    source: str          # log file where the gap was detected
    gap_start: str       # last timestamp before the gap (ISO string)
    gap_end: str         # first timestamp after the gap (ISO string)
    duration_seconds: float
    likely_cause: str    # human-readable best-guess reason

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

    # ------------------------------------------------------------------ #
    # Properties                                                          #
    # ------------------------------------------------------------------ #

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


def _parse_timestamp(line: str) -> str | None:
    m = re.match(r"^(\S+)", line)
    return m.group(1) if m else None


def _parse_host(line: str) -> str | None:
    m = re.match(r"^\S+\s+(\S+)", line)
    return m.group(1) if m else None


<<<<<<< HEAD
# ------------------------------------------------------------------ #
# Shutdown / reboot pattern matchers for gap cause detection          #
# ------------------------------------------------------------------ #
_SHUTDOWN_RE = re.compile(
    r"systemd-logind.*Power(?:ing off|ing down)"
    r"|systemd\[1\].*Reached target.*poweroff"
    r"|systemd-journald.*Journal stopped"
    r"|shutdown.*now"
    r"|reboot.*now",
    re.I,
)
_BOOT_RE = re.compile(
    r"kernel:.*Linux version"
    r"|systemd\[1\].*Starting.*systemd"
    r"|kernel:.*BIOS-provided",
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
    r"|Temporary failure in name resolution"
    r"|connect.*failed",
    re.I,
)


def _guess_gap_cause(
    lines_before: Sequence[str],
    lines_after: Sequence[str],
) -> str:
    """Heuristically determine why a log gap occurred."""
    # Look at up to 200 lines on each side
    context_before = lines_before[-200:] if len(lines_before) > 200 else lines_before
    context_after = lines_after[:200] if len(lines_after) > 200 else lines_after

    has_shutdown = any(_SHUTDOWN_RE.search(l) for l in context_before)
    has_boot = any(_BOOT_RE.search(l) for l in context_after)
    has_monitor_err = any(_MONITOR_UNREACHABLE_RE.search(l) for l in context_before)
    has_net_err = any(_NET_FAILURE_RE.search(l) for l in context_before)

    if has_shutdown and has_boot:
        return "system reboot / power-off (shutdown + boot sequence detected)"
    if has_shutdown:
        return "system shutdown (poweroff detected, no subsequent boot seen in this log)"
    if has_boot:
        return "system reboot (boot sequence detected, no preceding shutdown seen in this log)"
    if has_monitor_err:
        return "monitoring agent lost connectivity (HTTP 000 / monitor unreachable)"
    if has_net_err:
        return "network failure (DNS or connectivity errors detected)"
    return "unknown — no surrounding context matched a known cause"


def detect_gaps(
    lines: list[str],
    source: str,
    *,
    threshold_seconds: float = 300,
    ref_year: int = 2026,
) -> list[LogGap]:
    """Scan *lines* for timestamp gaps larger than *threshold_seconds*.

    Returns a list of :class:`LogGap` objects ordered chronologically.
    """
    gaps: list[LogGap] = []
    prev_dt: datetime | None = None
    prev_ts_str: str = ""
    prev_index: int = 0

    for i, line in enumerate(lines):
        dt = _extract_datetime(line, ref_year=ref_year)
        if dt is None:
            continue

        if prev_dt is not None:
            delta = (dt - prev_dt).total_seconds()
            if delta > threshold_seconds:
                cause = _guess_gap_cause(lines[:prev_index + 1], lines[i:])
                gaps.append(
                    LogGap(
                        source=source,
                        gap_start=prev_ts_str,
                        gap_end=line.strip()[:120],
                        duration_seconds=delta,
                        likely_cause=cause,
                    )
                )

        prev_dt = dt
        prev_ts_str = line.strip()[:120]
        prev_index = i

    return gaps
=======
def _parse_line_date(line: str, *, reference: date) -> date | None:
    iso_match = re.match(r"^(\d{4}-\d{2}-\d{2})", line)
    if iso_match:
        try:
            return datetime.strptime(iso_match.group(1), "%Y-%m-%d").date()
        except ValueError:
            return None

    syslog_match = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+\d{2}:\d{2}:\d{2}", line)
    if not syslog_match:
        return None

    try:
        parsed = datetime.strptime(
            f"{reference.year} {syslog_match.group(1)} {int(syslog_match.group(2))}",
            "%Y %b %d",
        ).date()
    except ValueError:
        return None

    if parsed > reference + timedelta(days=1):
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed
>>>>>>> 16e3676e89c86ad86ff272fa655001a247d2802a


def _message_body(line: str) -> str:
    """Normalize a log line for deduplication (strip timestamp, host, PID noise)."""
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


def analyze_paths(
    paths: list[str | Path],
    *,
    include_info: bool = False,
    min_severity: str = "low",
    allowlist_patterns: list[str] | None = None,
    since: date | None = None,
) -> AnalysisReport:
    report = AnalysisReport()
    min_rank = SEVERITY_ORDER[min_severity]
    seen_serious: set[tuple[str, str, str]] = set()
    seen_security: set[tuple[str, str, str]] = set()
    user_allowlist = allowlist_patterns or []

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

        for i, line in enumerate(lines, start=1):
            line = line.rstrip()
            if not line:
                continue

            line_date = _parse_line_date(line, reference=date.today())
            if since and line_date and line_date < since:
                continue

            ts = _parse_timestamp(line)
            if ts:
                _update_time_range(report, ts)

            host = _parse_host(line)
            if host and report.host is None:
                report.host = host

            # Skip lines matched by user allowlist
            if user_allowlist and is_allowlisted(line, user_allowlist):
                continue

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
