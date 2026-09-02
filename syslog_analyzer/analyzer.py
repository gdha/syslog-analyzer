"""Core log analysis engine."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

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


@dataclass
class AnalysisReport:
    sources: list[str] = field(default_factory=list)
    total_lines: int = 0
    time_range: tuple[str, str] | None = None
    host: str | None = None
    serious: list[Match] = field(default_factory=list)
    security: list[Match] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)

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
