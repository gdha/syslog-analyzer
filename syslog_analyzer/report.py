"""Human-readable and JSON report formatting."""

from __future__ import annotations

import json
from collections import Counter

from .analyzer import AnalysisReport, apparmor_profile_summary
from .patterns import SEVERITY_ORDER


def _severity_icon(severity: str) -> str:
    return {
        "critical": "[!!!]",
        "high": "[!!]",
        "medium": "[!]",
        "low": "[~]",
        "info": "[i]",
    }.get(severity, "[?]")


def format_text(report: AnalysisReport, *, max_per_category: int = 10) -> str:
    lines: list[str] = []
    sep = "=" * 72

    lines.append(sep)
    lines.append("SYSLOG ANALYZER REPORT")
    lines.append(sep)

    if report.time_range:
        lines.append(f"Period:    {report.time_range[0]} → {report.time_range[1]}")
    if report.host:
        lines.append(f"Host:      {report.host}")
    if report.sources:
        if len(report.sources) <= 5:
            lines.append(f"Sources:   {', '.join(report.sources)}")
        else:
            lines.append(f"Sources:   {len(report.sources)} files (active + rotated)")
            lines.append(f"           {', '.join(report.sources[:3])}, …")
    else:
        lines.append("Sources:   (none)")
    lines.append(f"Lines:     {report.total_lines:,}")
    if report.unreadable:
        lines.append(f"Skipped:   {', '.join(report.unreadable)} (not found or unreadable)")

    attacks = report.attack_indicators()
    lines.append("")
    if attacks:
        lines.append("⚠  ATTACK / AUTH FAILURE INDICATORS DETECTED")
        for m in attacks[:20]:
            lines.append(f"  {_severity_icon(m.severity)} [{m.source}:{m.line_number}] {m.line[:200]}")
    else:
        lines.append("✓  No SSH brute-force, sudo failures, or intrusion indicators found.")

    lines.append("")
    lines.append(sep)
    lines.append("SERIOUS ERRORS")
    lines.append(sep)

    if not report.serious:
        lines.append("(none)")
    else:
        by_cat = report.serious_by_category
        for cat in sorted(by_cat, key=lambda c: SEVERITY_ORDER[by_cat[c][0].severity]):
            entries = by_cat[cat]
            sev = entries[0].severity
            lines.append(f"\n--- {cat.upper()} ({len(entries)}) { _severity_icon(sev)} ---")
            msg_counts = Counter()
            for e in entries:
                body = e.line.split(" ", 2)[-1] if " " in e.line else e.line
                msg_counts[body] += 1
            for msg, count in msg_counts.most_common(max_per_category):
                prefix = f"[{count}x] " if count > 1 else ""
                sample = next(e for e in entries if msg in e.line)
                lines.append(
                    f"  {prefix}[{sample.source}:{sample.line_number}] {sample.line[:220]}"
                )
            if len(msg_counts) > max_per_category:
                lines.append(f"  ... and {len(msg_counts) - max_per_category} more unique messages")

    lines.append("")
    lines.append(sep)
    lines.append("SECURITY EVENTS")
    lines.append(sep)

    if not report.security:
        lines.append("(none above threshold)")
    else:
        by_cat = report.security_by_category
        for cat in sorted(by_cat, key=lambda c: SEVERITY_ORDER[by_cat[c][0].severity]):
            entries = by_cat[cat]
            sev = entries[0].severity
            lines.append(f"\n--- {cat.upper()} ({len(entries)}) {_severity_icon(sev)} ---")
            for e in entries[:max_per_category]:
                lines.append(f"  [{e.source}:{e.line_number}] {e.line[:220]}")
            if len(entries) > max_per_category:
                lines.append(f"  ... and {len(entries) - max_per_category} more")

        aa = [m for m in report.security if m.category == "apparmor_denied"]
        if aa:
            lines.append("\n--- APPARMOR DENIED (by profile) ---")
            for profile, count in apparmor_profile_summary(aa)[:12]:
                lines.append(f"  {profile}: {count}")

    lines.append("")
    lines.append(sep)
    highest = report.highest_serious_severity()
    if highest in ("critical", "high"):
        lines.append(f"Overall: REVIEW RECOMMENDED (highest serious severity: {highest})")
    elif attacks:
        lines.append("Overall: SECURITY REVIEW RECOMMENDED")
    else:
        lines.append("Overall: No critical issues detected in scanned logs.")
    lines.append(sep)

    return "\n".join(lines)


def format_json(report: AnalysisReport) -> str:
    payload = {
        "time_range": report.time_range,
        "host": report.host,
        "sources": report.sources,
        "total_lines": report.total_lines,
        "unreadable": report.unreadable,
        "attack_indicators": [
            {"source": m.source, "line": m.line_number, "category": m.category, "severity": m.severity, "text": m.line}
            for m in report.attack_indicators()
        ],
        "serious": [
            {"source": m.source, "line": m.line_number, "category": m.category, "severity": m.severity, "text": m.line}
            for m in report.serious
        ],
        "security": [
            {"source": m.source, "line": m.line_number, "category": m.category, "severity": m.severity, "text": m.line}
            for m in report.security
        ],
        "apparmor_profiles": dict(apparmor_profile_summary(
            [m for m in report.security if m.category == "apparmor_denied"]
        )),
    }
    return json.dumps(payload, indent=2)
