"""Analyze Linux system logs for errors and security events."""

from .analyzer import AnalysisReport, analyze_default_logs, analyze_paths
from .logs import default_log_paths, discover_rotated, resolve_log_paths
from .report import format_json, format_text

__all__ = [
    "AnalysisReport",
    "analyze_default_logs",
    "analyze_paths",
    "default_log_paths",
    "discover_rotated",
    "resolve_log_paths",
    "format_json",
    "format_text",
]
