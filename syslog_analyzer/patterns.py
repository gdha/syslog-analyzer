"""Pattern definitions for error and security log classification."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

# Lines matching any of these are excluded from serious-error matching.
BENIGN_PATTERNS: list[str] = [
    # --- systemd lifecycle (normal operation) ---
    r"Deactivated successfully",
    r"Finished .* successfully",
    r"^.* systemd\[\d+\]: Started ",
    r"^.* systemd\[\d+\]: Stopping ",
    r"^.* systemd\[\d+\]: Reached target ",
    r"^.* systemd\[\d+\]: Listening on ",
    r"^.* systemd\[\d+\]: Mounted ",
    r"^.* systemd\[\d+\]: Condition check resulted in .* being skipped",
    r"systemd.*: .* scheduled restart job",
    # --- dmesg / kernel severity keywords in informational context ---
    r"printk: \d+ messages suppressed",
    r"kern\.(?:crit|alert|emerg).*forwarded",  # log forwarding config
    r"priority=(?:crit|alert|emerg).*rotated",  # logrotate referencing priority
    r"loglevel=|log_level=|LogLevel=",  # config lines mentioning severity
    r"set.*(?:crit|critical|alert|emerg).*threshold",  # threshold configuration
    r"severity.*(?:crit|critical|alert|emerg).*configured",  # severity config
    r"dmesg.*--level|dmesg.*--facility",  # dmesg command invocations
    r"rsyslog.*action.*crit|syslog-ng.*filter.*crit",  # syslog daemon config
    # --- routine process signals / HUPs ---
    r"was HUPed",
    r"Reloading configuration",
    r"received SIGHUP.*reloading",
    # --- AppArmor housekeeping ---
    r"profile_replace.*same as current profile",
    r'apparmor="STATUS"',
    r"kauditd_printk_skb.*suppressed",
    r"type=1326 audit",  # seccomp — routine snap confinement
    # --- hardware / graphics benign ---
    r"/etc/vulkan/",
    r"product_sku",
    r"Errors from xkbcomp are not fatal",
    # --- D-Bus normal activity ---
    r"dbus_method_call.*timedate1",
    r"dbus_signal.*login1",
    # --- API / service deprecation notices (not errors) ---
    r"DEPRECATED_ENDPOINT",
    r"QUOTA_EXCEEDED",
    r"Initializing extension SECURITY",
    # --- session lifecycle (informational) ---
    r"session opened for user",
    r"session closed for user",
    r"New session .* of user",
    r"Removed session",
    # --- package manager normal output (contains 'error' keyword in paths) ---
    r"(?:dnf|yum|apt).*(?:Importing|Verifying|Running).*",
    r"hawkey.*repo.*error.*skipping",  # repo metadata warnings in hawkey
    # --- monitoring agent benign messages ---
    r"telegraf.*(?:Gathered|Connected|Loaded)",
    r"fluent-bit.*(?:\[info\]|\[notice\])",
    # --- cron / timer normal scheduling ---
    r"CRON\[\d+\]:.*\(.*\) CMD ",
    r"anacron.*Updated timestamp",
    # --- network manager informational ---
    r"NetworkManager.*state change.*connected",
    r"NetworkManager.*policy.*set .* default",
]

SERIOUS_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, category, severity: critical|high|medium|low)
    (r"\bsegfault\b|general protection fault|segfault at|traps:.*segfault", "segfault", "critical"),
    (r"\boom[\s-]?kill|out of memory|Killed process", "oom", "critical"),
    (r"\bpanic\b|Call Trace|Oops:", "kernel_panic", "critical"),
    (r"\b(critical|crit)\b", "critical", "critical"),
    (r"\b(fatal|emerg|alert)\b", "fatal", "high"),
    (r"Failed with result", "service_failed", "high"),
    (r"failed to (start|load|bind|connect|open|execute)", "operation_failed", "high"),
    (r"No space left on device", "disk_full", "high"),
    (r"\bI/O error\b", "io_error", "high"),
    (r"\bcorrupt|corruption\b", "corruption", "high"),
    (r"server misbehaving|device or resource busy", "dns_failure", "high"),
    (r"livepatch check failed|state ensure error", "service_unreachable", "high"),
    (r"Permission denied", "permission_denied", "medium"),
    (r"\b(error|err)\b", "error", "medium"),
]

SECURITY_PATTERNS: list[tuple[str, str, str]] = [
    (r"sshd.*(?:Invalid user|Failed password|authentication failure)", "ssh_auth_failure", "critical"),
    (r"sshd.*(?:Connection closed|Disconnected).*(?:preauth|invalid)", "ssh_suspicious", "high"),
    (r"sshd.*Accepted (?:publickey|password)", "ssh_accepted", "info"),
    (r"sshd.*Connection from", "ssh_connection", "info"),
    (r"sudo:.*authentication failure|sudo:.*incorrect password", "sudo_failure", "critical"),
    (r"sudo:.*COMMAND=", "sudo_command", "info"),
    (r"pkexec.*session opened", "pkexec", "info"),
    (r"polkitd.*Registered Authentication Agent", "polkit_agent", "info"),
    (r"pam_.*(?:auth|session|account).*(?:failure|denied)", "pam_failure", "high"),
    (r'apparmor="DENIED"', "apparmor_denied", "medium"),
    (r"audit:.*(?:DENIED|AVC)", "audit_denied", "medium"),
    (r"(?:ufw|iptables|nftables).*(?:BLOCK|DENY|REJECT)", "firewall_block", "high"),
    (r"\bfail2ban\b.*(?:Ban|Found)", "fail2ban", "high"),
    (r"brute[\s-]?force|intrusion (?:attempt|detected)|breach detected|under attack", "intrusion", "critical"),
    (r"invalid user|authentication failure", "auth_failure", "high"),
    (r"polkit.*denied", "polkit_denied", "medium"),
    (r"failed to parse ssh public key", "ssh_key_error", "medium"),
    (r"unauthorized: authentication required|access to the resource is denied", "registry_denied", "medium"),
    (r'apparmor="AUDIT".*userns_create', "sandbox_audit", "info"),
    (r"profile=\"cursor_sandbox\".*DENIED", "cursor_sandbox", "low"),
]

# Default logs to scan. Missing paths are skipped; Debian and RHEL layouts coexist.
DEFAULT_LOG_PATHS: list[str] = [
    # Debian / Ubuntu
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/kern.log",
    # RHEL / CentOS / Fedora
    "/var/log/messages",
    "/var/log/secure",
    # Package manager logs
    "/var/log/dnf.log",
    "/var/log/dnf.rpm.log",
    # Monitoring / log collectors
    "/var/log/telegraf/telegraf.log",
    "/var/log/fluent-bit/fluent-bit.log",
    # Miscellaneous system logs
    "/var/log/hawkey.log",
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Match:
    line: str
    source: str
    category: str
    severity: str
    line_number: int


def is_benign(line: str) -> bool:
    return any(re.search(p, line, re.I) for p in BENIGN_PATTERNS)


def _first_match(
    line: str,
    patterns: list[tuple[str, str, str]],
    *,
    skip_benign: bool = True,
) -> tuple[str, str] | None:
    if skip_benign and is_benign(line):
        return None
    for pattern, category, severity in patterns:
        if re.search(pattern, line, re.I):
            return category, severity
    return None
