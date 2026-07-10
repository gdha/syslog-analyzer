# syslog-analyzer

Scan Linux system logs for serious errors and security-related activity.

## Default sources

Active logs plus rotated archives for each path that exists on the system.
Missing files are skipped, so Debian and RHEL layouts work out of the box.

| Path | Distro | Contents |
|------|--------|----------|
| `/var/log/syslog` | Debian/Ubuntu | general system log |
| `/var/log/auth.log` | Debian/Ubuntu | SSH, sudo, PAM |
| `/var/log/kern.log` | Debian/Ubuntu | kernel, AppArmor |
| `/var/log/messages` | RHEL/CentOS/Fedora | general system log |
| `/var/log/secure` | RHEL/CentOS/Fedora | SSH, sudo, PAM |

Rotations supported: numeric (`.1`, `.2.gz`) and RHEL dateext (`messages-20250608.gz`).

## Usage

```bash
# Scan active + rotated logs (default)
python3 -m syslog_analyzer

# Active logs only
python3 -m syslog_analyzer --no-rotated

# Limit history depth (active + two rotations per log)
python3 -m syslog_analyzer --max-rotations 2

# Specific base file (auto-expands to rotations unless --no-rotated)
python3 -m syslog_analyzer /var/log/syslog

# Explicit archive only
python3 -m syslog_analyzer /var/log/syslog.2.gz

# JSON output, save to file
python3 -m syslog_analyzer --json -o report.json

# Only critical/high severity
python3 -m syslog_analyzer --min-severity high

# Include successful SSH logins and sudo commands
python3 -m syslog_analyzer --include-info
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No critical issues |
| 1 | High/critical errors found |
| 2 | Attack or auth-failure indicators found |

## Install (optional)

```bash
pip install -e .
syslog-analyzer
```
