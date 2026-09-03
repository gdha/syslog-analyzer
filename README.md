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
| `/var/log/dnf.log` | RHEL/Fedora/AL2023 | package manager operations |
| `/var/log/dnf.rpm.log` | RHEL/Fedora/AL2023 | RPM transaction details |
| `/var/log/telegraf/telegraf.log` | Any (if installed) | Telegraf monitoring agent |
| `/var/log/fluent-bit/fluent-bit.log` | Any (if installed) | Fluent Bit log collector |
| `/var/log/hawkey.log` | RHEL/Fedora/AL2023 | DNF dependency resolution |

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

# Analyze only entries from today
python3 -m syslog_analyzer --since today

# Analyze only entries since a specific date
python3 -m syslog_analyzer --since 2026-09-01
```

Each run is also appended to a daily run log at:

`/var/log/syslog-analyzer-YYYY-MM-DD`

If `/var/log` is not writable, it falls back to `./syslog-analyzer-YYYY-MM-DD`.

## False-positive suppression (allowlist)

Some log lines contain keywords like `critical`, `error`, or `fatal` in a purely
informational context (e.g. `dmesg --level=crit`, logrotate config references,
systemd status messages). To avoid these being reported as real issues, the
analyzer applies two layers of suppression:

1. **Built-in benign patterns** — a curated list in `patterns.py` that matches
   common harmless lines (systemd lifecycle, dmesg invocations, log-forwarding
   config, session open/close, etc.).

2. **User allowlist** — a personal file where you add regex patterns specific to
   your environment.

### Allowlist file format

One regex per line, matched case-insensitively against the full log line.
Blank lines and lines starting with `#` are comments.

```text
# ~/.config/syslog-analyzer/allowlist.conf
my_custom_app.*starting up
systemd-resolved.*Cache flush
kernel:.*ACPI.*Thermal Zone
```

### Allowlist CLI options

```bash
# Create the default allowlist with example content
python3 -m syslog_analyzer --allowlist-init

# Use a custom allowlist file
python3 -m syslog_analyzer --allowlist /path/to/my-allowlist.conf

# The default location (~/.config/syslog-analyzer/allowlist.conf)
# is loaded automatically if it exists
python3 -m syslog_analyzer
```

Default location: `~/.config/syslog-analyzer/allowlist.conf`

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

## Build a standalone executable

```bash
make build-exe
./dist/syslog-analyzer --help
```

The Makefile creates an isolated `.build-venv` virtual environment for the
build toolchain and writes the compiled executable to `dist/syslog-analyzer`.
