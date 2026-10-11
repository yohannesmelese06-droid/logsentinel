# LogSentinel 🛡️

A lightweight, dependency-free **SSH log analyzer** that detects common attack patterns in Linux `auth.log` files. Built as a defensive security / blue-team portfolio project.

## What it detects

| Rule | Severity | Description |
|------|----------|-------------|
| `brute_force` | medium/high | Many failed logins from one IP inside a sliding time window |
| `password_spraying` | high | One IP trying many different usernames (enumeration) |
| `possible_compromise` | critical | A successful login right after repeated failures from the same IP |

These map to MITRE ATT&CK **T1110 – Brute Force** (T1110.001 Password Guessing, T1110.003 Password Spraying) and **T1078 – Valid Accounts**.

## Quick start

```bash
git clone https://github.com/<your-username>/logsentinel.git
cd logsentinel

python -m logsentinel samples/auth.log --year 2026
python -m logsentinel samples/auth.log --year 2026 --format json
```

Requires Python 3.9+. No third-party packages.

### Example output

```
LogSentinel report: 16 auth events analyzed, 4 alert(s)

[CRIT] possible_compromise  198.51.100.23    Successful login as 'deploy' after 6 failures
[HIGH] password_spraying    203.0.113.5      6 distinct usernames attempted
[MED ] brute_force          198.51.100.23    6 failed logins within 5 min
[MED ] brute_force          203.0.113.5      6 failed logins within 5 min
```

The exit code is `1` when a high/critical alert is found, so it can be used in cron jobs or CI pipelines.

## Project structure

```
logsentinel/
├── logsentinel/
│   ├── parser.py      # regex parsing of sshd log lines into Event objects
│   ├── detectors.py   # sliding-window detection rules
│   └── cli.py         # command-line interface
├── samples/auth.log   # synthetic attack data (documentation IPs only)
└── tests/             # pytest unit tests
```

## Running tests

```bash
pip install pytest
pytest -v
```

## How it works

1. **Parse** – each `sshd` line is converted into an `Event(time, kind, user, ip)`.
2. **Group** – events are grouped per source IP and sorted by time.
3. **Detect** – sliding-window rules flag suspicious behaviour, with tunable thresholds.
4. **Report** – alerts are sorted by severity and printed as text or JSON.

## Ideas for extension

- Live tailing (`tail -f` mode) and alerting via email/Slack
- GeoIP and threat-intel (AbuseIPDB) enrichment
- Auto-blocking with `iptables`/`fail2ban` integration
- Support for Windows Event Logs (4625/4624) and web server logs

## Disclaimer

For defensive and educational use. Sample data uses reserved documentation IP ranges (RFC 5737).

## License

MIT
