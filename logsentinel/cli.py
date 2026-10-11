"""LogSentinel CLI."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime

from .detectors import Alert, run_all
from .parser import parse_lines

SEV_ICON = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}


def format_text(alerts: list[Alert], total_events: int) -> str:
    lines = [f"LogSentinel report: {total_events} auth events analyzed, {len(alerts)} alert(s)", ""]
    for a in alerts:
        lines.append(f"{SEV_ICON[a.severity]} {a.rule:<20} {a.ip:<16} {a.description}")
    if not alerts:
        lines.append("No suspicious activity detected.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="logsentinel", description="Detect SSH attacks in auth logs.")
    p.add_argument("logfile", help="Path to auth.log (use '-' for stdin)")
    p.add_argument("--year", type=int, default=datetime.now().year, help="Year of the log (syslog omits it)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv)

    fh = sys.stdin if args.logfile == "-" else open(args.logfile, encoding="utf-8", errors="replace")
    with fh:
        events = list(parse_lines(fh, args.year))
    alerts = run_all(events)

    if args.format == "json":
        print(json.dumps([asdict(a) for a in alerts], indent=2))
    else:
        print(format_text(alerts, len(events)))
    return 1 if any(a.severity in ("critical", "high") for a in alerts) else 0


if __name__ == "__main__":
    raise SystemExit(main())
