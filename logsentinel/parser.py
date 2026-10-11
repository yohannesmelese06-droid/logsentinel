"""Parse OpenSSH auth log lines (Debian/Ubuntu /var/log/auth.log format)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

# Example: "Oct 11 03:12:44 server sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2"
LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\da-fA-F:.]+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>[\da-fA-F:.]+) port \d+"
)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)")


@dataclass(frozen=True)
class Event:
    time: datetime
    kind: str  # "failed" | "accepted" | "invalid"
    user: str
    ip: str


def _parse_ts(raw: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int) -> Optional[Event]:
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    ts, msg = _parse_ts(m["ts"], year), m["msg"]
    for regex, kind in ((FAILED_RE, "failed"), (ACCEPTED_RE, "accepted"), (INVALID_RE, "invalid")):
        hit = regex.search(msg)
        if hit:
            return Event(ts, kind, hit["user"], hit["ip"])
    return None


def parse_lines(lines: Iterable[str], year: int) -> Iterator[Event]:
    for line in lines:
        ev = parse_line(line, year)
        if ev:
            yield ev
