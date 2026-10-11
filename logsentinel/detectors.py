"""Detection rules operating on parsed SSH events."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List, Sequence

from .parser import Event


@dataclass
class Alert:
    rule: str
    severity: str  # "low" | "medium" | "high" | "critical"
    ip: str
    description: str
    details: Dict[str, object] = field(default_factory=dict)


def _by_ip(events: Sequence[Event]) -> Dict[str, List[Event]]:
    grouped: Dict[str, List[Event]] = defaultdict(list)
    for ev in sorted(events, key=lambda e: e.time):
        grouped[ev.ip].append(ev)
    return grouped


def detect_brute_force(
    events: Sequence[Event], threshold: int = 5, window: timedelta = timedelta(minutes=5)
) -> List[Alert]:
    """Many failed logins from one IP inside a sliding time window."""
    alerts: List[Alert] = []
    for ip, evs in _by_ip(events).items():
        fails = [e for e in evs if e.kind in ("failed", "invalid")]
        start, best = 0, 0
        for end in range(len(fails)):
            while fails[end].time - fails[start].time > window:
                start += 1
            best = max(best, end - start + 1)
        if best >= threshold:
            alerts.append(
                Alert(
                    "brute_force",
                    "high" if best >= threshold * 3 else "medium",
                    ip,
                    f"{best} failed logins within {int(window.total_seconds() // 60)} min",
                    {"max_in_window": best, "total_failures": len(fails)},
                )
            )
    return alerts


def detect_password_spraying(
    events: Sequence[Event], min_users: int = 4, window: timedelta = timedelta(minutes=30)
) -> List[Alert]:
    """One IP trying many distinct usernames (spray / enumeration)."""
    alerts: List[Alert] = []
    for ip, evs in _by_ip(events).items():
        fails = [e for e in evs if e.kind in ("failed", "invalid")]
        start, best_users = 0, set()
        for end in range(len(fails)):
            while fails[end].time - fails[start].time > window:
                start += 1
            users = {e.user for e in fails[start : end + 1]}
            if len(users) > len(best_users):
                best_users = users
        if len(best_users) >= min_users:
            alerts.append(
                Alert(
                    "password_spraying",
                    "high",
                    ip,
                    f"{len(best_users)} distinct usernames attempted",
                    {"users": sorted(best_users)},
                )
            )
    return alerts


def detect_compromise(
    events: Sequence[Event], min_failures: int = 3, window: timedelta = timedelta(minutes=10)
) -> List[Alert]:
    """A successful login shortly after repeated failures from the same IP."""
    alerts: List[Alert] = []
    for ip, evs in _by_ip(events).items():
        for i, ev in enumerate(evs):
            if ev.kind != "accepted":
                continue
            prior = [
                e
                for e in evs[:i]
                if e.kind in ("failed", "invalid") and ev.time - e.time <= window
            ]
            if len(prior) >= min_failures:
                alerts.append(
                    Alert(
                        "possible_compromise",
                        "critical",
                        ip,
                        f"Successful login as '{ev.user}' after {len(prior)} failures",
                        {"user": ev.user, "time": ev.time.isoformat(), "prior_failures": len(prior)},
                    )
                )
                break
    return alerts


def run_all(events: Sequence[Event]) -> List[Alert]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts = detect_brute_force(events) + detect_password_spraying(events) + detect_compromise(events)
    return sorted(alerts, key=lambda a: (order[a.severity], a.ip))
