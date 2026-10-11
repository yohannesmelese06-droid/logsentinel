from datetime import timedelta

from logsentinel.detectors import (
    detect_brute_force,
    detect_compromise,
    detect_password_spraying,
    run_all,
)
from logsentinel.parser import parse_line, parse_lines

YEAR = 2026


def _events(lines):
    return list(parse_lines(lines, YEAR))


def fail(sec, user="bob", ip="1.2.3.4"):
    return f"Oct 11 03:00:{sec:02d} h sshd[1]: Failed password for {user} from {ip} port 22 ssh2"


def test_parse_failed_invalid_user():
    ev = parse_line(
        "Oct 11 03:12:43 web01 sshd[2103]: Failed password for invalid user root from 203.0.113.5 port 52144 ssh2",
        YEAR,
    )
    assert ev and ev.kind == "failed" and ev.user == "root" and ev.ip == "203.0.113.5"


def test_parse_accepted_and_ignores_noise():
    ok = parse_line("Oct  1 09:15:02 h sshd[1]: Accepted publickey for alice from 192.0.2.10 port 5 ssh2", YEAR)
    assert ok and ok.kind == "accepted"
    assert parse_line("Oct 11 10:00:00 h CRON[1]: session opened", YEAR) is None
    assert parse_line("garbage", YEAR) is None


def test_brute_force_triggers_at_threshold():
    evs = _events([fail(s) for s in range(5)])
    alerts = detect_brute_force(evs, threshold=5)
    assert len(alerts) == 1 and alerts[0].ip == "1.2.3.4"


def test_brute_force_respects_window():
    lines = [fail(s * 20 % 60) for s in range(0, 4)]
    evs = _events(lines)
    assert detect_brute_force(evs, threshold=5) == []
    assert detect_brute_force(evs, threshold=5, window=timedelta(seconds=1)) == []


def test_password_spraying():
    evs = _events([fail(i, user=f"u{i}") for i in range(5)])
    alerts = detect_password_spraying(evs, min_users=4)
    assert len(alerts) == 1 and len(alerts[0].details["users"]) == 5


def test_compromise_after_failures():
    lines = [fail(i) for i in range(4)]
    lines.append("Oct 11 03:01:00 h sshd[1]: Accepted password for bob from 1.2.3.4 port 22 ssh2")
    alerts = detect_compromise(_events(lines))
    assert len(alerts) == 1 and alerts[0].severity == "critical"


def test_clean_user_not_flagged():
    lines = [fail(1, user="alice", ip="9.9.9.9"),
             "Oct 11 03:00:30 h sshd[1]: Accepted publickey for alice from 9.9.9.9 port 22 ssh2"]
    assert run_all(_events(lines)) == []
