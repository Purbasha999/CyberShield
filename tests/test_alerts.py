"""Alert engine, event logger and SQLite event store."""

import pytest

from security.alert_manager import AlertManager
from security.event_logger import EventLogger
from security.events import HIGH, INFO, LOW, MEDIUM, SEVERITY_RANK, SecurityEvent


def ev(severity=LOW, module="process", key=None, ts=1000.0, title="Something happened"):
    return SecurityEvent(module, severity, title, {"x": 1}, key=key, timestamp=ts)


def test_unknown_severity_rejected():
    with pytest.raises(ValueError):
        SecurityEvent("process", "SEVERE", "bad")


def test_severity_ranking():
    assert SEVERITY_RANK[HIGH] > SEVERITY_RANK[MEDIUM] > SEVERITY_RANK[LOW] > SEVERITY_RANK[INFO]


def test_cooldown_suppresses_duplicate_keys():
    manager = AlertManager(cooldown_seconds=60)
    assert len(manager.process([ev(key="k")], now=1000)) == 1
    assert manager.process([ev(key="k")], now=1030) == []
    assert manager.suppressed == 1
    assert len(manager.process([ev(key="k")], now=1061)) == 1


def test_events_without_key_are_never_suppressed():
    manager = AlertManager(cooldown_seconds=60)
    assert len(manager.process([ev(), ev(), ev()], now=1000)) == 3


def test_info_events_are_counted_but_not_alerts():
    manager = AlertManager()
    manager.process([ev(INFO), ev(HIGH)])
    assert manager.counts[INFO] == 1 and manager.counts[HIGH] == 1
    assert [a.severity for a in manager.recent_alerts()] == [HIGH]


def test_recent_alerts_newest_first_and_filtered():
    manager = AlertManager()
    manager.process([ev(LOW, title="first"), ev(MEDIUM, title="second"), ev(HIGH, title="third")])
    assert [a.title for a in manager.recent_alerts()] == ["third", "second", "first"]
    assert [a.title for a in manager.recent_alerts(min_severity=MEDIUM)] == ["third", "second"]


@pytest.mark.parametrize(
    "severities, expected",
    [([], "SECURE"), ([INFO], "SECURE"), ([LOW], "NOTICE"), ([LOW, MEDIUM], "WARNING"), ([LOW, HIGH, MEDIUM], "CRITICAL")],
)
def test_overall_status(severities, expected):
    manager = AlertManager()
    manager.process([ev(s, ts=1000) for s in severities])
    assert manager.overall_status(window_seconds=300, now=1100) == expected


def test_status_returns_to_safe_after_window():
    manager = AlertManager()
    manager.process([ev(HIGH, module="login", ts=1000)])
    assert manager.module_status("login", 300, now=1100) == "WARNING"
    assert manager.module_status("file", 300, now=1100) == "SAFE"
    assert manager.module_status("login", 300, now=1400) == "SAFE"
    assert manager.overall_status(300, now=1400) == "SECURE"


def test_event_logger_writes_file_and_database(tmp_path, db):
    logger = EventLogger(tmp_path / "logs", db)
    try:
        manager = AlertManager(logger)
        manager.process([ev(HIGH, module="login", title="Multiple failed login attempts")])
        manager.process([ev(INFO, module="login", title="Successful login")])
    finally:
        logger.close()
    text = (tmp_path / "logs" / "security_events.log").read_text()
    assert "[HIGH] login: Multiple failed login attempts" in text
    assert "[INFO] login: Successful login" in text
    stored = db.recent_events()
    assert [e["title"] for e in stored] == ["Successful login", "Multiple failed login attempts"]
    assert stored[1]["details"] == {"x": 1}


def test_suppressed_events_are_not_logged(tmp_path, db):
    logger = EventLogger(tmp_path / "logs", db)
    try:
        AlertManager(logger, cooldown_seconds=60).process([ev(key="dup"), ev(key="dup")], now=1000)
    finally:
        logger.close()
    assert len(db.recent_events()) == 1


# ---- database queries ----

def test_recent_events_filters(db):
    for severity, module in [(INFO, "login"), (LOW, "resource"), (MEDIUM, "file"), (HIGH, "login")]:
        db.insert_event(ev(severity, module=module))
    assert len(db.recent_events()) == 4
    assert {e["severity"] for e in db.recent_events(min_severity=MEDIUM)} == {MEDIUM, HIGH}
    assert {e["severity"] for e in db.recent_events(module="login")} == {INFO, HIGH}
    assert len(db.recent_events(limit=2)) == 2


def test_severity_counts_since(db):
    db.insert_event(ev(HIGH, ts=100))
    db.insert_event(ev(HIGH, ts=5000))
    db.insert_event(ev(LOW, ts=5000))
    assert db.severity_counts(since=1000) == {INFO: 0, LOW: 1, MEDIUM: 0, HIGH: 1}


def test_hourly_counts_buckets(db):
    now = 10 * 3600 + 1800  # 10:30
    db.insert_event(ev(HIGH, ts=10 * 3600 + 60))     # current hour
    db.insert_event(ev(MEDIUM, ts=9 * 3600 + 60))    # previous hour
    db.insert_event(ev(LOW, ts=9 * 3600 + 120))
    db.insert_event(ev(INFO, ts=9 * 3600 + 120))     # INFO is not an alert
    db.insert_event(ev(HIGH, ts=1))                  # outside 3h window
    buckets = db.hourly_counts(hours=3, now=now)
    assert [b["hour"] for b in buckets] == [8 * 3600, 9 * 3600, 10 * 3600]
    assert buckets[1] == {"hour": 9 * 3600, "LOW": 1, "MEDIUM": 1, "HIGH": 0}
    assert buckets[2]["HIGH"] == 1
    assert buckets[0] == {"hour": 8 * 3600, "LOW": 0, "MEDIUM": 0, "HIGH": 0}
