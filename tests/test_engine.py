"""Integration: all modules running together through the security engine."""

import os
import time

from security.engine import SecurityEngine
from tests.conftest import auth_line

SSH_FAIL = "sshd[1201]: Failed password for root from 203.0.113.50 port 51234 ssh2"


def test_run_once_produces_state_for_every_module(config):
    engine = SecurityEngine(config)
    try:
        engine.run_once()
        state = engine.get_state()
    finally:
        engine.stop()
    assert set(state["modules"]) == {"process", "file", "login", "resource"}
    for name, module in state["modules"].items():
        assert module["snapshot"] is not None, name
        assert module["error"] is None, name
        assert module["status"] == "SAFE", name
    assert state["overall"] == "SECURE"
    assert len(state["history"]) == 1
    assert len(state["timeline_24h"]) == 24


def test_attack_scenario_end_to_end(config, watch_dir, auth_log):
    """Spec test case: 'Trigger security condition -> alert generated and logged'."""
    engine = SecurityEngine(config)
    try:
        engine.run_once()  # baseline
        with open(auth_log, "a") as fh:
            fh.writelines(auth_line(SSH_FAIL) for _ in range(5))
        (watch_dir / "a.txt").write_text("tampered\n")
        accepted = engine.run_once()
        state = engine.get_state()
    finally:
        engine.stop()

    alert_titles = {(e.severity, e.title) for e in accepted if e.is_alert}
    assert ("HIGH", "Multiple failed login attempts") in alert_titles
    assert ("MEDIUM", "File modification detected") in alert_titles

    assert state["overall"] == "CRITICAL"
    assert state["modules"]["login"]["status"] == "WARNING"
    assert state["modules"]["file"]["status"] == "WARNING"
    assert state["modules"]["resource"]["status"] == "SAFE"
    assert state["severity_counts_24h"]["HIGH"] == 1
    assert state["alerts"][0]["severity"] in ("HIGH", "MEDIUM")

    log_text = open(os.path.join(config["data_dir"], "logs", "security_events.log")).read()
    assert "[HIGH] login: Multiple failed login attempts" in log_text
    assert "[MEDIUM] file: File modification detected" in log_text
    assert os.path.exists(os.path.join(config["data_dir"], "cyber_events.db"))


def test_failing_module_is_isolated(config, monkeypatch):
    engine = SecurityEngine(config)
    try:
        def boom():
            raise RuntimeError("simulated crash")
        monkeypatch.setattr(engine.monitors["process"], "poll", boom)
        engine.run_once()
        state = engine.get_state()
    finally:
        engine.stop()
    assert state["modules"]["process"]["status"] == "ERROR"
    assert "simulated crash" in state["modules"]["process"]["error"]
    assert state["modules"]["resource"]["status"] == "SAFE"
    assert any(a["title"] == "Monitor error" for a in state["alerts"])


def test_disabled_module_is_not_started(config):
    config["login_monitor"]["enabled"] = False
    engine = SecurityEngine(config)
    try:
        assert "login" not in engine.monitors
        engine.run_once()
        assert "login" not in engine.get_state()["modules"]
    finally:
        engine.stop()


def test_background_threads_poll_and_stop(config):
    for section in ("process_monitor", "file_monitor", "login_monitor", "resource_monitor"):
        config[section]["interval_seconds"] = 0.2
    engine = SecurityEngine(config)
    engine.start()
    try:
        time.sleep(1.0)
        state = engine.get_state()
        assert all(m["last_poll"] for m in state["modules"].values())
        assert len(state["history"]) >= 3
    finally:
        threads = list(engine._threads)
        engine.stop()
    assert threads and all(not t.is_alive() for t in threads)


def test_rebaseline_through_engine(config, watch_dir):
    engine = SecurityEngine(config)
    try:
        engine.run_once()
        (watch_dir / "a.txt").write_text("approved\n")
        assert engine.rebaseline_files() is True
        accepted = engine.run_once()
    finally:
        engine.stop()
    assert not [e for e in accepted if e.module == "file" and e.is_alert]
