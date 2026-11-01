from types import SimpleNamespace

import pytest

import modules.resource_monitor as rm
from modules.resource_monitor import ResourceMonitor
from security.events import LOW

CFG = {"cpu_threshold": 90, "memory_threshold": 90, "disk_threshold": 90, "sustain_polls": 3, "disk_paths": ["/"]}


def test_real_snapshot_has_sane_values():
    monitor = ResourceMonitor(dict(CFG, cpu_threshold=101, memory_threshold=101, disk_threshold=101))
    snapshot, events = monitor.poll()
    assert events == []
    assert 0 <= snapshot["cpu_percent"] <= 100
    assert 0 < snapshot["memory"]["percent"] <= 100
    assert snapshot["memory"]["total"] > 0
    assert 0 < snapshot["disk_percent"] <= 100
    assert snapshot["process_count"] > 1
    assert len(snapshot["per_cpu"]) == snapshot["cpu_count"]
    assert snapshot["uptime_seconds"] > 0


@pytest.fixture
def fake_load(monkeypatch):
    """Lets a test dial CPU / RAM / disk percentages directly."""
    load = {"cpu": 10.0, "memory": 40.0, "disk": 50.0}
    monkeypatch.setattr(rm.psutil, "cpu_percent", lambda interval=None, percpu=False: [load["cpu"]] * 4 if percpu else load["cpu"])
    monkeypatch.setattr(
        rm.psutil, "virtual_memory",
        lambda: SimpleNamespace(percent=load["memory"], used=4 * 2**30, total=8 * 2**30, available=4 * 2**30),
    )
    monkeypatch.setattr(
        rm.psutil, "disk_usage",
        lambda path: SimpleNamespace(percent=load["disk"], used=50, total=100, free=50),
    )
    return load


def poll_titles(monitor):
    return [e.title for e in monitor.poll()[1]]


def test_high_cpu_alerts_only_after_sustained_polls(fake_load):
    monitor = ResourceMonitor(CFG)
    fake_load["cpu"] = 97.0
    assert poll_titles(monitor) == []
    assert poll_titles(monitor) == []
    snapshot, events = monitor.poll()
    assert [e.title for e in events] == ["High CPU utilization"]
    assert events[0].severity == LOW
    assert events[0].details["value"] == 97.0
    # Still high: same episode, no new alert.
    assert poll_titles(monitor) == []


def test_cpu_alert_rearms_after_recovery(fake_load):
    monitor = ResourceMonitor(dict(CFG, sustain_polls=1))
    fake_load["cpu"] = 95.0
    assert poll_titles(monitor) == ["High CPU utilization"]
    fake_load["cpu"] = 20.0
    assert poll_titles(monitor) == []
    fake_load["cpu"] = 95.0
    assert poll_titles(monitor) == ["High CPU utilization"]


def test_high_memory_alert(fake_load):
    monitor = ResourceMonitor(dict(CFG, sustain_polls=1))
    fake_load["memory"] = 93.5
    _, events = monitor.poll()
    assert [e.title for e in events] == ["High RAM utilization"]
    assert events[0].details["total_mb"] == 8192


def test_disk_alert_is_immediate(fake_load):
    monitor = ResourceMonitor(CFG)  # sustain_polls=3 does not apply to disk
    fake_load["disk"] = 96.0
    _, events = monitor.poll()
    assert [e.title for e in events] == ["High disk utilization"]
    assert events[0].details["path"] == "/"


def test_normal_load_is_quiet(fake_load):
    monitor = ResourceMonitor(dict(CFG, sustain_polls=1))
    for _ in range(3):
        assert poll_titles(monitor) == []
