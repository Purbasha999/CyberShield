import os
import shutil
import subprocess
import sys
import time

import psutil
import pytest

from modules.process_monitor import ProcessMonitor, assess_process
from security.events import LOW, MEDIUM
from tests.conftest import linux_only

RULES = {"suspicious_names": ["xmrig", "nc"], "suspicious_paths": ["/tmp/", "/dev/shm/"]}


def make_cfg(**overrides):
    cfg = {
        "cpu_threshold": 1000, "memory_threshold": 100, "sustain_polls": 2, "top_n": 10,
        "suspicious_names": ["xmrig"], "suspicious_paths": ["/tmp/", "/dev/shm/", "/var/tmp/"],
    }
    cfg.update(overrides)
    return cfg


def events_for(events, pid, title):
    return [e for e in events if e.details.get("pid") == pid and e.title == title]


# ---- pure rule checks ----

def test_clean_process_has_no_findings():
    info = {"name": "bash", "exe": "/usr/bin/bash", "cmdline": ["/usr/bin/bash"]}
    assert assess_process(info, RULES) == []


def test_suspicious_name_detected_case_insensitive():
    findings = assess_process({"name": "XMRig", "exe": "/opt/x/xmrig", "cmdline": []}, RULES)
    assert [f[0] for f in findings] == ["name"]
    assert findings[0][1] == MEDIUM


def test_suspicious_name_detected_from_argv0():
    findings = assess_process({"name": "python3", "exe": "/usr/bin/python3", "cmdline": ["/usr/bin/nc", "-l"]}, RULES)
    assert [f[0] for f in findings] == ["name"]


def test_temp_directory_executable_detected():
    findings = assess_process({"name": "updater", "exe": "/dev/shm/updater", "cmdline": []}, RULES)
    assert [f[0] for f in findings] == ["path"]


def test_access_denied_fields_are_tolerated():
    assert assess_process({"name": None, "exe": None, "cmdline": None}, RULES) == []


# ---- live checks against the real OS ----

def test_snapshot_lists_running_processes():
    monitor = ProcessMonitor(make_cfg())
    snapshot, _ = monitor.poll()
    assert snapshot["total"] > 1
    cpus = [p["cpu_percent"] for p in snapshot["top"]]
    assert cpus == sorted(cpus, reverse=True)
    assert len(snapshot["top"]) <= 10
    for row in snapshot["top"]:
        assert {"pid", "name", "user", "status", "cpu_percent", "memory_percent", "state"} <= row.keys()


@linux_only
def test_cpu_intensive_process_triggers_one_alert():
    """Spec test case: 'Start a CPU-intensive process -> process should appear in monitor'."""
    child = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    try:
        monitor = ProcessMonitor(make_cfg(cpu_threshold=50, sustain_polls=2))
        all_events = []
        for _ in range(5):
            snapshot, events = monitor.poll()
            all_events += events
            time.sleep(0.5)
        hits = events_for(all_events, child.pid, "High CPU process detected")
        assert len(hits) == 1, "alert once per episode, not on every poll"
        assert hits[0].severity == LOW
        assert snapshot["top"][0]["pid"] == child.pid or child.pid in {p["pid"] for p in snapshot["flagged"]}
    finally:
        child.kill()
        child.wait()


@linux_only
def test_short_cpu_spike_is_ignored_until_sustained():
    child = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    try:
        monitor = ProcessMonitor(make_cfg(cpu_threshold=50, sustain_polls=100))
        monitor.poll()
        time.sleep(0.5)
        _, events = monitor.poll()
        assert not events_for(events, child.pid, "High CPU process detected")
    finally:
        child.kill()
        child.wait()


@linux_only
def test_miner_named_binary_in_tmp_is_flagged(tmp_path):
    """A binary called 'xmrig' running from /tmp triggers both the name and location rules."""
    # A copy of the Python interpreter that just sleeps. (coreutils' sleep is a multi-call
    # binary on newer Ubuntu and refuses to run under a different name.)
    fake = tmp_path / "xmrig"
    shutil.copy(os.path.realpath(sys.executable), fake)
    fake.chmod(0o755)
    if not str(fake.resolve()).startswith("/tmp/"):
        pytest.skip("pytest tmp dir is not under /tmp")
    child = subprocess.Popen([str(fake), "-c", "import time; time.sleep(30)"])
    try:
        time.sleep(0.3)
        monitor = ProcessMonitor(make_cfg())
        snapshot, events = monitor.poll()
        titles = {e.title for e in events if e.details.get("pid") == child.pid}
        assert titles == {"Suspicious process detected", "Process running from temporary directory"}
        assert child.pid in {p["pid"] for p in snapshot["flagged"]}

        _, again = monitor.poll()
        assert not [e for e in again if e.details.get("pid") == child.pid], "no repeat while the process lives"
    finally:
        child.kill()
        child.wait()


# ---- blocking CPU/memory-heavy processes ----

class FakeNotifier:
    def __init__(self):
        self.shown = []

    def notify(self, title, text):
        self.shown.append((title, text))
        return True


def poll_until_blocked(monitor, child, polls=6):
    all_events = []
    for _ in range(polls):
        _, events = monitor.poll()
        all_events += events
        if child.poll() is not None:
            break
        time.sleep(0.5)
    return all_events


@linux_only
def test_heavy_cpu_process_is_blocked_and_user_told():
    child = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    notifier = FakeNotifier()
    try:
        monitor = ProcessMonitor(make_cfg(cpu_threshold=50, sustain_polls=2, block_heavy_processes=True), notifier=notifier)
        events = poll_until_blocked(monitor, child)
        child.wait(timeout=5)  # psutil already reaped our child, so Popen can't see the signal itself
        alert = events_for(events, child.pid, "High CPU process detected")
        assert alert and alert[0].details["blocked"] is True and "Stopped" in alert[0].details["result"]
        blocked = events_for(events, child.pid, "Potentially harmful process blocked")
        assert len(blocked) == 1 and blocked[0].severity == MEDIUM
        assert len(notifier.shown) == 1 and "might be harmful" in notifier.shown[0][1]
        assert str(child.pid) in notifier.shown[0][1]
    finally:
        child.kill()
        child.wait()


@linux_only
def test_exempt_process_is_reported_but_not_blocked():
    child = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    notifier = FakeNotifier()
    try:
        name = psutil.Process(child.pid).name()
        cfg = make_cfg(cpu_threshold=50, sustain_polls=2, block_heavy_processes=True, block_exempt_names=[name])
        monitor = ProcessMonitor(cfg, notifier=notifier)
        events = poll_until_blocked(monitor, child, polls=4)
        assert child.poll() is None, "exempt process keeps running"
        alert = events_for(events, child.pid, "High CPU process detected")
        assert alert and alert[0].details["blocked"] is False
        assert "block_exempt_names" in alert[0].details["result"]
        assert notifier.shown == []
    finally:
        child.kill()
        child.wait()


@linux_only
def test_blocking_off_only_reports():
    child = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    try:
        monitor = ProcessMonitor(make_cfg(cpu_threshold=50, sustain_polls=2, block_heavy_processes=False))
        events = poll_until_blocked(monitor, child, polls=4)
        assert child.poll() is None
        assert events_for(events, child.pid, "High CPU process detected")
        assert not events_for(events, child.pid, "Potentially harmful process blocked")
    finally:
        child.kill()
        child.wait()


def test_never_blocks_itself_or_its_parent():
    monitor = ProcessMonitor(make_cfg(block_heavy_processes=True))
    me = psutil.Process()
    for proc in [me, *me.parents()[:1]]:
        info = {"pid": proc.pid, "name": proc.name()}
        ok, message = monitor._block(info, (proc.pid, proc.create_time()))
        assert ok is False and "not blocked" in message
