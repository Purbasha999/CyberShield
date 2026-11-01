"""Confirm-or-rewind protection: approval manager, popups, file rewind, process pause."""

import os
import shutil
import subprocess
import sys
import time

import psutil
import pytest

from modules.file_monitor import FileMonitor
from modules.process_monitor import ProcessMonitor
from security.approvals import ApprovalManager
from security.events import HIGH, INFO, LOW
from security.popup import NativePrompter, message_for, parse_windows, parse_zenity
from tests.conftest import linux_only, not_root

APPROVAL_CFG = {"enabled": True, "file_changes": True, "suspicious_processes": True,
                "timeout_seconds": 60, "on_timeout": "rewind", "popup": "off"}


class Recorder:
    """Collects events the approval manager emits."""
    def __init__(self):
        self.events = []

    def __call__(self, events):
        self.events.extend(events)

    def titles(self):
        return [e.title for e in self.events]


@pytest.fixture
def emitted():
    return Recorder()


@pytest.fixture
def manager(emitted):
    return ApprovalManager(dict(APPROVAL_CFG), emit=emitted)


def ask(manager, calls, key=None, allow_result="allowed!", deny=None):
    return manager.request(
        "file", "Monitored file deleted", "/x", {"path": "/x"},
        on_allow=lambda: calls.append("allow") or allow_result,
        on_deny=deny or (lambda: calls.append("deny") or "rewound!"),
        key=key,
    )


# ---- approval manager ----

def test_allow_runs_allow_callback(manager, emitted):
    calls = []
    req = ask(manager, calls)
    assert [r["id"] for r in manager.pending()] == [req.id]
    result = manager.decide(req.id, True)
    assert calls == ["allow"]
    assert result["status"] == "allowed" and result["result"] == "allowed!"
    assert manager.pending() == []
    assert emitted.titles() == ["Change allowed by user"] and emitted.events[0].severity == INFO


def test_block_runs_rewind_callback(manager, emitted):
    calls = []
    req = ask(manager, calls)
    assert manager.decide(req.id, False)["status"] == "rewound"
    assert calls == ["deny"]
    assert emitted.events[0].title == "Change blocked and rewound" and emitted.events[0].severity == LOW


def test_first_answer_wins(manager):
    calls = []
    req = ask(manager, calls)
    manager.decide(req.id, False, source="popup")
    second = manager.decide(req.id, True, source="dashboard")
    assert calls == ["deny"]
    assert second["status"] == "rewound" and second["decided_by"] == "popup"


def test_failed_rewind_is_high_alert(manager, emitted):
    def broken():
        raise PermissionError("Permission denied: '/etc/passwd'")
    req = ask(manager, [], deny=broken)
    result = manager.decide(req.id, False)
    assert result["status"] == "failed"
    assert "sudo" in result["result"]
    assert emitted.events[0].title == "Rewind failed" and emitted.events[0].severity == HIGH


def test_same_key_reuses_pending_request(manager):
    first = ask(manager, [], key="file:/x")
    second = ask(manager, [], key="file:/x")
    assert first is second and len(manager.pending()) == 1


def test_timeout_applies_policy(emitted):
    calls = []
    rewind = ApprovalManager(dict(APPROVAL_CFG, on_timeout="rewind"), emit=emitted)
    req = ask(rewind, calls)
    rewind.expire_due(now=req.deadline - 1)
    assert calls == []
    rewind.expire_due(now=req.deadline + 0.1)
    assert calls == ["deny"]
    assert rewind.get(req.id).decided_by == "timeout"
    assert "no answer" in emitted.titles()[0]

    allow = ApprovalManager(dict(APPROVAL_CFG, on_timeout="allow"))
    req = ask(allow, calls)
    allow.expire_due(now=req.deadline + 1)
    assert calls[-1] == "allow"


def test_shutdown_settles_pending_requests(manager):
    calls = []
    ask(manager, calls)
    manager.stop()
    assert calls == ["deny"] and manager.pending() == []


def test_cancel_module(manager):
    calls = []
    req = ask(manager, calls)
    manager.cancel_module("file", "baseline reset")
    assert calls == [] and manager.get(req.id).status == "cancelled"


def test_background_timer_expires_requests(emitted):
    calls = []
    mgr = ApprovalManager(dict(APPROVAL_CFG, timeout_seconds=0.3), emit=emitted)
    mgr.start()
    try:
        ask(mgr, calls)
        deadline = time.time() + 3
        while not calls and time.time() < deadline:
            time.sleep(0.1)
    finally:
        mgr.stop()
    assert calls == ["deny"]


# ---- native popup plumbing (no real dialogs) ----

def test_popup_answer_parsing():
    assert parse_windows(0, "Yes\r\n") is True
    assert parse_windows(0, "No\n") is False
    assert parse_windows(1, "") is None
    assert parse_zenity(0, "") is True and parse_zenity(1, "") is False and parse_zenity(5, "") is None


def test_popup_message_explains_choices(manager):
    req = ask(manager, [])
    text = message_for(req, "rewind")
    assert "/x" in text and "Yes" in text and "No" in text and "blocked and rewound" in text


def test_popup_off_has_no_command():
    assert NativePrompter("off").available is False
    assert NativePrompter("off").notify("process blocked", "text") is False


def test_windows_notice_passes_text_through_environment():
    prompter = NativePrompter("off")
    prompter.kind = "windows"
    argv, env = prompter._notice_command("CyberShield OS - process blocked", "yes (PID 42) might be harmful")
    assert env["CS_MSG"] == "yes (PID 42) might be harmful" and "CS_MSG" in env["WSLENV"].split(":")
    assert "'OK'" in argv[-1] and "42" not in " ".join(argv)


@linux_only
def test_popup_answer_reaches_manager(manager, monkeypatch):
    """A fake 'dialog' that answers Yes, standing in for the Windows message box."""
    prompter = NativePrompter("off")
    monkeypatch.setattr(prompter, "_command", lambda req, on_timeout: (["sh", "-c", "echo Yes"], {}, parse_windows))
    manager.prompter = prompter
    calls = []
    req = ask(manager, calls)
    deadline = time.time() + 5
    while manager.get(req.id).status == "pending" and time.time() < deadline:
        time.sleep(0.05)
    assert calls == ["allow"] and manager.get(req.id).decided_by == "popup"


@linux_only
def test_answering_elsewhere_closes_popup(manager, monkeypatch):
    prompter = NativePrompter("off")
    monkeypatch.setattr(prompter, "_command", lambda req, on_timeout: (["sleep", "30"], {}, parse_windows))
    manager.prompter = prompter
    req = ask(manager, [])
    time.sleep(0.3)
    proc = prompter._procs[req.id]
    manager.decide(req.id, False, source="dashboard")
    assert proc.wait(timeout=5) != 0  # killed


# ---- file protection ----

def file_monitor(db, tmp_path, watch_dir, manager):
    cfg = {"watch_paths": [str(watch_dir)], "exclude": [], "recursive": True, "fast_mode": False,
           "max_file_size_mb": 50, "vault_max_mb": 1, "realtime": False}
    monitor = FileMonitor(cfg, db, str(tmp_path / "data"), manager)
    monitor.poll()  # baseline + vault
    return monitor


def only_pending(manager):
    pending = manager.pending()
    assert len(pending) == 1, pending
    return pending[0]


def test_deleted_file_is_held_and_rewound(db, tmp_path, watch_dir, manager):
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    target = watch_dir / "a.txt"
    target.unlink()
    _, events = monitor.poll()
    assert [e.title for e in events] == ["Monitored file deleted"]
    assert events[0].details["awaiting_confirmation"] is True
    req = only_pending(manager)
    assert req["summary"] == str(target)

    _, again = monitor.poll()
    assert again == [] and len(manager.pending()) == 1, "asked only once while waiting"

    result = manager.decide(req["id"], allow=False)
    assert result["status"] == "rewound", result
    assert target.read_text() == "alpha\n"
    assert monitor.poll()[1] == []


def test_deleted_file_allowed_stays_deleted(db, tmp_path, watch_dir, manager):
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    (watch_dir / "a.txt").unlink()
    monitor.poll()
    manager.decide(only_pending(manager)["id"], allow=True)
    assert not (watch_dir / "a.txt").exists()
    snapshot, events = monitor.poll()
    assert events == [] and snapshot["total_files"] == 1


def test_modified_file_rewound_to_trusted_content(db, tmp_path, watch_dir, manager):
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    target = watch_dir / "b.conf"
    target.write_text("setting=EVIL\n")
    monitor.poll()
    manager.decide(only_pending(manager)["id"], allow=False)
    assert target.read_text() == "setting=1\n"
    assert monitor.poll()[1] == []


def test_modified_file_allowed_becomes_new_baseline(db, tmp_path, watch_dir, manager):
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    target = watch_dir / "b.conf"
    target.write_text("setting=2\n")
    monitor.poll()
    manager.decide(only_pending(manager)["id"], allow=True)
    assert monitor.poll()[1] == []
    # The allowed version is now the trusted copy: a later change rewinds to it.
    target.write_text("setting=3\n")
    monitor.poll()
    manager.decide(only_pending(manager)["id"], allow=False)
    assert target.read_text() == "setting=2\n"


@linux_only
def test_permission_change_rewound(db, tmp_path, watch_dir, manager):
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    target = watch_dir / "a.txt"
    original = os.stat(target).st_mode & 0o777
    os.chmod(target, 0o777)
    monitor.poll()
    result = manager.decide(only_pending(manager)["id"], allow=False)
    assert "permissions" in result["result"]
    assert os.stat(target).st_mode & 0o777 == original


def test_new_file_blocked_goes_to_quarantine(db, tmp_path, watch_dir, manager):
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    dropped = watch_dir / "backdoor.sh"
    dropped.write_text("echo owned\n")
    _, events = monitor.poll()
    assert [e.title for e in events] == ["New file detected"]
    manager.decide(only_pending(manager)["id"], allow=False)
    assert not dropped.exists()
    quarantined = list((tmp_path / "data" / "quarantine").iterdir())
    assert len(quarantined) == 1 and quarantined[0].read_text() == "echo owned\n"
    assert monitor.poll()[1] == []


def test_new_file_allowed_is_kept(db, tmp_path, watch_dir, manager):
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    (watch_dir / "notes.md").write_text("hello")
    monitor.poll()
    manager.decide(only_pending(manager)["id"], allow=True)
    snapshot, events = monitor.poll()
    assert events == [] and snapshot["total_files"] == 3


def test_whole_folder_deleted_is_rewound(db, tmp_path, watch_dir, manager):
    nested = watch_dir / "sub"
    nested.mkdir()
    (nested / "deep.txt").write_text("deep")
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    shutil.rmtree(watch_dir)
    monitor.poll()
    for req in manager.pending():
        manager.decide(req["id"], allow=False)
    assert (watch_dir / "a.txt").read_text() == "alpha\n"
    assert (nested / "deep.txt").read_text() == "deep"


def test_change_undone_by_user_cancels_request(db, tmp_path, watch_dir, manager):
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    target = watch_dir / "a.txt"
    target.write_text("oops\n")
    monitor.poll()
    req_id = only_pending(manager)["id"]
    target.write_text("alpha\n")  # user fixed it themselves
    monitor.poll()
    assert manager.pending() == [] and manager.get(req_id).status == "cancelled"


def test_rewind_without_trusted_copy_fails_loudly(db, tmp_path, watch_dir, manager, emitted):
    (watch_dir / "big.bin").write_bytes(b"x" * (2 * 2**20))  # larger than vault_max_mb=1
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    (watch_dir / "big.bin").unlink()
    monitor.poll()
    result = manager.decide(only_pending(manager)["id"], allow=False)
    assert result["status"] == "failed" and "No trusted copy" in result["result"]
    assert emitted.events[-1].severity == HIGH


def test_vault_is_private(db, tmp_path, watch_dir, manager):
    file_monitor(db, tmp_path, watch_dir, manager)
    vault = tmp_path / "data" / "vault"
    copies = list(vault.iterdir())
    assert len(copies) == 2
    if sys.platform == "linux":
        assert all(os.stat(c).st_mode & 0o777 == 0o600 for c in copies)


def test_without_approvals_changes_are_accepted_immediately(db, tmp_path, watch_dir):
    monitor = file_monitor(db, tmp_path, watch_dir, None)
    (watch_dir / "a.txt").unlink()
    assert [e.title for e in monitor.poll()[1]] == ["Monitored file deleted"]
    assert monitor.poll()[1] == []


def test_rename_is_one_request_and_rewinds_back(db, tmp_path, watch_dir, manager):
    """Renaming in File Explorer is a delete + create with the same content: ask once, as a rename."""
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    (watch_dir / "a.txt").rename(watch_dir / "renamed.txt")
    _, events = monitor.poll()
    assert [e.title for e in events] == ["File renamed or moved"]
    req = only_pending(manager)
    assert req["details"]["old_path"] == str(watch_dir / "a.txt")
    assert monitor.poll()[1] == [] and len(manager.pending()) == 1

    result = manager.decide(req["id"], allow=False)
    assert result["status"] == "rewound" and "back to" in result["result"]
    assert (watch_dir / "a.txt").read_text() == "alpha\n" and not (watch_dir / "renamed.txt").exists()
    assert monitor.poll()[1] == []


def test_rename_allowed_moves_the_baseline(db, tmp_path, watch_dir, manager):
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    (watch_dir / "a.txt").rename(watch_dir / "renamed.txt")
    monitor.poll()
    manager.decide(only_pending(manager)["id"], allow=True)
    snapshot, events = monitor.poll()
    assert events == [] and snapshot["total_files"] == 2
    (watch_dir / "renamed.txt").write_text("changed\n")
    monitor.poll()
    manager.decide(only_pending(manager)["id"], allow=False)
    assert (watch_dir / "renamed.txt").read_text() == "alpha\n"


def test_rename_without_approvals_is_reported_once(db, tmp_path, watch_dir):
    monitor = file_monitor(db, tmp_path, watch_dir, None)
    (watch_dir / "a.txt").rename(watch_dir / "renamed.txt")
    assert [e.title for e in monitor.poll()[1]] == ["File renamed or moved"]
    assert monitor.poll()[1] == []


def test_new_file_renamed_before_answer_cancels_first_request(db, tmp_path, watch_dir, manager):
    """Explorer: New > Text Document creates 'New Text Document.txt', then the user types a name."""
    monitor = file_monitor(db, tmp_path, watch_dir, manager)
    (watch_dir / "New Text Document.txt").write_text("")
    monitor.poll()
    first = only_pending(manager)["id"]
    (watch_dir / "New Text Document.txt").rename(watch_dir / "notes.txt")
    _, events = monitor.poll()
    assert manager.get(first).status == "cancelled"
    assert [e.title for e in events] == ["New file detected"]
    assert only_pending(manager)["summary"] == str(watch_dir / "notes.txt")


@linux_only
def test_realtime_watcher_wakes_on_change(db, tmp_path, watch_dir, manager):
    cfg = {"watch_paths": [str(watch_dir)], "exclude": [], "recursive": True, "fast_mode": False,
           "max_file_size_mb": 50, "realtime": True}
    monitor = FileMonitor(cfg, db, str(tmp_path / "data"), manager)
    monitor.poll()
    assert monitor.wait_for_change(0.2) is False
    (watch_dir / "a.txt").unlink()
    started = time.time()
    assert monitor.wait_for_change(2) is True
    assert time.time() - started < 1


# ---- process protection ----

@pytest.fixture
def fake_miner(tmp_path):
    fake = tmp_path / "xmrig"
    shutil.copy(os.path.realpath(sys.executable), fake)
    fake.chmod(0o755)
    if not str(fake.resolve()).startswith("/tmp/"):
        pytest.skip("pytest tmp dir is not under /tmp")
    child = subprocess.Popen([str(fake), "-c", "import time; time.sleep(30)"])
    time.sleep(0.3)
    yield child
    child.kill()
    child.wait()


def process_monitor(manager):
    cfg = {"cpu_threshold": 1000, "memory_threshold": 100, "sustain_polls": 2, "top_n": 10,
           "suspicious_names": ["xmrig"], "suspicious_paths": ["/tmp/"]}
    return ProcessMonitor(cfg, manager)


def wait_status(pid, wanted, timeout=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = psutil.Process(pid).status()
        if status in wanted:
            return status
        time.sleep(0.05)
    return psutil.Process(pid).status()


@linux_only
def test_suspicious_process_is_paused_then_killed(manager, fake_miner):
    monitor = process_monitor(manager)
    _, events = monitor.poll()
    mine = [e for e in events if e.details.get("pid") == fake_miner.pid]
    assert mine and all(e.details["paused"] for e in mine)
    req = only_pending(manager)
    assert req["title"] == "Suspicious process paused"
    assert wait_status(fake_miner.pid, {psutil.STATUS_STOPPED}) == psutil.STATUS_STOPPED

    result = manager.decide(req["id"], allow=False)
    assert result["status"] == "rewound" and "Killed" in result["result"]
    assert fake_miner.wait(timeout=5) == -9


@linux_only
def test_suspicious_process_allowed_resumes_and_is_not_asked_again(manager, fake_miner):
    monitor = process_monitor(manager)
    monitor.poll()
    manager.decide(only_pending(manager)["id"], allow=True)
    assert wait_status(fake_miner.pid, {psutil.STATUS_SLEEPING, psutil.STATUS_RUNNING}) != psutil.STATUS_STOPPED
    monitor.poll()
    assert manager.pending() == []


@linux_only
@not_root
def test_other_users_process_cannot_be_paused(manager):
    """PID 1 belongs to root and is never touched; a root-owned suspicious process is reported, not paused."""
    monitor = process_monitor(manager)
    info = {"pid": 1, "name": "xmrig", "username": "root", "exe": "/tmp/xmrig"}
    assert monitor._pause_and_ask(info, (1, psutil.Process(1).create_time()), "test") is None
    assert manager.pending() == []
