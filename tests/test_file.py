import hashlib
import os

from modules.file_monitor import FileMonitor, sha256_file
from security.events import INFO, LOW, MEDIUM
from tests.conftest import linux_only, not_root


def make_monitor(db, watch_paths, **overrides):
    cfg = {
        "watch_paths": [str(p) for p in watch_paths],
        "exclude": [".git", "*.tmp", "*.swp"],
        "recursive": True,
        "fast_mode": False,
        "max_file_size_mb": 50,
    }
    cfg.update(overrides)
    return FileMonitor(cfg, db)


def alerts(events):
    return [(e.title, os.path.basename(e.details["path"])) for e in events if e.severity != INFO]


def test_sha256_matches_hashlib(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(os.urandom(200_000))
    assert sha256_file(f) == hashlib.sha256(f.read_bytes()).hexdigest()


def test_first_scan_builds_baseline_silently(db, watch_dir):
    monitor = make_monitor(db, [watch_dir])
    snapshot, events = monitor.poll()
    assert alerts(events) == []
    assert [e.title for e in events] == ["Integrity baseline created"]
    assert snapshot["total_files"] == 2
    _, events = monitor.poll()
    assert events == []


def test_modified_file_detected_once(db, watch_dir):
    """Spec test case: 'Modify monitored file -> modification alert generated'."""
    monitor = make_monitor(db, [watch_dir])
    monitor.poll()
    (watch_dir / "a.txt").write_text("alpha CHANGED\n")
    snapshot, events = monitor.poll()
    assert alerts(events) == [("File modification detected", "a.txt")]
    assert events[0].severity == MEDIUM
    assert events[0].details["old_hash"] != events[0].details["new_hash"]
    assert snapshot["recent_changes"][0]["title"] == "File modification detected"
    _, events = monitor.poll()
    assert events == [], "the new content becomes the baseline after it is reported"


def test_new_and_deleted_files_detected(db, watch_dir):
    monitor = make_monitor(db, [watch_dir])
    monitor.poll()
    (watch_dir / "new.sh").write_text("echo hi\n")
    (watch_dir / "b.conf").unlink()
    _, events = monitor.poll()
    assert sorted(alerts(events)) == [("Monitored file deleted", "b.conf"), ("New file detected", "new.sh")]
    severities = {e.title: e.severity for e in events}
    assert severities["New file detected"] == LOW
    assert severities["Monitored file deleted"] == MEDIUM


def test_nested_directories_are_watched(db, watch_dir):
    nested = watch_dir / "sub" / "deeper"
    nested.mkdir(parents=True)
    (nested / "secret.key").write_text("k1")
    monitor = make_monitor(db, [watch_dir])
    monitor.poll()
    (nested / "secret.key").write_text("k2")
    assert alerts(monitor.poll()[1]) == [("File modification detected", "secret.key")]


def test_non_recursive_ignores_subfolders(db, watch_dir):
    (watch_dir / "sub").mkdir()
    (watch_dir / "sub" / "x.txt").write_text("1")
    monitor = make_monitor(db, [watch_dir], recursive=False)
    snapshot, _ = monitor.poll()
    assert snapshot["total_files"] == 2


@linux_only
def test_permission_change_detected(db, watch_dir):
    monitor = make_monitor(db, [watch_dir])
    monitor.poll()
    os.chmod(watch_dir / "a.txt", 0o777)
    _, events = monitor.poll()
    assert alerts(events) == [("File permissions changed", "a.txt")]
    assert events[0].details["new_mode"] == "0o777"


def test_excluded_files_and_dirs_are_ignored(db, watch_dir):
    monitor = make_monitor(db, [watch_dir])
    monitor.poll()
    (watch_dir / "scratch.tmp").write_text("temp")
    (watch_dir / ".git").mkdir()
    (watch_dir / ".git" / "index").write_text("git stuff")
    assert monitor.poll()[1] == []


def test_absolute_exclude_path(db, watch_dir):
    (watch_dir / "data").mkdir()
    monitor = make_monitor(db, [watch_dir], exclude=[str(watch_dir / "data")])
    monitor.poll()
    (watch_dir / "data" / "cyber_events.db").write_text("x")
    assert monitor.poll()[1] == []


def test_single_file_watch_path(db, tmp_path):
    target = tmp_path / "passwd"
    target.write_text("root:x:0:0\n")
    monitor = make_monitor(db, [target])
    monitor.poll()
    target.write_text("root:x:0:0\nhacker:x:0:0\n")
    assert alerts(monitor.poll()[1]) == [("File modification detected", "passwd")]


def test_baseline_survives_restart(db, watch_dir):
    """A change made while CyberShield was not running is still caught on the next start."""
    make_monitor(db, [watch_dir]).poll()
    (watch_dir / "a.txt").write_text("changed while offline\n")
    restarted = make_monitor(db, [watch_dir])
    assert alerts(restarted.poll()[1]) == [("File modification detected", "a.txt")]


def test_rebaseline_accepts_current_state(db, watch_dir):
    monitor = make_monitor(db, [watch_dir])
    monitor.poll()
    (watch_dir / "a.txt").write_text("approved change\n")
    monitor.rebaseline()
    _, events = monitor.poll()
    assert alerts(events) == []
    assert snapshot_changes(monitor) == []


def snapshot_changes(monitor):
    return list(monitor.recent_changes)


def test_fast_mode_skips_hash_when_metadata_unchanged(db, watch_dir):
    """fast_mode trusts size+mtime; restoring mtime hides a same-size edit. Full mode still catches it."""
    target = watch_dir / "a.txt"
    fast = make_monitor(db, [watch_dir], fast_mode=True)
    fast.poll()
    st = os.stat(target)
    target.write_text("ALPHA\n")  # same size
    os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert alerts(fast.poll()[1]) == []

    full = make_monitor(db, [watch_dir], fast_mode=False)
    assert alerts(full.poll()[1]) == [("File modification detected", "a.txt")]


def test_large_files_are_skipped(db, watch_dir):
    (watch_dir / "big.iso").write_bytes(b"0" * (2 * 2**20))
    monitor = make_monitor(db, [watch_dir], max_file_size_mb=1)
    snapshot, _ = monitor.poll()
    assert snapshot["total_files"] == 2
    assert any("big.iso" in err for err in snapshot["errors"])


@linux_only
@not_root
def test_unreadable_file_is_not_reported_as_deleted(db, watch_dir):
    monitor = make_monitor(db, [watch_dir])
    monitor.poll()
    target = watch_dir / "a.txt"
    target.chmod(0o000)
    try:
        snapshot, events = monitor.poll()
        assert ("Monitored file deleted", "a.txt") not in alerts(events)
        assert snapshot["error_count"] == 1
    finally:
        target.chmod(0o644)


def test_missing_watch_path_reported(db, tmp_path):
    monitor = make_monitor(db, [tmp_path / "not-there"])
    snapshot, events = monitor.poll()
    assert snapshot["roots"][0]["exists"] is False
    assert alerts(events) == []
