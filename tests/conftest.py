import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.loader import load_config  # noqa: E402
from database.db import EventDatabase  # noqa: E402

linux_only = pytest.mark.skipif(sys.platform != "linux", reason="needs Linux /proc and permissions")
not_root = pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file permissions")


def auth_line(message, ts=None, host="testhost"):
    """Build an auth.log line in rsyslog's RFC3339 format."""
    stamp = datetime.fromtimestamp(ts if ts is not None else datetime.now().timestamp(), timezone.utc)
    return f"{stamp.isoformat()} {host} {message}\n"


@pytest.fixture
def watch_dir(tmp_path):
    path = tmp_path / "watch"
    path.mkdir()
    (path / "a.txt").write_text("alpha\n")
    (path / "b.conf").write_text("setting=1\n")
    return path


@pytest.fixture
def auth_log(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("")
    return path


@pytest.fixture
def config(tmp_path, watch_dir, auth_log):
    return load_config(
        tmp_path / "does-not-exist.json",
        overrides={
            "data_dir": str(tmp_path / "data"),
            "dashboard": {"port": 0},
            "alerts": {"cooldown_seconds": 60, "status_window_seconds": 300},
            # Never open real Windows/zenity dialogs during tests.
            "approvals": {"popup": "off", "timeout_seconds": 60},
            # High thresholds so the real machine's load does not create surprise alerts in tests.
            "process_monitor": {"cpu_threshold": 1000, "memory_threshold": 100, "suspicious_names": ["xmrig"]},
            "resource_monitor": {"cpu_threshold": 101, "memory_threshold": 101, "disk_threshold": 101},
            "file_monitor": {"watch_paths": [str(watch_dir)]},
            "login_monitor": {"log_path": str(auth_log), "max_failed_attempts": 3, "window_seconds": 300},
        },
    )


@pytest.fixture
def db(tmp_path):
    database = EventDatabase(tmp_path / "test.db")
    yield database
    database.close()
