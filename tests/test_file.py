import tempfile
import threading
import unittest
from pathlib import Path

from modules.file_monitor import FileIntegrityMonitor


class FakeAlerts:
    def __init__(self):
        self.items = []

    def raise_alert(self, source, severity, message, details=None):
        self.items.append((source, severity, message, details))


class FileIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        (self.base / "watched").mkdir()
        self.sample = self.base / "watched" / "sample.txt"
        self.sample.write_text("original", encoding="utf-8")

        config = {"file_integrity": {"monitor_path": "watched", "scan_interval_seconds": 1}}
        self.alerts = FakeAlerts()
        self.monitor = FileIntegrityMonitor(config, self.alerts, threading.Event(), str(self.base))

    def tearDown(self):
        self.temp.cleanup()

    def events(self):
        return [item[3]["event"] for item in self.alerts.items]

    def test_sha256_is_64_hex_chars(self):
        self.assertEqual(len(FileIntegrityMonitor.sha256(str(self.sample))), 64)

    def test_unchanged_file_raises_nothing(self):
        self.monitor.scan_once()
        self.assertEqual(self.alerts.items, [])

    def test_modification_reported_once(self):
        self.sample.write_text("modified", encoding="utf-8")
        self.monitor.scan_once()
        self.monitor.scan_once()
        self.assertEqual(self.events(), ["modified"])

    def test_deletion_and_creation_reported_once(self):
        self.sample.unlink()
        (self.base / "watched" / "new.txt").write_text("new", encoding="utf-8")
        self.monitor.scan_once()
        self.monitor.scan_once()
        self.assertEqual(sorted(self.events()), ["created", "deleted"])


if __name__ == "__main__":
    unittest.main()
