import unittest

from modules.login_monitor import LoginMonitor


class FakeAlerts:
    def __init__(self):
        self.items = []

    def raise_alert(self, source, severity, message, details=None):
        self.items.append((source, severity, message, details))


class LoginMonitorTests(unittest.TestCase):
    def test_failed_login_detection(self):
        alerts = FakeAlerts()

        config = {
            "login": {
                "failed_attempt_threshold": 3,
                "window_seconds": 300,
                "poll_interval_seconds": 1
            }
        }

        import threading
        monitor = LoginMonitor(config, alerts, threading.Event())

        lines = [
            "Failed password for invalid user test",
            "Failed password for invalid user test",
            "Failed password for invalid user test"
        ]

        monitor.process_lines(lines, now=1000)

        self.assertGreaterEqual(len(alerts.items), 3)
        self.assertTrue(any(item[0] == "LOGIN_BRUTE_FORCE" for item in alerts.items))


if __name__ == "__main__":
    unittest.main()
