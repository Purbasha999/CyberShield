import threading
import unittest

from modules.login_monitor import LoginMonitor


class FakeAlerts:
    def __init__(self):
        self.items = []

    def raise_alert(self, source, severity, message, details=None):
        self.items.append((source, severity, message, details))


def make_monitor(alerts, threshold=3):
    config = {
        "login": {
            "failed_attempt_threshold": threshold,
            "window_seconds": 300,
            "poll_interval_seconds": 1
        }
    }
    return LoginMonitor(config, alerts, threading.Event())


class LoginMonitorTests(unittest.TestCase):
    def test_failed_login_detection(self):
        alerts = FakeAlerts()
        monitor = make_monitor(alerts)

        lines = ["Failed password for invalid user test"] * 3
        monitor.process_lines(lines, now=1000)

        self.assertGreaterEqual(len(alerts.items), 3)
        self.assertTrue(any(item[0] == "LOGIN_BRUTE_FORCE" for item in alerts.items))

    def test_brute_force_alert_raised_once(self):
        alerts = FakeAlerts()
        monitor = make_monitor(alerts)

        monitor.process_lines(["Failed password for root"] * 3, now=1000)
        monitor.process_lines([], now=1005)
        monitor.process_lines([], now=1010)

        brute_force = [item for item in alerts.items if item[0] == "LOGIN_BRUTE_FORCE"]
        self.assertEqual(len(brute_force), 1)

    def test_brute_force_rearms_after_window(self):
        alerts = FakeAlerts()
        monitor = make_monitor(alerts)

        monitor.process_lines(["Failed password for root"] * 3, now=1000)
        monitor.process_lines([], now=1400)   # window expired
        monitor.process_lines(["Failed password for root"] * 3, now=1500)

        brute_force = [item for item in alerts.items if item[0] == "LOGIN_BRUTE_FORCE"]
        self.assertEqual(len(brute_force), 2)


if __name__ == "__main__":
    unittest.main()
