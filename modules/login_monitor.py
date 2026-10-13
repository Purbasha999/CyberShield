import os
import re
import subprocess
import threading
import time
from collections import deque
from datetime import datetime


class LoginMonitor(threading.Thread):
    FAILED_PATTERNS = (
        "Failed password",
        "authentication failure",
        "FAILED LOGIN",
        "Failed login",
    )

    def __init__(self, config, alerts, stop_event):
        super().__init__(daemon=True, name="LoginMonitor")
        login_cfg = config["login"]
        self.threshold = login_cfg["failed_attempt_threshold"]
        self.window = login_cfg["window_seconds"]
        self.poll_interval = login_cfg["poll_interval_seconds"]
        self.alerts = alerts
        self.stop_event = stop_event
        self.failed_events = deque()
        self.last_size = 0

    def _auth_log_path(self):
        if os.path.exists("/var/log/auth.log"):
            return "/var/log/auth.log"
        if os.path.exists("/var/log/secure"):
            return "/var/log/secure"
        return None

    def _read_new_lines(self):
        path = self._auth_log_path()

        if path:
            try:
                size = os.path.getsize(path)
                if size < self.last_size:
                    self.last_size = 0

                with open(path, "r", encoding="utf-8", errors="ignore") as file:
                    file.seek(self.last_size)
                    data = file.read()
                    self.last_size = file.tell()
                return data.splitlines()
            except (PermissionError, OSError):
                return []

        try:
            result = subprocess.run(
                ["journalctl", "-n", "50", "--no-pager", "-o", "short-iso"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False
            )
            return result.stdout.splitlines()
        except (OSError, subprocess.SubprocessError):
            return []

    def _is_failed(self, line):
        return any(pattern.lower() in line.lower() for pattern in self.FAILED_PATTERNS)

    def process_lines(self, lines, now=None):
        now = now or time.time()

        for line in lines:
            if self._is_failed(line):
                self.failed_events.append(now)
                self.alerts.raise_alert(
                    "LOGIN_FAILURE",
                    "HIGH" if self._recent_failures(now) >= self.threshold else "MEDIUM",
                    "Failed authentication attempt detected",
                    {"message": line[-250:]}
                )

        cutoff = now - self.window
        while self.failed_events and self.failed_events[0] < cutoff:
            self.failed_events.popleft()

        if len(self.failed_events) >= self.threshold:
            self.alerts.raise_alert(
                "LOGIN_BRUTE_FORCE",
                "HIGH",
                f"{len(self.failed_events)} failed authentication attempts in {self.window} seconds",
                {"count": len(self.failed_events), "window_seconds": self.window}
            )

    def _recent_failures(self, now):
        cutoff = now - self.window
        return sum(timestamp >= cutoff for timestamp in self.failed_events)

    def run(self):
        while not self.stop_event.is_set():
            self.process_lines(self._read_new_lines())
            self.stop_event.wait(self.poll_interval)
