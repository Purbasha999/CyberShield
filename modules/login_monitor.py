import os
import subprocess
import threading
import time
from collections import deque


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
        self.last_size = None          # None = first read: skip old history
        self.journal_cursor = None     # last journal entry already processed
        self.brute_force_active = False
        self.permission_warned = False

    def _auth_log_path(self):
        if os.path.exists("/var/log/auth.log"):
            return "/var/log/auth.log"
        if os.path.exists("/var/log/secure"):
            return "/var/log/secure"
        return None

    def _read_auth_file(self, path):
        try:
            size = os.path.getsize(path)
            if self.last_size is None:
                # First read: start at the end so old failures are not replayed.
                self.last_size = size
                return []
            if size < self.last_size:
                # Log was rotated: read the new file from the beginning.
                self.last_size = 0

            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                file.seek(self.last_size)
                data = file.read()
                self.last_size = file.tell()
            return data.splitlines()
        except PermissionError:
            self._warn_permission(path)
            return []
        except OSError:
            return []

    def _read_journal(self):
        first_read = self.journal_cursor is None
        command = ["journalctl", "--no-pager", "-o", "short-iso", "--show-cursor"]
        if first_read:
            # Only learn where the journal currently ends.
            command += ["-n", "1"]
        else:
            command.append(f"--after-cursor={self.journal_cursor}")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=3,
                check=False
            )
        except (OSError, subprocess.SubprocessError):
            return []

        lines = []
        for line in result.stdout.splitlines():
            if line.startswith("-- cursor: "):
                self.journal_cursor = line[len("-- cursor: "):]
            else:
                lines.append(line)

        return [] if first_read else lines

    def _read_new_lines(self):
        path = self._auth_log_path()
        if path:
            return self._read_auth_file(path)
        return self._read_journal()

    def _warn_permission(self, path):
        if self.permission_warned:
            return
        self.permission_warned = True
        self.alerts.raise_alert(
            "LOGIN_MONITOR",
            "MEDIUM",
            f"Cannot read {path}: run with sudo or add your user to the 'adm' group",
            {"path": path}
        )

    def _is_failed(self, line):
        return any(pattern.lower() in line.lower() for pattern in self.FAILED_PATTERNS)

    def _prune(self, now):
        cutoff = now - self.window
        while self.failed_events and self.failed_events[0] < cutoff:
            self.failed_events.popleft()

    def process_lines(self, lines, now=None):
        now = now or time.time()

        for line in lines:
            if self._is_failed(line):
                self.failed_events.append(now)
                self._prune(now)
                self.alerts.raise_alert(
                    "LOGIN_FAILURE",
                    "HIGH" if len(self.failed_events) >= self.threshold else "MEDIUM",
                    "Failed authentication attempt detected",
                    {"message": line[-250:]}
                )

        self._prune(now)
        count = len(self.failed_events)

        # Alert once when the threshold is crossed, not on every poll.
        if count >= self.threshold and not self.brute_force_active:
            self.brute_force_active = True
            self.alerts.raise_alert(
                "LOGIN_BRUTE_FORCE",
                "HIGH",
                f"{count} failed authentication attempts in {self.window} seconds",
                {"count": count, "window_seconds": self.window}
            )
        elif count < self.threshold:
            self.brute_force_active = False

    def run(self):
        while not self.stop_event.is_set():
            self.process_lines(self._read_new_lines())
            self.stop_event.wait(self.poll_interval)
