"""CyberShield Security Engine: runs every monitor, feeds the alert manager and exposes state."""

import logging
import os
import threading
import time
from collections import deque

from database.db import EventDatabase
from modules.file_monitor import FileMonitor
from modules.login_monitor import LoginMonitor
from modules.process_monitor import ProcessMonitor
from modules.resource_monitor import ResourceMonitor
from security.alert_manager import AlertManager
from security.approvals import ApprovalManager
from security.event_logger import EventLogger
from security.events import INFO, LOW, SecurityEvent
from security.popup import NativePrompter

log = logging.getLogger("cybershield.engine")

MODULE_CONFIG = {
    "process": "process_monitor",
    "file": "file_monitor",
    "login": "login_monitor",
    "resource": "resource_monitor",
}


class SecurityEngine:
    def __init__(self, config):
        self.config = config
        os.makedirs(config["data_dir"], exist_ok=True)
        self.db = EventDatabase(os.path.join(config["data_dir"], "cyber_events.db"))
        self.event_logger = EventLogger(os.path.join(config["data_dir"], "logs"), self.db)
        self.alerts = AlertManager(self.event_logger, config["alerts"]["cooldown_seconds"])
        self.status_window = config["alerts"]["status_window_seconds"]
        self.started_at = time.time()

        approvals_cfg = config["approvals"]
        self.prompter = NativePrompter(approvals_cfg["popup"])
        self.approvals = ApprovalManager(approvals_cfg, emit=self.alerts.process,
                                         prompter=self.prompter if approvals_cfg["enabled"] else None)

        self.monitors = {}
        if config["process_monitor"]["enabled"]:
            self.monitors["process"] = ProcessMonitor(config["process_monitor"], self.approvals, self.prompter)
        if config["file_monitor"]["enabled"]:
            self.monitors["file"] = FileMonitor(config["file_monitor"], self.db, config["data_dir"], self.approvals)
        if config["login_monitor"]["enabled"]:
            self.monitors["login"] = LoginMonitor(config["login_monitor"])
        if config["resource_monitor"]["enabled"]:
            self.monitors["resource"] = ResourceMonitor(config["resource_monitor"])

        self.history = deque(maxlen=config["resource_monitor"]["history_size"])
        self._state = {name: {"snapshot": None, "last_poll": None, "error": None} for name in self.monitors}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads = []

    # ---- polling ------------------------------------------------------

    def poll_monitor(self, name):
        monitor = self.monitors[name]
        try:
            snapshot, events = monitor.poll()
            error = None
        except Exception as exc:  # a broken module must not take the whole engine down
            log.exception("%s monitor failed", name)
            snapshot, events, error = None, [], f"{type(exc).__name__}: {exc}"
            events.append(
                SecurityEvent(name, LOW, "Monitor error", {"error": error}, key=f"engine:error:{name}")
            )
        with self._lock:
            entry = self._state[name]
            entry["last_poll"] = time.time()
            entry["error"] = error
            if snapshot is not None:
                entry["snapshot"] = snapshot
            if name == "resource" and snapshot is not None:
                self.history.append(
                    {
                        "t": entry["last_poll"],
                        "cpu": snapshot["cpu_percent"],
                        "memory": snapshot["memory"]["percent"],
                        "disk": snapshot["disk_percent"],
                    }
                )
        return self.alerts.process(events)

    def run_once(self):
        accepted = []
        for name in self.monitors:
            accepted.extend(self.poll_monitor(name))
        return accepted

    def _loop(self, name, interval):
        wait_for_change = getattr(self.monitors[name], "wait_for_change", None)
        while not self._stop.is_set():
            self.poll_monitor(name)
            if wait_for_change is None:
                self._stop.wait(interval)
                continue
            # Rescan as soon as inotify reports a change, otherwise after `interval`.
            deadline = time.time() + interval
            while not self._stop.is_set() and time.time() < deadline:
                if wait_for_change(min(0.5, max(0.01, deadline - time.time()))):
                    self._stop.wait(0.2)  # let editors finish writing (save = write temp + rename)
                    break

    def start(self):
        self.approvals.start()
        self.alerts.process([SecurityEvent("engine", INFO, "CyberShield started", {"modules": list(self.monitors)})])
        for name in self.monitors:
            interval = self.config[MODULE_CONFIG[name]]["interval_seconds"]
            thread = threading.Thread(target=self._loop, args=(name, interval), name=f"monitor-{name}", daemon=True)
            thread.start()
            self._threads.append(thread)

    def stop(self):
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=5)
        self._threads.clear()
        self.approvals.stop()  # unanswered requests are settled with the on_timeout policy
        self.alerts.process([SecurityEvent("engine", INFO, "CyberShield stopped", {})])
        self.event_logger.close()
        self.db.close()

    # ---- actions ------------------------------------------------------

    def rebaseline_files(self):
        monitor = self.monitors.get("file")
        if monitor is None:
            return False
        monitor.rebaseline()
        self.alerts.process([SecurityEvent("file", INFO, "File baseline reset by user", {})])
        self.poll_monitor("file")
        return True

    # ---- state for dashboards -----------------------------------------

    def module_status(self, name):
        entry = self._state[name]
        if entry["error"]:
            return "ERROR"
        if entry["snapshot"] is None:
            return "STARTING"
        if name == "login" and entry["snapshot"]["status"] != "OK":
            return entry["snapshot"]["status"]
        return self.alerts.module_status(name, self.status_window)

    def get_state(self, alert_limit=50):
        now = time.time()
        with self._lock:
            modules = {
                name: {
                    "status": self.module_status(name),
                    "last_poll": entry["last_poll"],
                    "error": entry["error"],
                    "snapshot": entry["snapshot"],
                }
                for name, entry in self._state.items()
            }
            history = list(self.history)
        return {
            "generated_at": now,
            "started_at": self.started_at,
            "overall": self.alerts.overall_status(self.status_window),
            "status_window_seconds": self.status_window,
            "refresh_seconds": self.config["dashboard"]["refresh_seconds"],
            "modules": modules,
            "history": history,
            "alerts": self.db.recent_events(limit=alert_limit, min_severity=LOW),
            "events": self.db.recent_events(limit=alert_limit, min_severity=INFO),
            "severity_counts_24h": self.db.severity_counts(since=now - 86400),
            "timeline_24h": self.db.hourly_counts(24, now),
            "suppressed_duplicates": self.alerts.suppressed,
            "approvals": {
                "enabled": self.approvals.enabled,
                "popup": self.prompter.kind,
                "timeout_seconds": self.approvals.timeout,
                "on_timeout": self.approvals.on_timeout,
                "pending": self.approvals.pending(),
                "recent": self.approvals.recent(),
            },
        }
