import hashlib
import json
import os
import threading
import time


class FileIntegrityMonitor(threading.Thread):
    def __init__(self, config, alerts, stop_event, base_dir):
        super().__init__(daemon=True, name="FileIntegrityMonitor")
        self.alerts = alerts
        self.stop_event = stop_event
        self.interval = config["file_integrity"]["scan_interval_seconds"]

        configured_path = config["file_integrity"]["monitor_path"]
        if os.path.isabs(configured_path):
            self.monitor_path = configured_path
        else:
            self.monitor_path = os.path.join(base_dir, configured_path)

        self.baseline_path = os.path.join(base_dir, "config", "baseline.json")
        self.baseline = self._load_baseline()

    @staticmethod
    def sha256(path):
        digest = hashlib.sha256()
        with open(path, "rb") as file:
            for block in iter(lambda: file.read(65536), b""):
                digest.update(block)
        return digest.hexdigest()

    def _files(self):
        if not os.path.exists(self.monitor_path):
            return []

        if os.path.isfile(self.monitor_path):
            return [self.monitor_path]

        result = []
        for root, _, filenames in os.walk(self.monitor_path):
            for filename in filenames:
                path = os.path.join(root, filename)
                if os.path.isfile(path):
                    result.append(path)
        return result

    def _load_baseline(self):
        os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)

        if os.path.exists(self.baseline_path):
            try:
                with open(self.baseline_path, "r", encoding="utf-8") as file:
                    return json.load(file)
            except (json.JSONDecodeError, OSError):
                pass

        baseline = {}
        for path in self._files():
            try:
                baseline[path] = self.sha256(path)
            except OSError:
                pass

        with open(self.baseline_path, "w", encoding="utf-8") as file:
            json.dump(baseline, file, indent=2)

        return baseline

    def scan_once(self):
        current = {}
        for path in self._files():
            try:
                current[path] = self.sha256(path)
            except OSError:
                continue

        for path, original_hash in self.baseline.items():
            if path not in current:
                self.alerts.raise_alert(
                    "FILE_INTEGRITY", "HIGH",
                    f"Monitored file deleted: {path}",
                    {"path": path, "event": "deleted"}
                )
            elif current[path] != original_hash:
                self.alerts.raise_alert(
                    "FILE_INTEGRITY", "MEDIUM",
                    f"File modification detected: {path}",
                    {"path": path, "event": "modified"}
                )

        for path in current:
            if path not in self.baseline:
                self.alerts.raise_alert(
                    "FILE_INTEGRITY", "MEDIUM",
                    f"New file detected: {path}",
                    {"path": path, "event": "created"}
                )

        return current

    def run(self):
        while not self.stop_event.is_set():
            self.scan_once()
            self.stop_event.wait(self.interval)
