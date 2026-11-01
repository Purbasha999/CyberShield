"""Central alert engine: de-duplicates events, logs them and tracks module/system status."""

import threading
import time
from collections import Counter, deque

from security.events import HIGH, LOW, MEDIUM, SEVERITY_RANK

OVERALL_STATUS = {None: "SECURE", LOW: "NOTICE", MEDIUM: "WARNING", HIGH: "CRITICAL"}


class AlertManager:
    def __init__(self, event_logger=None, cooldown_seconds=60, max_recent=500):
        self.event_logger = event_logger
        self.cooldown_seconds = cooldown_seconds
        self._recent = deque(maxlen=max_recent)
        self._last_seen = {}
        self._lock = threading.Lock()
        self.counts = Counter()
        self.suppressed = 0

    def process(self, events, now=None):
        """Accept a batch of events. Returns the ones that were not suppressed by the cooldown."""
        accepted = []
        for event in events:
            current = now if now is not None else time.time()
            with self._lock:
                if event.key:
                    last = self._last_seen.get(event.key)
                    if last is not None and current - last < self.cooldown_seconds:
                        self.suppressed += 1
                        continue
                    self._last_seen[event.key] = current
                self.counts[event.severity] += 1
                if event.is_alert:
                    self._recent.append(event)
            if self.event_logger is not None:
                self.event_logger.log(event)
            accepted.append(event)
        return accepted

    def recent_alerts(self, limit=50, min_severity=LOW):
        with self._lock:
            items = [e for e in self._recent if SEVERITY_RANK[e.severity] >= SEVERITY_RANK[min_severity]]
        return list(reversed(items))[:limit]

    def highest_severity(self, window_seconds, module=None, now=None):
        now = now if now is not None else time.time()
        best = None
        with self._lock:
            for event in self._recent:
                if now - event.timestamp > window_seconds:
                    continue
                if module and event.module != module:
                    continue
                if best is None or SEVERITY_RANK[event.severity] > SEVERITY_RANK[best]:
                    best = event.severity
        return best

    def module_status(self, module, window_seconds, now=None):
        return "WARNING" if self.highest_severity(window_seconds, module, now) else "SAFE"

    def overall_status(self, window_seconds, now=None):
        return OVERALL_STATUS[self.highest_severity(window_seconds, now=now)]
