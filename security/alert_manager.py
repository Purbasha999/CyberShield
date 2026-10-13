import threading


class AlertManager:
    SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def __init__(self, event_logger):
        self.event_logger = event_logger
        self.lock = threading.Lock()
        self.alerts = []

    def raise_alert(self, source, severity, message, details=None):
        severity = severity.upper()
        if severity not in self.SEVERITIES:
            severity = "LOW"

        alert = {
            "source": source,
            "severity": severity,
            "message": message,
            "details": details or {}
        }

        with self.lock:
            self.alerts.insert(0, alert)
            self.alerts = self.alerts[:200]

        self.event_logger.log(source, severity, message, details)
        print(f"[{severity}] {source}: {message}")
        return alert

    def recent_alerts(self, limit=50):
        with self.lock:
            return self.alerts[:limit]
