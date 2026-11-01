"""The event type shared by every monitor, the alert manager and the logger."""

import time
from dataclasses import dataclass, field

INFO, LOW, MEDIUM, HIGH = "INFO", "LOW", "MEDIUM", "HIGH"
SEVERITY_RANK = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3}


@dataclass
class SecurityEvent:
    module: str
    severity: str
    title: str
    details: dict = field(default_factory=dict)
    # Events sharing a key are de-duplicated by the alert manager's cooldown.
    key: str = None
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self):
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"Unknown severity {self.severity!r}")

    @property
    def is_alert(self):
        return self.severity != INFO

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "module": self.module,
            "severity": self.severity,
            "title": self.title,
            "details": self.details,
        }
