"""Writes every security event to a rotating log file and to SQLite."""

import json
import logging
import os
from logging.handlers import RotatingFileHandler

from security.events import HIGH, INFO, LOW, MEDIUM

_LOG_LEVEL = {INFO: logging.INFO, LOW: logging.WARNING, MEDIUM: logging.WARNING, HIGH: logging.CRITICAL}


class EventLogger:
    def __init__(self, log_dir, db=None, max_bytes=1_000_000, backups=5):
        os.makedirs(log_dir, exist_ok=True)
        self.log_path = os.path.join(log_dir, "security_events.log")
        self.db = db
        # A per-instance logger name keeps handlers from leaking between instances (e.g. in tests).
        self._logger = logging.getLogger(f"cybershield.events.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._handler = RotatingFileHandler(
            self.log_path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
        )
        self._handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        self._logger.addHandler(self._handler)

    def log(self, event):
        details = json.dumps(event.details, default=str, sort_keys=True)
        self._logger.log(
            _LOG_LEVEL[event.severity],
            f"[{event.severity}] {event.module}: {event.title} | {details}",
        )
        if self.db is not None:
            self.db.insert_event(event)

    def close(self):
        self._logger.removeHandler(self._handler)
        self._handler.close()
