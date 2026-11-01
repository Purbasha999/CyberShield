"""Ask the user before a risky change stands: allow it, or block it and rewind.

A monitor that detects a risky change (a watched file deleted, a suspicious process started)
holds it - keeps the old file baseline, freezes the process - and files an ApprovalRequest with
two callbacks. Whoever answers first (native popup, dashboard, or the timeout) decides.
"""

import itertools
import threading
import time
from collections import OrderedDict

from security.events import HIGH, INFO, LOW, SecurityEvent

PENDING, ALLOWED, REWOUND, FAILED, CANCELLED = "pending", "allowed", "rewound", "failed", "cancelled"


class ApprovalRequest:
    def __init__(self, req_id, module, title, summary, details, on_allow, on_deny, timeout, key):
        self.id = req_id
        self.module = module
        self.title = title
        self.summary = summary
        self.details = details
        self.on_allow = on_allow
        self.on_deny = on_deny
        self.key = key
        self.created = time.time()
        self.deadline = self.created + timeout
        self.status = PENDING
        self.decided_by = None
        self.decided_at = None
        self.result = None

    def to_dict(self, now=None):
        now = now if now is not None else time.time()
        return {
            "id": self.id,
            "module": self.module,
            "title": self.title,
            "summary": self.summary,
            "details": self.details,
            "created": self.created,
            "deadline": self.deadline,
            "seconds_left": max(0, round(self.deadline - now, 1)) if self.status == PENDING else 0,
            "status": self.status,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "result": self.result,
        }


class ApprovalManager:
    def __init__(self, cfg, emit=None, prompter=None):
        self.enabled = cfg.get("enabled", True)
        self.file_changes = cfg.get("file_changes", True)
        self.suspicious_processes = cfg.get("suspicious_processes", True)
        self.timeout = cfg.get("timeout_seconds", 120)
        self.on_timeout = cfg.get("on_timeout", "rewind")
        self.emit = emit or (lambda events: None)
        self.prompter = prompter
        self._requests = OrderedDict()
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    # ---- lifecycle ----------------------------------------------------

    def start(self):
        self._thread = threading.Thread(target=self._expiry_loop, name="approvals", daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the timer and settle anything still waiting with the timeout policy."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        for req in self.pending_requests():
            self.decide(req.id, self.on_timeout == "allow", source="shutdown")

    def _expiry_loop(self):
        while not self._stop.wait(0.5):
            self.expire_due()

    # ---- requests -----------------------------------------------------

    def request(self, module, title, summary, details, on_allow, on_deny, key=None):
        with self._lock:
            if key:
                for req in self._requests.values():
                    if req.key == key and req.status == PENDING:
                        return req
            req = ApprovalRequest(next(self._ids), module, title, summary, details, on_allow, on_deny, self.timeout, key)
            self._requests[req.id] = req
            self._trim()
        if self.prompter is not None:
            self.prompter.ask(req, self.on_timeout, lambda allow: self.decide(req.id, allow, source="popup"))
        return req

    def _trim(self, keep=50):
        decided = [r.id for r in self._requests.values() if r.status != PENDING]
        for req_id in decided[: max(0, len(decided) - keep)]:
            del self._requests[req_id]

    def get(self, req_id):
        with self._lock:
            return self._requests.get(req_id)

    def pending_requests(self):
        with self._lock:
            return [r for r in self._requests.values() if r.status == PENDING]

    def pending(self):
        return [r.to_dict() for r in self.pending_requests()]

    def recent(self, limit=10):
        with self._lock:
            done = [r for r in self._requests.values() if r.status != PENDING]
        return [r.to_dict() for r in reversed(done[-limit:])]

    # ---- decisions ----------------------------------------------------

    def decide(self, req_id, allow, source="dashboard"):
        with self._lock:
            req = self._requests.get(req_id)
            if req is None:
                return None
            if req.status != PENDING:
                return req.to_dict()
            req.status = "deciding"  # claims the request so a second answer is ignored

        try:
            message = (req.on_allow if allow else req.on_deny)()
            status = ALLOWED if allow else REWOUND
        except PermissionError as exc:
            status, message = FAILED, f"{exc}. Run CyberShield with sudo to act on system files and other users' processes."
        except Exception as exc:
            status, message = FAILED, f"{type(exc).__name__}: {exc}"

        with self._lock:
            req.status, req.result, req.decided_by, req.decided_at = status, message, source, time.time()
        if self.prompter is not None:
            self.prompter.cancel(req)

        if status == FAILED:
            title, severity = ("Allow action failed" if allow else "Rewind failed"), HIGH
        elif status == ALLOWED:
            title, severity = "Change allowed by user", INFO
        else:
            title, severity = "Change blocked and rewound", LOW
        if source in ("timeout", "shutdown") and status != FAILED:
            title = f"{'Change allowed' if allow else 'Change blocked and rewound'} (no answer, {source})"
        self.emit([
            SecurityEvent(
                req.module, severity, title,
                {"request": req.title, "summary": req.summary, "result": message, "decided_by": source, **req.details},
            )
        ])
        return req.to_dict()

    def cancel(self, req_id, reason):
        with self._lock:
            req = self._requests.get(req_id)
            if req is None or req.status != PENDING:
                return
            req.status, req.result, req.decided_by, req.decided_at = CANCELLED, reason, "system", time.time()
        if self.prompter is not None:
            self.prompter.cancel(req)

    def cancel_module(self, module, reason):
        for req in self.pending_requests():
            if req.module == module:
                self.cancel(req.id, reason)

    def expire_due(self, now=None):
        now = now if now is not None else time.time()
        for req in self.pending_requests():
            if now >= req.deadline:
                self.decide(req.id, self.on_timeout == "allow", source="timeout")
