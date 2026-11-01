"""Login monitoring: follows /var/log/auth.log and detects repeated authentication failures."""

import os
import re
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime

from security.events import HIGH, INFO, LOW, MEDIUM, SecurityEvent

# "2026-10-27T14:16:45.871735+00:00 host proc[pid]: message"  (rsyslog high-precision format)
RFC3339_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+(.*)$"
)
# "Oct 27 14:16:45 host proc[pid]: message"  (traditional syslog format)
BSD_LINE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$")
PROGRAM = re.compile(r"^(\([^)]*\)|[^\s:\[]+)(?:\[(\d+)\])?:\s*(.*)$")

SSH_FAILED = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+)")
SSH_ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
PAM_FAILURE = re.compile(r"pam_unix\(([^:)]+):auth\): authentication failure;(.*)")
PAM_SESSION = re.compile(r"pam_unix\(([^:)]+):session\): session opened for user ([^\s(]+)(?:\(uid=\d+\))?(?: by ([^\s(]*))?")
SUDO_COMMAND = re.compile(r"^\s*(\S+) : .*COMMAND=(.*)$")
USER_CREATED = re.compile(r"new user: name=([^,\s]+)")
GROUP_ADD = re.compile(r"add '([^']+)' to (?:shadow )?group '(sudo|admin|wheel|root)'")
GPASSWD_ADD = re.compile(r"user (\S+) added by \S+ to group (sudo|admin|wheel|root)")
PASSWORD_CHANGED = re.compile(r"password changed for (\S+)")

# Interactive logins worth reporting; cron/systemd-user sessions are noise.
LOGIN_SESSION_SERVICES = {"su", "su-l", "sudo", "login", "gdm-password", "lightdm"}


@dataclass
class AuthRecord:
    timestamp: float
    kind: str           # failure | success | sudo_command | user_created | privilege_grant | password_changed
    service: str
    user: str = ""
    source: str = "local"
    detail: str = ""
    raw: str = field(default="", repr=False)


def parse_timestamp(text, now=None):
    if "T" in text[:11]:
        text = text.replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", text):
            text = text[:-2] + ":" + text[-2:]
        dt = datetime.fromisoformat(text)
        return dt.timestamp()
    now_dt = datetime.fromtimestamp(now if now is not None else time.time())
    dt = datetime.strptime(f"{now_dt.year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")
    if dt > now_dt.replace(microsecond=0) and dt.month > now_dt.month:
        dt = dt.replace(year=now_dt.year - 1)  # a December line read in January
    return dt.timestamp()


def _kv(text):
    return dict(re.findall(r"(\w+)=(\S*)", text))


def parse_line(line, now=None):
    """Turn one auth.log line into an AuthRecord, or None if it is not interesting."""
    line = line.rstrip("\n")
    match = RFC3339_LINE.match(line) or BSD_LINE.match(line)
    if not match:
        return None
    try:
        ts = parse_timestamp(match.group(1), now)
    except ValueError:
        return None
    prog_match = PROGRAM.match(match.group(3))
    if not prog_match:
        return None
    program = prog_match.group(1).strip("()")
    msg = prog_match.group(3)

    if "incorrect password attempt" in msg:
        return None  # sudo's summary line; each attempt is already counted from pam_unix

    m = SSH_FAILED.search(msg)
    if m:
        return AuthRecord(ts, "failure", "sshd", m.group(1), m.group(2), "failed password", line)
    m = SSH_ACCEPTED.search(msg)
    if m:
        return AuthRecord(ts, "success", "sshd", m.group(2), m.group(3), f"accepted {m.group(1)}", line)
    m = PAM_FAILURE.search(msg)
    if m:
        service = m.group(1)
        if service == "sshd":
            return None  # sshd also writes a "Failed password" line, avoid double counting
        kv = _kv(m.group(2))
        source = kv.get("rhost") or kv.get("ruser") or kv.get("logname") or "local"
        return AuthRecord(ts, "failure", service, kv.get("user", ""), source, "authentication failure", line)
    m = PAM_SESSION.search(msg)
    if m:
        service = m.group(1)
        if service not in LOGIN_SESSION_SERVICES:
            return None
        by = m.group(3) or "local"
        return AuthRecord(ts, "success", service, m.group(2), by, "session opened", line)
    if program == "sudo":
        m = SUDO_COMMAND.search(msg)
        if m:
            return AuthRecord(ts, "sudo_command", "sudo", m.group(1), "local", m.group(2).strip(), line)
    m = USER_CREATED.search(msg)
    if m:
        return AuthRecord(ts, "user_created", program, m.group(1), "local", "new user account", line)
    m = GROUP_ADD.search(msg) or GPASSWD_ADD.search(msg)
    if m:
        return AuthRecord(ts, "privilege_grant", program, m.group(1), "local", f"added to group {m.group(2)}", line)
    m = PASSWORD_CHANGED.search(msg)
    if m:
        return AuthRecord(ts, "password_changed", program, m.group(1), "local", "password changed", line)
    return None


class LoginMonitor:
    name = "login"

    def __init__(self, cfg):
        self.cfg = cfg
        self.path = cfg["log_path"]
        self._offset = None
        self._inode = None
        self._partial = ""
        self._failures = deque()           # (timestamp, source, user)
        self._alerted_until = {}           # source -> time before which no new brute-force alert is raised
        self.recent = deque(maxlen=30)
        self.totals = Counter()
        self.status = "OK"
        self.message = ""

    def _read_new_lines(self):
        st = os.stat(self.path)
        if self._offset is None:
            self._offset = 0 if self.cfg["read_history_on_start"] else st.st_size
        elif st.st_ino != self._inode or st.st_size < self._offset:
            self._offset, self._partial = 0, ""  # log was rotated or truncated
        self._inode = st.st_ino
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self._offset)
            data = fh.read()
            self._offset = fh.tell()
        data = self._partial + data
        lines = data.split("\n")
        self._partial = lines.pop()  # incomplete last line, finished on the next poll
        return lines

    def _handle(self, rec, now, events):
        window = self.cfg["window_seconds"]
        fresh = now - rec.timestamp <= window
        self.totals[rec.kind] += 1
        self.recent.appendleft({k: v for k, v in asdict(rec).items() if k != "raw"})
        details = {"service": rec.service, "user": rec.user, "source": rec.source, "detail": rec.detail}

        if rec.kind == "failure":
            # Log lines arrive in time order, so anything older than the window can be dropped now.
            while self._failures and rec.timestamp - self._failures[0][0] > window:
                self._failures.popleft()
            self._failures.append((rec.timestamp, rec.source, rec.user))
            if fresh:
                events.append(SecurityEvent(self.name, INFO, "Failed login attempt", details, timestamp=rec.timestamp))
            count = sum(1 for ts, src, _ in self._failures if src == rec.source and rec.timestamp - ts <= window)
            if fresh and count > self.cfg["max_failed_attempts"] and now >= self._alerted_until.get(rec.source, 0):
                self._alerted_until[rec.source] = now + window
                users = sorted({u for ts, src, u in self._failures if src == rec.source and u})
                events.append(
                    SecurityEvent(
                        self.name, HIGH, "Multiple failed login attempts",
                        {"source": rec.source, "users": users, "attempts": count,
                         "window_seconds": window, "service": rec.service},
                        key=f"login:bruteforce:{rec.source}",
                    )
                )
        elif not fresh:
            return
        elif rec.kind == "success":
            events.append(SecurityEvent(self.name, INFO, "Successful login", details, timestamp=rec.timestamp))
        elif rec.kind == "sudo_command":
            events.append(SecurityEvent(self.name, INFO, "Privileged command executed", details, timestamp=rec.timestamp))
        elif rec.kind == "user_created":
            events.append(SecurityEvent(self.name, MEDIUM, "New user account created", details, timestamp=rec.timestamp))
        elif rec.kind == "privilege_grant":
            events.append(SecurityEvent(self.name, HIGH, "User granted administrator privileges", details, timestamp=rec.timestamp))
        elif rec.kind == "password_changed":
            events.append(SecurityEvent(self.name, LOW, "Account password changed", details, timestamp=rec.timestamp))

    def poll(self, now=None):
        now = now if now is not None else time.time()
        events = []
        try:
            lines = self._read_new_lines()
            self.status, self.message = "OK", ""
        except FileNotFoundError:
            lines = []
            self.status, self.message = "MISSING", f"{self.path} not found (is rsyslog installed and running?)"
        except PermissionError:
            lines = []
            self.status = "NO ACCESS"
            self.message = f"Cannot read {self.path}. Run: sudo usermod -aG adm $USER (then restart WSL)"

        for line in lines:
            rec = parse_line(line, now)
            if rec:
                self._handle(rec, now, events)

        window = self.cfg["window_seconds"]
        while self._failures and now - self._failures[0][0] > window:
            self._failures.popleft()
        in_window = Counter(src for _, src, _ in self._failures)

        snapshot = {
            "status": self.status,
            "message": self.message,
            "log_path": self.path,
            "failed_total": self.totals["failure"],
            "success_total": self.totals["success"],
            "sudo_total": self.totals["sudo_command"],
            "failed_in_window": len(self._failures),
            "max_failed_attempts": self.cfg["max_failed_attempts"],
            "window_seconds": window,
            "top_sources": in_window.most_common(5),
            "recent": list(self.recent)[:15],
        }
        return snapshot, events
