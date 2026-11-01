"""Process monitoring: PID, name, owner, CPU/memory usage and suspicious-process rules."""

import os
from collections import Counter

import psutil

from security.events import LOW, MEDIUM, SecurityEvent

HEAVY_RULES = ("cpu", "memory")

ATTRS = ["pid", "name", "username", "status", "cpu_percent", "memory_percent", "exe", "cmdline", "create_time"]


def assess_process(info, cfg):
    """Static rules that need only one sample: suspicious name or executable location.

    Returns a list of (rule, severity, title, reason).
    """
    findings = []
    name = (info.get("name") or "").lower()
    cmdline = info.get("cmdline") or []
    argv0 = os.path.basename(cmdline[0]).lower() if cmdline else ""
    suspicious = {n.lower() for n in cfg.get("suspicious_names", [])}
    if name in suspicious or argv0 in suspicious:
        findings.append(
            ("name", MEDIUM, "Suspicious process detected", f"name '{info.get('name')}' is on the watch list")
        )
    exe = info.get("exe") or ""
    for prefix in cfg.get("suspicious_paths", []):
        if exe.startswith(prefix):
            findings.append(
                ("path", MEDIUM, "Process running from temporary directory", f"executable is {exe}")
            )
            break
    return findings


class ProcessMonitor:
    name = "process"

    def __init__(self, cfg, approvals=None, notifier=None):
        self.cfg = cfg
        self.approvals = approvals if approvals and approvals.enabled and approvals.suspicious_processes else None
        self.notifier = notifier  # shows the "process blocked" popup
        self._cpu_streak = {}   # (pid, create_time) -> consecutive polls above the CPU threshold
        self._active = set()    # (pid, create_time, rule) currently alerting; cleared when the rule stops matching
        self._allowed = set()   # (pid, create_time) the user chose to let run
        # Never block ourselves or the shell/terminal chain that started us.
        self._protected = {0, 1, os.getpid()} | {p.pid for p in psutil.Process().parents()}
        # Under sudo, block the invoking user's processes, not every root process.
        self._owner_uid = int(os.environ.get("SUDO_UID", os.getuid())) if hasattr(os, "getuid") else None

    # ---- approvals ----------------------------------------------------

    @staticmethod
    def _same_process(ident):
        """psutil.Process for ident, or None if it exited (or the PID was reused)."""
        try:
            proc = psutil.Process(ident[0])
            return proc if proc.create_time() == ident[1] else None
        except psutil.NoSuchProcess:
            return None

    def _resume(self, ident, name):
        self._allowed.add(ident)
        proc = self._same_process(ident)
        if proc is None:
            return f"{name} (PID {ident[0]}) already exited"
        try:
            proc.resume()
        except psutil.AccessDenied as exc:
            raise PermissionError(f"Not allowed to resume PID {ident[0]}") from exc
        return f"Resumed {name} (PID {ident[0]})"

    def _terminate(self, ident, name):
        proc = self._same_process(ident)
        if proc is None:
            return f"{name} (PID {ident[0]}) already exited"
        try:
            proc.kill()
        except psutil.AccessDenied as exc:
            raise PermissionError(f"Not allowed to kill PID {ident[0]}") from exc
        return f"Killed {name} (PID {ident[0]})"

    def _block(self, info, ident):
        """Stop a CPU/memory-heavy process. Returns (blocked, message)."""
        pid, name = info["pid"], info.get("name") or "?"
        exempt = {n.lower() for n in self.cfg.get("block_exempt_names", [])}
        if pid in self._protected or ident in self._allowed:
            return False, "not blocked: CyberShield or the terminal that started it"
        if name.lower() in exempt:
            return False, f"not blocked: '{name}' is in block_exempt_names"
        proc = self._same_process(ident)
        if proc is None:
            return False, "already exited"
        try:
            if self._owner_uid is not None and proc.uids().real != self._owner_uid:
                return False, "not blocked: belongs to another user"
            proc.terminate()  # SIGTERM first, so the program can clean up
            _, alive = psutil.wait_procs([proc], timeout=1.5)
            for left in alive:
                left.kill()
        except psutil.NoSuchProcess:
            return True, f"Stopped {name} (PID {pid})"
        except psutil.AccessDenied:
            return False, "not blocked: permission denied"
        return True, f"Stopped {name} (PID {pid})"

    def _notify_blocked(self, blocked):
        if self.notifier is None or not blocked:
            return
        lines = [f"- {d['name']} (PID {d['pid']}): {d['reason']}" for d in blocked[:5]]
        if len(blocked) > 5:
            lines.append(f"- and {len(blocked) - 5} more")
        names = sorted({d["name"] for d in blocked})
        self.notifier.notify(
            "process blocked",
            "Potentially harmful process blocked\n\n" + "\n".join(lines) + "\n\n"
            f"{'This process' if len(blocked) == 1 else 'These processes'} might be harmful "
            "(using too much CPU or memory), so CyberShield has blocked "
            f"{'it' if len(blocked) == 1 else 'them'}.\n\n"
            f"If this was expected, add {', '.join(repr(n) for n in names)} to "
            "process_monitor.block_exempt_names in config/config.json.",
        )

    def _pause_and_ask(self, info, ident, reason):
        pid, name = info["pid"], info.get("name") or "?"
        if ident in self._allowed or pid in (0, 1, os.getpid(), os.getppid()):
            return None
        proc = self._same_process(ident)
        if proc is None:
            return None
        try:
            proc.suspend()  # SIGSTOP: the process is frozen until the user decides
            paused = True
        except psutil.AccessDenied:
            paused = False
        except psutil.NoSuchProcess:
            return None
        summary = f"{name} (PID {pid}, user {info.get('username') or '?'}): {reason}"
        if not paused:
            summary += ". Could not pause it; run CyberShield with sudo for other users' processes."
        self.approvals.request(
            module=self.name,
            title="Suspicious process paused" if paused else "Suspicious process detected",
            summary=summary,
            details={"pid": pid, "name": name, "exe": info.get("exe"), "paused": paused},
            on_allow=lambda: self._resume(ident, name),
            on_deny=lambda: self._terminate(ident, name),
            key=f"process:{pid}:{ident[1]}",
        )
        return paused

    def poll(self):
        events, rows, blocked = [], [], []
        statuses = Counter()
        block_heavy = self.cfg.get("block_heavy_processes", False)
        alive = set()
        cpu_limit = self.cfg["cpu_threshold"]
        mem_limit = self.cfg["memory_threshold"]
        sustain = max(1, int(self.cfg["sustain_polls"]))

        # process_iter caches Process objects, so cpu_percent is measured since the previous poll.
        for proc in psutil.process_iter(ATTRS, ad_value=None):
            info = proc.info
            ident = (info["pid"], info.get("create_time"))
            alive.add(ident)
            cpu = info.get("cpu_percent") or 0.0
            mem = info.get("memory_percent") or 0.0
            statuses[info.get("status") or "unknown"] += 1

            findings = assess_process(info, self.cfg)

            streak = self._cpu_streak.get(ident, 0) + 1 if cpu >= cpu_limit else 0
            self._cpu_streak[ident] = streak
            if streak >= sustain:
                findings.append(("cpu", LOW, "High CPU process detected", f"CPU {cpu:.1f}% of a core for {streak} checks in a row"))
            if mem >= mem_limit:
                findings.append(("memory", LOW, "High memory process detected", f"memory {mem:.1f}% of RAM"))

            matched = set()
            was_blocked = False
            for rule, severity, title, reason in findings:
                matched.add(rule)
                if (*ident, rule) in self._active:
                    continue
                self._active.add((*ident, rule))
                details = {
                    "pid": info["pid"],
                    "name": info.get("name"),
                    "user": info.get("username"),
                    "cpu_percent": round(cpu, 1),
                    "memory_percent": round(mem, 2),
                    "exe": info.get("exe"),
                    "reason": reason,
                }
                # Only the "suspicious" rules ask the user first.
                if self.approvals and rule in ("name", "path"):
                    paused = self._pause_and_ask(info, ident, reason)
                    if paused is not None:
                        details["awaiting_confirmation"] = True
                        details["paused"] = paused
                # Heavy CPU/memory use is stopped at once (when enabled) and the user is told afterwards.
                outcome = None
                if block_heavy and rule in HEAVY_RULES and not was_blocked:
                    ok, outcome = self._block(info, ident)
                    details["blocked"] = ok
                    details["result"] = outcome
                    was_blocked = ok
                events.append(
                    SecurityEvent(
                        module=self.name,
                        severity=severity,
                        title=title,
                        details=details,
                        key=f"process:{rule}:{info['pid']}",
                    )
                )
                if outcome and details["blocked"]:
                    blocked.append(details)
                    events.append(SecurityEvent(
                        module=self.name,
                        severity=MEDIUM,
                        title="Potentially harmful process blocked",
                        details={**details, "reason": f"{reason} - {outcome}"},
                    ))
            for rule in ("name", "path", "cpu", "memory"):
                if rule not in matched:
                    self._active.discard((*ident, rule))

            rows.append(
                {
                    "pid": info["pid"],
                    "name": info.get("name") or "?",
                    "user": info.get("username") or "?",
                    "status": info.get("status") or "?",
                    "cpu_percent": round(cpu, 1),
                    "memory_percent": round(mem, 2),
                    "flags": [f[3] for f in findings],
                    "state": "BLOCKED" if was_blocked else "WARNING" if findings else "OK",
                }
            )

        self._notify_blocked(blocked)

        # Forget processes that have exited.
        self._cpu_streak = {k: v for k, v in self._cpu_streak.items() if k in alive}
        self._active = {a for a in self._active if (a[0], a[1]) in alive}
        self._allowed &= alive

        rows.sort(key=lambda r: (r["cpu_percent"], r["memory_percent"]), reverse=True)
        snapshot = {
            "total": len(rows),
            "top": rows[: self.cfg["top_n"]],
            "flagged": [r for r in rows if r["flags"]],
            "statuses": dict(statuses),
            "zombies": statuses.get(psutil.STATUS_ZOMBIE, 0),
            "cpu_threshold": cpu_limit,
            "memory_threshold": mem_limit,
            "block_heavy": block_heavy,
        }
        return snapshot, events
