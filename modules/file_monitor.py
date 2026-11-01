"""File integrity monitoring: SHA-256 baselines for watched files and folders.

With approvals enabled, a detected change is held instead of accepted: the old baseline stays,
the user is asked, and the change is then either accepted or rewound from the vault (a
content-addressed store of trusted file copies kept in the data directory).
"""

import hashlib
import os
import shutil
import stat
import sys
import threading
import time
from collections import deque
from fnmatch import fnmatch

from security.events import INFO, LOW, MEDIUM, SecurityEvent

CHUNK = 64 * 1024


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


class FileMonitor:
    name = "file"

    def __init__(self, cfg, db, data_dir=None, approvals=None):
        self.cfg = cfg
        self.db = db
        self.approvals = approvals if approvals and approvals.enabled and approvals.file_changes else None
        self.vault_dir = os.path.join(data_dir, "vault") if data_dir else None
        self.quarantine_dir = os.path.join(data_dir, "quarantine") if data_dir else None
        self._lock = threading.RLock()
        self._pending = {}  # path -> approval request id
        self._pending_new = set()  # pending paths that don't exist in the trusted state (new files, rename targets)
        self.recent_changes = deque(maxlen=25)
        self._watcher = None
        if cfg.get("realtime", True) and sys.platform == "linux":
            try:
                from modules.inotify import Inotify
                self._watcher = Inotify()
            except (OSError, AttributeError):
                self._watcher = None

    # ---- helpers ------------------------------------------------------

    def is_excluded(self, path):
        name = os.path.basename(path)
        for pattern in self.cfg["exclude"]:
            if os.path.isabs(pattern):
                prefix = pattern.rstrip("/")
                if path == prefix or path.startswith(prefix + "/"):
                    return True
            elif fnmatch(name, pattern) or fnmatch(path, pattern):
                return True
        return False

    def iter_files(self, root):
        if self.is_excluded(root):
            return
        if os.path.isfile(root):
            yield root
            return
        if not os.path.isdir(root):
            return
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if not self.is_excluded(os.path.join(dirpath, d)))
            for filename in sorted(filenames):
                path = os.path.join(dirpath, filename)
                if not self.is_excluded(path):
                    yield path
            if not self.cfg["recursive"]:
                break

    def _watch_dirs(self):
        dirs = set()
        for root in self.cfg["watch_paths"]:
            if os.path.isdir(root):
                dirs.add(root)
                if self.cfg["recursive"]:
                    for dirpath, dirnames, _ in os.walk(root, followlinks=False):
                        dirnames[:] = [d for d in dirnames if not self.is_excluded(os.path.join(dirpath, d))]
                        dirs.update(os.path.join(dirpath, d) for d in dirnames)
            elif os.path.isdir(os.path.dirname(root)):
                dirs.add(os.path.dirname(root))  # a watched file, or a watched folder that was deleted
        return dirs

    def wait_for_change(self, timeout):
        """Sleep up to `timeout`; returns True early if inotify reports a change."""
        if self._watcher is None:
            time.sleep(timeout)
            return False
        return self._watcher.wait(timeout)

    def rebaseline(self):
        """Forget the stored baseline; the next scan silently records the current state."""
        with self._lock:
            self.db.clear_baseline()
            self.recent_changes.clear()
            if self.approvals and self._pending:
                self.approvals.cancel_module(self.name, "baseline reset by user")
            self._pending.clear()
            self._pending_new.clear()

    # ---- vault (trusted copies) ---------------------------------------

    def _vault_path(self, digest):
        return os.path.join(self.vault_dir, digest)

    def _vault_store(self, path, digest):
        """Keep a copy of `path` under its hash, so it can be restored later."""
        if not self.vault_dir or os.path.exists(self._vault_path(digest)):
            return
        if os.path.getsize(path) > self.cfg.get("vault_max_mb", 20) * 2**20:
            return
        os.makedirs(self.vault_dir, mode=0o700, exist_ok=True)
        tmp = self._vault_path(digest) + ".tmp"
        check = hashlib.sha256()
        try:
            with open(path, "rb") as src, os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as dst:
                for block in iter(lambda: src.read(CHUNK), b""):
                    check.update(block)
                    dst.write(block)
        except OSError:
            if os.path.exists(tmp):
                os.remove(tmp)
            return
        if check.hexdigest() == digest:
            os.replace(tmp, self._vault_path(digest))
        else:
            os.remove(tmp)  # file changed while copying; the next scan will catch it

    # ---- approvals ----------------------------------------------------

    def _drop_pending(self, path):
        """Forget the request waiting on `path` (and the other path of a rename); returns its id."""
        req_id = self._pending.pop(path, None)
        if req_id is not None:
            for other in [p for p, r in self._pending.items() if r == req_id]:
                del self._pending[other]
            self._pending_new &= set(self._pending)
        return req_id

    def _ask(self, root, path, old, title, details):
        req = self.approvals.request(
            module=self.name,
            title=title,
            summary=path,
            details={"path": path, **details},
            on_allow=lambda: self._accept(root, path),
            on_deny=lambda: self._rewind(root, path, old),
            key=f"file:{path}",
        )
        self._pending[path] = req.id
        if old is None:
            self._pending_new.add(path)

    def _accept(self, root, path):
        with self._lock:
            self._drop_pending(path)
            if os.path.isfile(path):
                st = os.stat(path)
                digest = sha256_file(path)
                self.db.upsert_file(root, path, {"sha256": digest, "size": st.st_size, "mtime": st.st_mtime, "mode": stat.S_IMODE(st.st_mode)})
                self._vault_store(path, digest)
                return f"Accepted the current version of {path} as trusted"
            self.db.delete_file(path)
            return f"Accepted the deletion of {path}"

    def _accept_rename(self, root, old_path, new_path):
        with self._lock:
            self._drop_pending(old_path)
            self.db.delete_file(old_path)
            if os.path.isfile(new_path):
                self._accept(root, new_path)
            return f"Accepted the rename of {old_path} to {new_path}"

    def _rewind_rename(self, root, old_path, new_path, old):
        with self._lock:
            self._drop_pending(old_path)
            if os.path.lexists(new_path) and not os.path.lexists(old_path):
                os.makedirs(os.path.dirname(old_path), exist_ok=True)
                os.rename(new_path, old_path)
                self._rewind(root, old_path, old)  # also puts back the old permissions
                return f"Renamed {new_path} back to {old_path}"
            message = self._rewind(root, old_path, old)
            if os.path.lexists(new_path):
                message += "; " + self._rewind(root, new_path, None)
            return message

    def _rewind(self, root, path, old):
        with self._lock:
            self._drop_pending(path)
            if old is None:  # an unexpected new file: move it out of the way, never delete it
                if not os.path.lexists(path):
                    return f"{path} is already gone"
                os.makedirs(self.quarantine_dir, mode=0o700, exist_ok=True)
                dest = os.path.join(self.quarantine_dir, f"{int(time.time())}_{os.path.basename(path)}")
                shutil.move(path, dest)
                return f"Moved {path} to quarantine: {dest}"

            if os.path.isfile(path) and sha256_file(path) == old["sha256"]:
                os.chmod(path, old["mode"])
                message = f"Restored permissions of {path} to {oct(old['mode'])}"
            else:
                trusted = self._vault_path(old["sha256"]) if self.vault_dir else None
                if not trusted or not os.path.exists(trusted):
                    raise FileNotFoundError(f"No trusted copy of {path} in the vault (file too large or vault disabled)")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                tmp = path + ".cybershield-restore"
                shutil.copyfile(trusted, tmp)
                os.chmod(tmp, old["mode"])
                os.replace(tmp, path)
                message = f"Restored {path} from the trusted copy"
            st = os.stat(path)
            self.db.upsert_file(root, path, {"sha256": old["sha256"], "size": st.st_size, "mtime": st.st_mtime, "mode": stat.S_IMODE(st.st_mode)})
            return message

    # ---- scanning -----------------------------------------------------

    def _event(self, severity, title, path, **details):
        change = {"timestamp": time.time(), "severity": severity, "title": title, "path": path, **details}
        if severity != INFO:
            self.recent_changes.appendleft(change)
        # No cooldown key: every event is a distinct change (the baseline moves on or a request is pending).
        return SecurityEvent(module=self.name, severity=severity, title=title, details={"path": path, **details})

    def _report(self, events, root, path, old, severity, title, details):
        """Raise the alert; with approvals on, also ask the user (once per pending change)."""
        if self.approvals is None:
            events.append(self._event(severity, title, path, **details))
            return
        if path in self._pending:
            return
        events.append(self._event(severity, title, path, awaiting_confirmation=True, **details))
        self._ask(root, path, old, title, details)

    def _report_rename(self, events, root, old_path, new_path, old, entry):
        details = {"old_path": old_path, "size": entry["size"]}
        if self.approvals is None:
            events.append(self._event(MEDIUM, "File renamed or moved", new_path, **details))
            return
        if old_path in self._pending or new_path in self._pending:
            return
        events.append(self._event(MEDIUM, "File renamed or moved", new_path, awaiting_confirmation=True, **details))
        req = self.approvals.request(
            module=self.name,
            title="File renamed or moved",
            summary=f"{old_path}  ->  {new_path}",
            details={"path": new_path, **details},
            on_allow=lambda: self._accept_rename(root, old_path, new_path),
            on_deny=lambda: self._rewind_rename(root, old_path, new_path, old),
            key=f"file:{old_path}",
        )
        self._pending[old_path] = self._pending[new_path] = req.id
        self._pending_new.add(new_path)

    def _scan_root(self, root, events, errors):
        baseline = self.db.get_baseline(root)
        initial = not self.db.has_root(root)
        max_bytes = self.cfg["max_file_size_mb"] * 2**20
        current = {}
        new_files = {}  # reported after the scan, so a rename (deleted + new, same content) is one change

        for path in self.iter_files(root):
            try:
                st = os.stat(path)
            except OSError as exc:
                errors.append(f"{path}: {exc.strerror}")
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_size > max_bytes:
                errors.append(f"{path}: skipped, larger than {self.cfg['max_file_size_mb']} MB")
                continue

            old = baseline.get(path)
            mode = stat.S_IMODE(st.st_mode)
            unchanged_meta = old and old["size"] == st.st_size and old["mtime"] == st.st_mtime and old["mode"] == mode
            if self.cfg["fast_mode"] and unchanged_meta:
                digest = old["sha256"]
            else:
                try:
                    digest = sha256_file(path)
                except OSError as exc:
                    errors.append(f"{path}: {exc.strerror}")
                    if old:
                        current[path] = old  # keep it so an unreadable file is not reported as deleted
                    continue

            entry = {"sha256": digest, "size": st.st_size, "mtime": st.st_mtime, "mode": mode}
            change = None
            if not initial and old is None:
                new_files[path] = entry
                if self.approvals is None:
                    current[path] = entry
                continue
            if not initial:
                if digest != old["sha256"]:
                    change = (MEDIUM, "File modification detected", {
                        "old_hash": old["sha256"][:16], "new_hash": digest[:16],
                        "old_size": old["size"], "new_size": st.st_size,
                    })
                elif mode != old["mode"]:
                    change = (MEDIUM, "File permissions changed", {"old_mode": oct(old["mode"]), "new_mode": oct(mode)})

            if change and self.approvals:
                if old:
                    current[path] = old  # hold the trusted state until the user decides
                self._report(events, root, path, old, *change)
                continue
            if change is None and path in self._pending:
                # The file went back to its trusted state on its own; nothing left to decide.
                self.approvals.cancel(self._drop_pending(path), "file returned to its trusted state")
            if change:
                self._report(events, root, path, old, *change)
            current[path] = entry
            if self.approvals:
                self._vault_store(path, digest)

        if initial:
            self.db.add_root(root)
            events.append(self._event(INFO, "Integrity baseline created", root, files=len(current)))
        else:
            by_hash = {}
            for path, entry in new_files.items():
                by_hash.setdefault(entry["sha256"], []).append(path)
            for path in sorted(set(baseline) - set(current)):
                old = baseline[path]
                if self.approvals:
                    current[path] = old
                twins = [] if path in self._pending else by_hash.get(old["sha256"], [])
                if twins:
                    new_path = twins.pop(0)
                    self._report_rename(events, root, path, new_path, old, new_files.pop(new_path))
                else:
                    self._report(events, root, path, old, MEDIUM, "Monitored file deleted", {})
            for path, entry in new_files.items():
                self._report(events, root, path, None, LOW, "New file detected", {"size": entry["size"]})

        self.db.save_baseline(root, current)
        return {"path": root, "files": len(current), "exists": os.path.exists(root)}

    def poll(self):
        with self._lock:
            started = time.time()
            events, errors, roots = [], [], []
            for root in self.cfg["watch_paths"]:
                roots.append(self._scan_root(root, events, errors))
            # A new file that disappeared before anyone answered (e.g. Explorer's "New Text Document.txt"
            # renamed while the popup was open) has nothing left to decide.
            for path in [p for p in self._pending_new if not os.path.lexists(p)]:
                self.approvals.cancel(self._drop_pending(path), "file no longer exists")
            if self._watcher is not None:
                self._watcher.sync(self._watch_dirs())
            snapshot = {
                "roots": roots,
                "total_files": sum(r["files"] for r in roots),
                "last_scan": started,
                "scan_seconds": round(time.time() - started, 3),
                "recent_changes": list(self.recent_changes),
                "errors": errors[:20],
                "error_count": len(errors),
                "fast_mode": self.cfg["fast_mode"],
                "realtime": self._watcher is not None,
                "protected": self.approvals is not None,
                "pending": len(self._pending),
            }
            return snapshot, events
