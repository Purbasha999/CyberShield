"""Minimal Linux inotify wrapper (ctypes, no dependencies).

Used only as a wake-up signal: when anything changes in a watched directory the file monitor
rescans immediately instead of waiting for its next interval. Changes made by Windows apps to
/mnt/* drives do not raise inotify events, so the regular interval scan still covers those.
"""

import ctypes
import ctypes.util
import os
import select

IN_MODIFY = 0x002
IN_ATTRIB = 0x004
IN_CLOSE_WRITE = 0x008
IN_MOVED_FROM = 0x040
IN_MOVED_TO = 0x080
IN_CREATE = 0x100
IN_DELETE = 0x200
IN_DELETE_SELF = 0x400
IN_MOVE_SELF = 0x800
WATCH_MASK = (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO
              | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF)


class Inotify:
    def __init__(self):
        self._libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        self.fd = self._libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self._watched = set()

    def add(self, path):
        if path in self._watched:
            return True
        wd = self._libc.inotify_add_watch(self.fd, os.fsencode(path), WATCH_MASK)
        if wd >= 0:
            self._watched.add(path)
        return wd >= 0

    def sync(self, directories):
        """Watch these directories (new subfolders appear here after each scan)."""
        # A deleted directory's watch is removed by the kernel, so forget it and re-add if it returns.
        self._watched = {p for p in self._watched if os.path.isdir(p)}
        for path in directories:
            self.add(path)

    def wait(self, timeout):
        """Block up to `timeout` seconds; True if something changed."""
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return False
        try:
            while os.read(self.fd, 65536):
                pass
        except BlockingIOError:
            pass
        return True

    def close(self):
        os.close(self.fd)
