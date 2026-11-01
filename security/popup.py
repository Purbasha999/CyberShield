"""Native Yes/No popups for approval requests.

Under WSL the popup is a Windows message box (through powershell.exe, nothing to install).
On a Linux desktop it uses zenity. The message text travels in environment variables, so it
never has to be escaped into a command line.
"""

import logging
import os
import shutil
import subprocess
import threading
import time

log = logging.getLogger("cybershield.popup")

WINDOWS_POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"

# Default button is "No" (Button2), so an accidental Enter blocks rather than allows.
POWERSHELL_SCRIPT = (
    "Add-Type -AssemblyName System.Windows.Forms;"
    "$owner = New-Object System.Windows.Forms.Form;"
    "$owner.TopMost = $true;"
    "$r = [System.Windows.Forms.MessageBox]::Show($owner, $env:CS_MSG, $env:CS_TITLE, 'YesNo', 'Warning', 'Button2');"
    "Write-Output $r"
)

# Information-only box (OK button) for things CyberShield already did, e.g. blocking a process.
POWERSHELL_NOTICE = (
    "Add-Type -AssemblyName System.Windows.Forms;"
    "$owner = New-Object System.Windows.Forms.Form;"
    "$owner.TopMost = $true;"
    "[void][System.Windows.Forms.MessageBox]::Show($owner, $env:CS_MSG, $env:CS_TITLE, 'OK', 'Error')"
)


def is_wsl():
    try:
        with open("/proc/version") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


def find_powershell():
    return shutil.which("powershell.exe") or (WINDOWS_POWERSHELL if os.path.exists(WINDOWS_POWERSHELL) else None)


def detect_kind(mode="auto"):
    if mode == "off":
        return None
    if mode in ("auto", "windows") and is_wsl() and find_powershell():
        return "windows"
    if mode in ("auto", "zenity") and shutil.which("zenity") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return "zenity"
    return None


def message_for(req, on_timeout):
    seconds = max(1, int(req.deadline - time.time()))
    default = "allowed" if on_timeout == "allow" else "blocked and rewound"
    return (
        f"{req.title}\n\n{req.summary}\n\n"
        "Do you want to continue?\n\n"
        "Yes  =  continue (allow it)\n"
        "No   =  stop it and rewind\n\n"
        f"If you don't answer within {seconds}s it will be {default}."
    )


def parse_windows(returncode, stdout):
    answer = (stdout or "").strip().splitlines()[-1:] or [""]
    return {"Yes": True, "No": False}.get(answer[0].strip())


def parse_zenity(returncode, stdout):
    return {0: True, 1: False}.get(returncode)  # 5 = zenity's own timeout -> no answer


class NativePrompter:
    def __init__(self, mode="auto"):
        self.kind = detect_kind(mode)
        self._procs = {}
        self._lock = threading.Lock()

    @property
    def available(self):
        return self.kind is not None

    @staticmethod
    def _windows_command(script, title, text):
        # WSLENV lists the variables WSL copies into the Windows process environment.
        shared = ":".join(filter(None, [os.environ.get("WSLENV"), "CS_TITLE", "CS_MSG"]))
        env = {"CS_TITLE": title, "CS_MSG": text, "WSLENV": shared}
        return [find_powershell(), "-NoProfile", "-NonInteractive", "-Command", script], env

    def _command(self, req, on_timeout):
        """Return (argv, extra_env, parser) for this request."""
        title, text = f"CyberShield OS - {req.module} protection", message_for(req, on_timeout)
        if self.kind == "windows":
            return (*self._windows_command(POWERSHELL_SCRIPT, title, text), parse_windows)
        if self.kind == "zenity":
            seconds = str(max(1, int(req.deadline - time.time())))
            argv = ["zenity", "--question", "--title", title, "--text", text,
                    "--ok-label=Allow", "--cancel-label=Block and rewind", "--timeout", seconds]
            return argv, {}, parse_zenity
        return None

    def _notice_command(self, title, text):
        if self.kind == "windows":
            return self._windows_command(POWERSHELL_NOTICE, title, text)
        if self.kind == "zenity":
            return ["zenity", "--error", "--title", title, "--text", text], {}
        return None

    def notify(self, title, text):
        """Show an information popup and return at once; nobody waits for the OK click."""
        command = self._notice_command(f"CyberShield OS - {title}", text)
        if command is None:
            return False
        argv, extra_env = command
        try:
            subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             env={**os.environ, **extra_env}, start_new_session=True)
        except OSError as exc:
            log.warning("could not open popup: %s", exc)
            return False
        return True

    def ask(self, req, on_timeout, callback):
        command = self._command(req, on_timeout)
        if command is None:
            return
        threading.Thread(target=self._run, args=(req, command, callback), name=f"popup-{req.id}", daemon=True).start()

    def _run(self, req, command, callback):
        argv, extra_env, parser = command
        try:
            proc = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, env={**os.environ, **extra_env},
            )
        except OSError as exc:
            log.warning("could not open popup: %s", exc)
            return
        with self._lock:
            self._procs[req.id] = proc
        try:
            out, _ = proc.communicate(timeout=max(1, req.deadline - time.time()) + 5)
        except subprocess.TimeoutExpired:
            proc.kill()
            return
        finally:
            with self._lock:
                cancelled = self._procs.pop(req.id, None) is None
        if cancelled:
            return  # answered elsewhere; we closed the popup ourselves
        answer = parser(proc.returncode, out)
        if answer is not None:
            callback(answer)

    def cancel(self, req):
        with self._lock:
            proc = self._procs.pop(req.id, None)
        if proc is not None and proc.poll() is None:
            proc.kill()
