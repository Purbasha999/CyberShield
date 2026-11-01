import os
import time

import pytest

from modules.login_monitor import LoginMonitor, parse_line, parse_timestamp
from security.events import HIGH, INFO, LOW, MEDIUM
from tests.conftest import auth_line, linux_only, not_root

SSH_FAIL = "sshd[1201]: Failed password for invalid user admin from 203.0.113.50 port 51234 ssh2"
SU_FAIL = ("su[2201]: pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 "
           "tty=/dev/pts/1 ruser=alice rhost=  user=root")


def make_monitor(log_path, **overrides):
    cfg = {"log_path": str(log_path), "max_failed_attempts": 3, "window_seconds": 300, "read_history_on_start": True}
    cfg.update(overrides)
    return LoginMonitor(cfg)


def append(path, *lines):
    with open(path, "a") as fh:
        fh.writelines(lines)


def titles(events):
    return [e.title for e in events]


# ---- parser ----

def test_parse_rfc3339_ssh_failure():
    rec = parse_line(auth_line(SSH_FAIL, ts=1_700_000_000.5))
    assert (rec.kind, rec.service, rec.user, rec.source) == ("failure", "sshd", "admin", "203.0.113.50")
    assert rec.timestamp == pytest.approx(1_700_000_000.5)


def test_parse_traditional_syslog_format():
    now = time.mktime((2026, 10, 27, 15, 0, 0, 0, 0, -1))
    rec = parse_line(f"Oct 27 14:16:45 laptop {SSH_FAIL}\n", now=now)
    assert rec.kind == "failure"
    assert rec.timestamp == time.mktime((2026, 10, 27, 14, 16, 45, 0, 0, -1))


def test_december_line_read_in_january_uses_previous_year():
    now = time.mktime((2027, 1, 2, 10, 0, 0, 0, 0, -1))
    assert parse_timestamp("Dec 31 23:59:00", now) == time.mktime((2026, 12, 31, 23, 59, 0, 0, 0, -1))


def test_parse_su_failure():
    rec = parse_line(auth_line(SU_FAIL))
    assert (rec.kind, rec.service, rec.user, rec.source) == ("failure", "su", "root", "alice")


def test_parse_sudo_failure_uses_logname_when_no_ruser():
    line = "sudo[3001]: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser= rhost=  user=bob"
    rec = parse_line(auth_line(line))
    assert (rec.kind, rec.service, rec.source) == ("failure", "sudo", "bob")


def test_sshd_pam_failure_is_ignored_to_avoid_double_counting():
    line = "sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.50"
    assert parse_line(auth_line(line)) is None


def test_sudo_summary_line_is_ignored():
    line = "sudo[3001]:      bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id"
    assert parse_line(auth_line(line)) is None


def test_parse_successful_logins():
    ssh = parse_line(auth_line("sshd[9]: Accepted publickey for alice from 198.51.100.7 port 2200 ssh2: ED25519 SHA256:abc"))
    assert (ssh.kind, ssh.user, ssh.source) == ("success", "alice", "198.51.100.7")
    su = parse_line(auth_line("su[5]: pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)"))
    assert (su.kind, su.service, su.user, su.source) == ("success", "su", "root", "alice")


def test_background_sessions_are_not_logins():
    cron = "CRON[77]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)"
    systemd = "(systemd): pam_unix(systemd-user:session): session opened for user alice(uid=1000) by alice(uid=0)"
    assert parse_line(auth_line(cron)) is None
    assert parse_line(auth_line(systemd)) is None


def test_parse_sudo_command():
    rec = parse_line(auth_line("sudo[42]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"))
    assert (rec.kind, rec.user, rec.detail) == ("sudo_command", "alice", "/usr/bin/apt update")


@pytest.mark.parametrize(
    "message, kind, user",
    [
        ("useradd[88]: new user: name=mallory, UID=1001, GID=1001, home=/home/mallory, shell=/bin/bash", "user_created", "mallory"),
        ("usermod[89]: add 'mallory' to group 'sudo'", "privilege_grant", "mallory"),
        ("usermod[89]: add 'mallory' to shadow group 'sudo'", "privilege_grant", "mallory"),
        ("gpasswd[90]: user mallory added by root to group sudo", "privilege_grant", "mallory"),
        ("passwd[91]: pam_unix(passwd:chauthtok): password changed for alice", "password_changed", "alice"),
    ],
)
def test_parse_account_changes(message, kind, user):
    rec = parse_line(auth_line(message))
    assert (rec.kind, rec.user) == (kind, user)


@pytest.mark.parametrize("line", ["", "garbage", "2026-10-27T14:16:44+00:00 host systemd-logind[161]: New seat seat0."])
def test_uninteresting_lines_return_none(line):
    assert parse_line(line) is None


# ---- monitor ----

def test_failed_logins_over_threshold_raise_high_alert(auth_log):
    """Spec test case: 'Generate failed login attempts -> failed attempts detected'."""
    monitor = make_monitor(auth_log)
    append(auth_log, *[auth_line(SSH_FAIL) for _ in range(3)])
    snapshot, events = monitor.poll()
    assert titles(events) == ["Failed login attempt"] * 3, "3 attempts = threshold, not above it"
    assert snapshot["failed_in_window"] == 3

    append(auth_log, auth_line(SSH_FAIL))
    snapshot, events = monitor.poll()
    assert titles(events) == ["Failed login attempt", "Multiple failed login attempts"]
    alert = events[1]
    assert alert.severity == HIGH
    assert alert.details["source"] == "203.0.113.50"
    assert alert.details["attempts"] == 4
    assert alert.details["users"] == ["admin"]
    assert snapshot["top_sources"] == [("203.0.113.50", 4)]


def test_brute_force_alert_not_repeated_within_window(auth_log):
    monitor = make_monitor(auth_log)
    append(auth_log, *[auth_line(SSH_FAIL) for _ in range(10)])
    _, events = monitor.poll()
    assert titles(events).count("Multiple failed login attempts") == 1


def test_sources_are_counted_separately(auth_log):
    monitor = make_monitor(auth_log)
    append(auth_log, *[auth_line(SSH_FAIL) for _ in range(2)], *[auth_line(SU_FAIL) for _ in range(2)])
    snapshot, events = monitor.poll()
    assert "Multiple failed login attempts" not in titles(events)
    assert snapshot["failed_in_window"] == 4


def test_old_failures_outside_window_do_not_alert(auth_log):
    old = time.time() - 3600
    append(auth_log, *[auth_line(SSH_FAIL, ts=old + i) for i in range(10)])
    snapshot, events = make_monitor(auth_log).poll()
    assert events == []
    assert snapshot["failed_total"] == 10
    assert snapshot["failed_in_window"] == 0


def test_only_new_lines_are_processed(auth_log):
    monitor = make_monitor(auth_log)
    append(auth_log, auth_line(SSH_FAIL))
    assert len(monitor.poll()[1]) == 1
    assert monitor.poll()[1] == []
    append(auth_log, auth_line(SU_FAIL))
    assert len(monitor.poll()[1]) == 1


def test_partial_line_is_completed_on_next_poll(auth_log):
    monitor = make_monitor(auth_log)
    full = auth_line(SSH_FAIL)
    append(auth_log, full[:40])
    assert monitor.poll()[1] == []
    append(auth_log, full[40:])
    assert titles(monitor.poll()[1]) == ["Failed login attempt"]


def test_log_rotation_restarts_from_beginning(auth_log):
    monitor = make_monitor(auth_log)
    append(auth_log, *[auth_line(SSH_FAIL) for _ in range(3)])
    monitor.poll()
    auth_log.write_text(auth_line(SU_FAIL))  # truncated + new content, like logrotate copytruncate
    snapshot, events = monitor.poll()
    assert titles(events) == ["Failed login attempt"]
    assert events[0].details["service"] == "su"


def test_history_can_be_skipped_on_start(auth_log):
    append(auth_log, *[auth_line(SSH_FAIL) for _ in range(5)])
    monitor = make_monitor(auth_log, read_history_on_start=False)
    snapshot, events = monitor.poll()
    assert events == [] and snapshot["failed_total"] == 0


def test_account_change_severities(auth_log):
    monitor = make_monitor(auth_log)
    append(
        auth_log,
        auth_line("useradd[88]: new user: name=mallory, UID=1001, GID=1001, home=/home/mallory, shell=/bin/bash"),
        auth_line("usermod[89]: add 'mallory' to group 'sudo'"),
        auth_line("passwd[91]: pam_unix(passwd:chauthtok): password changed for mallory"),
        auth_line("sudo[42]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"),
        auth_line("su[5]: pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)"),
    )
    snapshot, events = monitor.poll()
    assert [(e.title, e.severity) for e in events] == [
        ("New user account created", MEDIUM),
        ("User granted administrator privileges", HIGH),
        ("Account password changed", LOW),
        ("Privileged command executed", INFO),
        ("Successful login", INFO),
    ]
    assert snapshot["sudo_total"] == 1 and snapshot["success_total"] == 1
    assert snapshot["recent"][0]["kind"] == "success"


def test_missing_log_file(tmp_path):
    snapshot, events = make_monitor(tmp_path / "nope.log").poll()
    assert snapshot["status"] == "MISSING" and events == []


@linux_only
@not_root
def test_unreadable_log_reports_no_access(auth_log):
    os.chmod(auth_log, 0o000)
    try:
        snapshot, _ = make_monitor(auth_log).poll()
        assert snapshot["status"] == "NO ACCESS"
        assert "adm" in snapshot["message"]
    finally:
        os.chmod(auth_log, 0o644)


@linux_only
def test_real_auth_log_is_parseable_if_readable():
    """Smoke test against this machine's actual /var/log/auth.log."""
    path = "/var/log/auth.log"
    if not os.access(path, os.R_OK):
        pytest.skip("auth.log not readable (add user to adm group)")
    snapshot, _ = make_monitor(path).poll()
    assert snapshot["status"] == "OK"
