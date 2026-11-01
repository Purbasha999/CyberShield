# CyberShield OS

A security monitoring layer for Linux, built as an Operating Systems course project. It watches
processes, CPU, memory and disk usage, selected files and login activity. It applies simple
detection rules, logs every security event, and shows the results in a web or terminal dashboard.

```
 Process ─┐
 File ────┤                         ┌─ rotating log file
 Login ───┼─► Security Engine ──► Alert Manager ─┼─ SQLite event database
 Resource ┘   (one thread per        (severity,  └─ Web / terminal dashboard
               monitor)               cooldown)
```

## Modules

| Module | What it watches | Rules (all configurable in `config/config.json`) | Severity |
|---|---|---|---|
| **Process Monitor** (`modules/process_monitor.py`) | Every process: PID, name, owner, state, CPU %, memory % | CPU ≥ 80 % (of one core) for 2 polls in a row: **blocked** | LOW + MEDIUM "blocked" |
| | | Memory ≥ 25 % of RAM: **blocked** | LOW + MEDIUM "blocked" |
| | | Name on the watch list (`xmrig`, `nc`, `hydra`, …) | MEDIUM |
| | | Executable running from `/tmp`, `/dev/shm` or `/var/tmp` | MEDIUM |
| **File Integrity** (`modules/file_monitor.py`) | SHA-256 + permissions of the files and folders you list | Content changed | MEDIUM |
| | | File deleted / permissions changed | MEDIUM |
| | | New file in a watched folder | LOW |
| | | File renamed or moved (same content, new name) | MEDIUM |
| **Login Monitor** (`modules/login_monitor.py`) | `/var/log/auth.log` (ssh, su, sudo, login, useradd, usermod, passwd) | Failed attempts from one source > 3 within 5 min | HIGH |
| | | User added to `sudo`/`admin`/`wheel` group | HIGH |
| | | New user account | MEDIUM |
| | | Password changed | LOW |
| | | Successful logins, sudo commands, single failures | INFO (logged) |
| **Resource Monitor** (`modules/resource_monitor.py`) | CPU (total and per core), RAM, swap, disk, load, uptime, network bytes, process count | CPU or RAM ≥ 90 % for 3 polls; disk ≥ 90 % | LOW |
| **Alert Manager** (`security/alert_manager.py`) | Events from all modules | Drops duplicate alerts within a 60 s cooldown and works out module and overall status | – |
| **Event Logger** (`security/event_logger.py`) | Every accepted event | Writes to `security_events.log` (rotating) and SQLite | – |

Overall status: **SECURE** (no alerts in the last 5 minutes), **NOTICE** (LOW), **WARNING** (MEDIUM), **CRITICAL** (HIGH).

## Confirm-or-rewind protection

For the riskiest alerts, CyberShield doesn't just report the change. It holds the change and asks you
whether to keep it:

| You do… | CyberShield… | Allow | Block & rewind |
|---|---|---|---|
| Delete a watched file | asks within ~0.2 s | deletion is accepted | file restored from its trusted copy |
| Edit a watched file | asks within ~0.2 s | new version becomes the trusted copy | previous content restored |
| `chmod` a watched file | asks within ~0.2 s | new permissions accepted | old permissions restored |
| Create a file in a watched folder | asks within ~0.2 s | file is added to the baseline | file moved to `~/.cybershield/quarantine/` (never deleted) |
| Rename a watched file | asks once within ~0.2 s | new name is trusted | renamed back |
| Start a suspicious process (`xmrig`, run from `/tmp`, …) | **freezes it** (SIGSTOP) within one poll (~3 s) and asks | process resumes and isn't asked about again | process is killed |

**Edit from Windows File Explorer:** open `\\wsl$\Ubuntu\home\<you>\cybershield_watch` (or run
`explorer.exe ~/cybershield_watch`). Changes made there reach Linux instantly, so the same popups
appear. Explorer's *New → Text Document* first creates `New Text Document.txt`. Once you type the
real name, the first question closes by itself and you're asked about the final name only.

**Heavy processes are blocked automatically.** A process of yours using ≥ 80 % of a core for two
checks, or ≥ 25 % of RAM, is stopped at once (SIGTERM, then SIGKILL). A popup and a dashboard
dialog then tell you *"Potentially harmful process blocked"*. CyberShield never blocks itself, the
terminal that started it, other users' processes, or names in `process_monitor.block_exempt_names`.
Turn it off with `"block_heavy_processes": false`. Stop CyberShield before running `pytest`, or it
may block the test suite's CPU-burning tests.

**How you're asked:**
- **Windows popup.** Under WSL CyberShield opens a native Windows Yes/No box via `powershell.exe`, with nothing to install. On a Linux desktop it uses `zenity`.
- **Dashboard dialog** with Allow and Block & rewind buttons and a countdown. Click *Enable desktop alerts* in the top bar for browser notifications as well.

Whichever you answer first counts, and the other closes. If you don't answer within
`timeout_seconds` (default 120), the `on_timeout` policy applies (default `rewind`). Stopping
CyberShield applies the same policy to anything still waiting.

**How it works:** Linux doesn't let a normal program pause a delete *before* it happens; that needs
a kernel security module. So CyberShield does the next best thing:
1. inotify reports file changes instantly.
2. The vault (`~/.cybershield/vault/`, private, files up to `vault_max_mb`) holds a copy of every
   trusted file, so any change can be undone.
3. Suspicious processes are frozen with SIGSTOP while you decide.

**Notes:**
- **System files** such as `/etc/passwd`, and other users' processes, can only be rewound when CyberShield runs with
  `sudo`. Otherwise you get a HIGH "Rewind failed" alert. Under `sudo`, Ubuntu sets `HOME=/root`, so data goes
  to `/root/.cybershield`.
- **Answer Allow for your own admin work.** `sudo adduser` edits `/etc/passwd` and `/etc/group`, so you'll be asked.
  Rewinding only some of the account files would leave the account half-created.
- **Turn it off or tune it** in `config.json` → `approvals` (`enabled`, `file_changes`, `suspicious_processes`,
  `timeout_seconds`, `on_timeout`, `popup`: `auto` / `windows` / `zenity` / `off`).

## Project structure

```
OS_CyberShield/
├── main.py                    # entry point (web / terminal / --once / --rebaseline)
├── config/                    # config.json + loader (defaults, ~ expansion)
├── modules/                   # process, file, login, resource monitors
├── security/                  # events, alert manager, event logger, engine
├── database/                  # SQLite event store + file-integrity baseline
├── dashboard/                 # web server (stdlib), static UI, terminal view
├── tests/                     # pytest suite, one file per module + integration
├── scripts/                   # setup + attack simulations for demos
└── docs/                      # project brief and system requirements
```

Runtime data is kept **outside the project**, in `~/.cybershield/`:
`cyber_events.db` (events + file baseline) and `logs/security_events.log`. This keeps usernames and
IPs from auth.log out of Git, and stops the file monitor from alerting on its own database.

## Setup and running

Everything below runs inside **Ubuntu on WSL2** (or any Ubuntu/Kali machine).

### 1. Open Ubuntu and go to the project

```bash
cd /mnt/e/My_Programming/Coding/OS_CyberShield
```

### 2. One-time setup

```bash
bash scripts/setup_wsl.sh
```

This script:
- installs any missing packages (`python3-venv`, `rsyslog`)
- creates a virtual environment at `~/.venvs/cybershield` with `psutil` and `pytest`
- creates the demo folder `~/cybershield_watch`
- checks that you can read `/var/log/auth.log`

If it adds you to the `adm` group, run `wsl --shutdown` in Windows PowerShell and reopen Ubuntu.

### 3. Activate the virtual environment (each new terminal)

```bash
source ~/.venvs/cybershield/bin/activate
```

### 4. Run the tests

```bash
python -m pytest -v
```

### 5. Start CyberShield

```bash
python main.py                    # web dashboard
```

Open **http://localhost:8080** in your Windows browser. WSL2 forwards localhost automatically.

Other modes:

```bash
python main.py --mode terminal    # live terminal dashboard (like the report's example output)
python main.py --once             # one scan, print report, exit
python main.py --rebaseline       # trust the current state of all watched files
python main.py --port 8090        # if 8080 is busy
sudo ~/.venvs/cybershield/bin/python main.py   # full process details for other users (optional)
```

Stop with **Ctrl+C**.

### 6. Trigger alerts (in a second Ubuntu terminal)

```bash
cd /mnt/e/My_Programming/Coding/OS_CyberShield
source ~/.venvs/cybershield/bin/activate

bash scripts/simulate_failed_logins.sh        # HIGH   – brute-force detection
bash scripts/simulate_suspicious_process.sh   # MEDIUM – "xmrig" running from /tmp (a renamed Python that only sleeps)
python scripts/simulate_cpu_load.py           # CPU-hungry process -> alert + BLOCKED + popup
python scripts/simulate_cpu_load.py --spread  # whole CPU ~100%, each process ~50% -> system CPU alert, nothing blocked
python scripts/simulate_memory_hog.py         # process holding 35% of RAM -> alert + BLOCKED + popup
python scripts/simulate_workload.py           # waves of CPU + RAM for the charts, kept under the block limits (3 min)
python scripts/simulate_file_tamper.py        # MEDIUM/LOW – modify, create, chmod, delete in ~/cybershield_watch
bash scripts/demo_all.sh                      # all of the above in sequence
```

You can also cause a real failed login: run `su root` and type a wrong password 4 times.

### 7. View logs

```bash
tail -f ~/.cybershield/logs/security_events.log
sqlite3 ~/.cybershield/cyber_events.db "SELECT datetime(timestamp,'unixepoch','localtime'), severity, title FROM events ORDER BY id DESC LIMIT 20;"
```

## Tests

| File | Covers |
|---|---|
| `test_process.py` | Rule logic; a real CPU-burning child process alerts once; short spikes ignored; a fake `xmrig` in `/tmp` flagged |
| `test_file.py` | Baseline, modify, create, delete, chmod, nested dirs, excludes, restart persistence, rebaseline, fast mode, size limit, unreadable files |
| `test_login.py` | Parser for ssh/su/sudo/useradd/usermod/gpasswd/passwd in both syslog timestamp formats; threshold, window, per-source counting, incremental tailing, partial lines, log rotation, missing/unreadable log |
| `test_resource.py` | Real snapshot values; CPU/RAM/disk thresholds, sustain logic, re-arming |
| `test_alerts.py` | Severities, cooldown, status levels, log file + SQLite writing, queries and 24 h buckets |
| `test_engine.py` | All modules together; full attack scenario end to end; crashing module isolated; threads start/stop |
| `test_dashboard.py` | HTTP API, static files, security headers, path traversal blocked, POST needs custom header, approval API flow; terminal layout |
| `test_approvals.py` | Allow/rewind/timeout/shutdown/first-answer-wins; popup answer and cancel plumbing; rewinding deletes, edits, chmod, new files (quarantine), whole folders; vault privacy; inotify wake-up; real process frozen then killed or resumed |
| `test_main.py` | CLI `--once`, `--rebaseline`, bad config |
| `test_config.py` | Defaults, merging, path expansion, invalid JSON |

## Configuration notes

- **Watch more files:** add paths to `file_monitor.watch_paths`. Windows drives work too
  (`/mnt/e/Documents/important`). For large folders, set `"fast_mode": true` so files are only
  re-hashed when their size or modified time changes, and add noisy folders to `exclude`.
- **Root-only files** (`/etc/shadow`, `/etc/sudoers`) can be watched only when CyberShield runs with `sudo`.
- **Scope:** CyberShield monitors the Linux system it runs on. Under WSL2 that is the WSL VM, not Windows apps.

## Security design

- CyberShield changes files and stops processes only as described above: it rewinds changes you
  blocked and stops your own CPU- or memory-heavy processes. Quarantined files are moved, never deleted.
- The dashboard binds to `127.0.0.1` only. It sends CSP, `nosniff` and `X-Frame-Options` headers.
  Static file paths are confined to `dashboard/static`. POST actions require a custom header, so
  other websites open in your browser cannot trigger them.
- Runs as a normal user. Reading auth.log needs only the `adm` group, not root.
- Simulations use `logger`, a renamed Python that only sleeps, and a temp folder. Nothing touches the network or real accounts.
