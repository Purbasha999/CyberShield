# CyberShield OS

A lightweight Linux-based security monitoring layer for an Operating Systems course project.

## What this implementation does

CyberShield runs on top of Kali/Debian/Ubuntu Linux and demonstrates:

- Process monitoring with PID, name, CPU, RAM, owner and status
- CPU, RAM, disk and active-process monitoring
- SHA-256 file integrity monitoring
- Linux authentication/login event monitoring
- Centralized severity-based security alerts
- SQLite security-event storage
- Python logging
- A lightweight Flask dashboard
- Basic automated tests

This follows the scope and architecture of the supplied CyberShield OS project specification.

## Architecture

```text
                    Kali Linux
                        |
                  CyberShield OS
                        |
        +---------------+---------------+
        |               |               |
   Process Monitor  Resource Monitor  File Monitor
        |               |               |
        +---------------+---------------+
                        |
                  Login Monitor
                        |
                Security Engine
                        |
          +-------------+-------------+
          |                           |
     Alert Manager              Event Logger
          |                           |
          +-------------+-------------+
                        |
                  SQLite Database
                        |
                 Flask Dashboard
```

## Project structure

```text
CyberShield-OS/
├── main.py
├── requirements.txt
├── config/
│   └── config.json
├── modules/
│   ├── __init__.py
│   ├── process_monitor.py
│   ├── resource_monitor.py
│   ├── file_monitor.py
│   └── login_monitor.py
├── security/
│   ├── __init__.py
│   ├── alert_manager.py
│   └── event_logger.py
├── dashboard/
│   ├── __init__.py
│   └── dashboard.py
├── database/
│   └── .gitkeep
├── logs/
│   └── .gitkeep
├── test_files/
│   └── monitored_sample.txt
└── tests/
    ├── test_process.py
    ├── test_file.py
    └── test_login.py
```

## Installation on Kali Linux

```bash
cd ~/Desktop/CyberShield-OS

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

If your Kali installation does not have the venv package:

```bash
sudo apt update
sudo apt install python3-venv -y
```

Then recreate the virtual environment.

## Start CyberShield

```bash
source venv/bin/activate
python3 main.py
```

The dashboard is available at:

```text
http://127.0.0.1:5000
```

Stop with `Ctrl+C`.

## Important: file-integrity demonstration

The default monitored directory is the project's own `test_files/` directory.

After starting CyberShield, edit:

```text
test_files/monitored_sample.txt
```

The SHA-256 value will change and CyberShield will generate a MEDIUM file-modification alert.

Do NOT initially monitor `/etc`, `/boot`, `/usr`, or other critical system directories while developing the project.

## Process-monitor demonstration

Start a CPU-intensive process in another terminal:

```bash
python3 -c "while True: pass"
```

CyberShield should show the process and can generate a LOW resource alert when the configured threshold is exceeded.

Stop it with `Ctrl+C`.

## Login-monitor demonstration

The login monitor is designed to read Linux authentication information. On systems with `/var/log/auth.log`, it watches that file. If the file is unavailable, it reads new authentication messages through `journalctl`. Only events that happen after CyberShield starts are analysed.

`/var/log/auth.log` is readable only by root and the `adm` group. If CyberShield cannot read it, the dashboard shows a `LOGIN_MONITOR` alert. Either run CyberShield with `sudo`, or add your user to the `adm` group once and log in again:

```bash
sudo usermod -aG adm $USER
```

On WSL, run `wsl --shutdown` from PowerShell and reopen Ubuntu for the group change to apply.

You can inspect your own authentication records with:

```bash
sudo tail -n 30 /var/log/auth.log
```

or:

```bash
sudo journalctl -n 30
```

Do not repeatedly perform real login attacks just to test the project. The included login detector can also be unit-tested safely.

## Run tests

```bash
source venv/bin/activate
python3 -m unittest discover -s tests -v
```

## Data

Runtime data is intentionally generated locally:

- `database/cybershield.db`
- `logs/cybershield.log`
- `config/baseline.json`

These are ignored by Git.

## GitHub references used for design research

This project is an original educational implementation, not a direct copy of another repository.

Design ideas were researched from:

1. Garima Upadhyay — Host-Based-Intrusion-Detection-System
   https://github.com/garimaupadhyayy/Host-Based-Intrusion-Detection-System
   Used as architectural reference for modular host monitoring, file integrity, process monitoring, log monitoring and dashboard concepts.

2. NazimManaf — linux-hids
   https://github.com/NazimManaf/linux-hids
   Used as reference for Linux authentication monitoring, detector separation and structured alerts.

3. HusnainZargar — IntegrityEye
   https://github.com/HusnainZargar/IntegrityEye
   Used as reference for Linux file-integrity concepts, SHA-256 baselines, severity classification and SQLite/dashboard ideas.

4. SoorajKM1 — Host-Based-Intrusion-Detection-System-HIDS-
   https://github.com/SoorajKM1/Host-Based-Intrusion-Detection-System-HIDS-
   Used as reference for combining file integrity, authentication log monitoring, alerting and threaded modules.

The implementation in this archive was written specifically for the CyberShield OS course-project scope and keeps the initial version intentionally small.

## Course-project mapping

| CyberShield requirement | Implementation |
|---|---|
| Process management | `modules/process_monitor.py` |
| CPU/RAM/disk monitoring | `modules/resource_monitor.py` |
| File system/integrity | `modules/file_monitor.py` |
| User/authentication monitoring | `modules/login_monitor.py` |
| Security rules | monitor thresholds |
| Alerts | `security/alert_manager.py` |
| System event logging | `security/event_logger.py` |
| Persistence | SQLite |
| Dashboard | `dashboard/dashboard.py` |
| Integration | `main.py` |
| Testing | `tests/` |

## Disclaimer

This is an educational host-monitoring project. It is not a complete operating system, commercial antivirus, full IDS, firewall, or production security product.
