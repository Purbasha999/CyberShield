"""Terminal dashboard, laid out like the report's example output."""

import os
import sys
import time
from datetime import datetime

WIDTH = 60
COLORS = {
    "HIGH": "\033[91m", "CRITICAL": "\033[91m", "ERROR": "\033[91m", "NO ACCESS": "\033[91m",
    "MEDIUM": "\033[93m", "WARNING": "\033[93m", "MISSING": "\033[93m",
    "LOW": "\033[96m", "NOTICE": "\033[96m",
    "SAFE": "\033[92m", "SECURE": "\033[92m",
}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
SHORT = {"HIGH": "HIGH", "MEDIUM": "MED", "LOW": "LOW"}
MODULE_LABELS = [("file", "File Integrity"), ("login", "Login Monitor"), ("process", "Process Monitor"), ("resource", "Resource Monitor")]


def _c(text, key, color):
    return f"{COLORS.get(key, '')}{text}{RESET}" if color else text


def _bar(percent, width=20):
    filled = int(round(max(0.0, min(100.0, percent)) / 100 * width))
    return "█" * filled + "░" * (width - filled)


def render(state, color=True):
    lines = []
    rule, thin = "=" * WIDTH, "-" * WIDTH
    lines += [rule, "CYBERSHIELD OS".center(WIDTH), "SECURITY MONITORING SYSTEM".center(WIDTH), rule, ""]

    res = (state["modules"].get("resource") or {}).get("snapshot")
    lines += ["SYSTEM STATUS", thin]
    if res:
        lines.append(f"CPU Usage          : {_bar(res['cpu_percent'])} {res['cpu_percent']:5.1f}%")
        lines.append(f"Memory Usage       : {_bar(res['memory']['percent'])} {res['memory']['percent']:5.1f}%")
        lines.append(f"Disk Usage         : {_bar(res['disk_percent'])} {res['disk_percent']:5.1f}%")
        lines.append(f"Running Processes  : {res['process_count']}")
    else:
        lines.append("Resource monitor not available")
    lines.append("")

    lines += ["SECURITY STATUS", thin]
    for name, label in MODULE_LABELS:
        module = state["modules"].get(name)
        status = module["status"] if module else "DISABLED"
        lines.append(f"{label:<18} : {_c(status, status, color)}")
    lines.append("")

    lines += ["RECENT ALERTS", thin]
    alerts = state["alerts"][:8]
    if not alerts:
        lines.append(_c("No alerts", "SAFE", color))
    for alert in alerts:
        when = datetime.fromtimestamp(alert["timestamp"]).strftime("%H:%M:%S")
        tag = _c(f"[{SHORT.get(alert['severity'], alert['severity'])}]", alert["severity"], color)
        lines.append(f"{when} {tag:<6} {alert['title']} ({alert['module']})")
    lines.append("")

    pending = (state.get("approvals") or {}).get("pending") or []
    if pending:
        lines += ["CONFIRMATION NEEDED (answer in the popup or web dashboard)", thin]
        for req in pending:
            lines.append(_c(f"! {req['title']}: {req['summary']}  ({int(req['seconds_left'])}s left)", "HIGH", color))
        lines.append("")

    overall = state["overall"]
    label = "SECURITY WARNING" if overall in ("WARNING", "CRITICAL") else overall
    lines += [rule, f"SYSTEM STATUS: {_c(BOLD + label, overall, True) if color else label}", rule]
    return "\n".join(lines)


def run(engine, refresh_seconds=2):
    color = sys.stdout.isatty()
    try:
        while True:
            frame = render(engine.get_state(), color)
            if color:
                sys.stdout.write("\033[2J\033[H")
            sys.stdout.write(frame + f"\n{DIM if color else ''}Ctrl+C to quit{RESET if color else ''}\n")
            sys.stdout.flush()
            time.sleep(refresh_seconds)
    except KeyboardInterrupt:
        pass
