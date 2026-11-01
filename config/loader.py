"""Configuration loading: built-in defaults deep-merged with config.json."""

import copy
import json
import os
from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config.json"

DEFAULTS = {
    "data_dir": "~/.cybershield",
    "dashboard": {"host": "127.0.0.1", "port": 8080, "refresh_seconds": 2},
    "alerts": {"cooldown_seconds": 60, "status_window_seconds": 300},
    "approvals": {
        "enabled": True,
        "file_changes": True,
        "suspicious_processes": True,
        "timeout_seconds": 120,
        "on_timeout": "rewind",
        "popup": "auto",
    },
    "process_monitor": {
        "enabled": True,
        "interval_seconds": 3,
        "cpu_threshold": 80,
        "memory_threshold": 25,
        "sustain_polls": 2,
        "top_n": 15,
        "suspicious_names": [
            "nc", "ncat", "netcat", "socat", "xmrig", "minerd", "cpuminer",
            "hydra", "john", "hashcat", "mimikatz", "kworkerds",
        ],
        "suspicious_paths": ["/tmp/", "/dev/shm/", "/var/tmp/"],
        "block_heavy_processes": True,
        "block_exempt_names": [
            "systemd", "init", "sshd", "bash", "zsh", "sh", "fish", "tmux", "screen",
            "node", "code", "code-server", "wslhost", "Xwayland", "apt", "apt-get", "dpkg",
        ],
    },
    "file_monitor": {
        "enabled": True,
        "interval_seconds": 10,
        "watch_paths": [],
        "exclude": [],
        "recursive": True,
        "fast_mode": False,
        "max_file_size_mb": 50,
        "vault_max_mb": 20,
        "realtime": True,
    },
    "login_monitor": {
        "enabled": True,
        "interval_seconds": 2,
        "log_path": "/var/log/auth.log",
        "max_failed_attempts": 3,
        "window_seconds": 300,
        "read_history_on_start": True,
    },
    "resource_monitor": {
        "enabled": True,
        "interval_seconds": 2,
        "cpu_threshold": 90,
        "memory_threshold": 90,
        "disk_threshold": 90,
        "sustain_polls": 3,
        "disk_paths": ["/"],
        "history_size": 150,
    },
}


class ConfigError(Exception):
    pass


def _deep_merge(base, override):
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _expand(path):
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))


def load_config(path=None, overrides=None):
    """Load config.json (or `path`), fill in defaults and expand ~ in paths."""
    path = Path(path) if path else DEFAULT_CONFIG_PATH
    user_cfg = {}
    if path.exists():
        try:
            user_cfg = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Invalid JSON in {path}: {exc}") from exc
        if not isinstance(user_cfg, dict):
            raise ConfigError(f"{path} must contain a JSON object")

    cfg = _deep_merge(DEFAULTS, user_cfg)
    if overrides:
        cfg = _deep_merge(cfg, overrides)

    cfg["data_dir"] = _expand(cfg["data_dir"])
    fm = cfg["file_monitor"]
    fm["watch_paths"] = [_expand(p) for p in fm["watch_paths"]]
    # Never watch our own database/logs, otherwise every alert would trigger another one.
    fm["exclude"] = list(fm["exclude"]) + [cfg["data_dir"]]
    cfg["login_monitor"]["log_path"] = _expand(cfg["login_monitor"]["log_path"])
    approvals = cfg["approvals"]
    if approvals["on_timeout"] not in ("rewind", "allow"):
        raise ConfigError("approvals.on_timeout must be 'rewind' or 'allow'")
    if approvals["popup"] not in ("auto", "windows", "zenity", "off"):
        raise ConfigError("approvals.popup must be 'auto', 'windows', 'zenity' or 'off'")
    return cfg
