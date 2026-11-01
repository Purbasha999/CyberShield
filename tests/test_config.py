import json
import os

import pytest

from config.loader import DEFAULT_CONFIG_PATH, ConfigError, load_config

MODULE_SECTIONS = ["process_monitor", "file_monitor", "login_monitor", "resource_monitor"]


def test_shipped_config_is_valid():
    cfg = load_config(DEFAULT_CONFIG_PATH)
    for section in MODULE_SECTIONS:
        assert cfg[section]["enabled"] is True
        assert cfg[section]["interval_seconds"] > 0
    assert cfg["dashboard"]["host"] == "127.0.0.1", "dashboard must only listen on localhost by default"


def test_defaults_used_when_file_missing(tmp_path):
    cfg = load_config(tmp_path / "nope.json")
    assert cfg["login_monitor"]["log_path"] == "/var/log/auth.log" or cfg["login_monitor"]["log_path"].endswith("auth.log")
    assert cfg["alerts"]["cooldown_seconds"] == 60


def test_partial_file_is_merged_with_defaults(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"process_monitor": {"cpu_threshold": 55}}))
    cfg = load_config(path)
    assert cfg["process_monitor"]["cpu_threshold"] == 55
    assert cfg["process_monitor"]["sustain_polls"] == 2  # untouched default survives


def test_paths_are_expanded_and_data_dir_excluded(tmp_path):
    cfg = load_config(
        tmp_path / "nope.json",
        overrides={"data_dir": "~/cs-data", "file_monitor": {"watch_paths": ["~/watched"]}},
    )
    home = os.path.expanduser("~")
    assert cfg["data_dir"] == os.path.join(home, "cs-data")
    assert cfg["file_monitor"]["watch_paths"] == [os.path.join(home, "watched")]
    assert cfg["data_dir"] in cfg["file_monitor"]["exclude"]


@pytest.mark.parametrize("content", ["{not json", "[1, 2, 3]"])
def test_invalid_config_raises(tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_text(content)
    with pytest.raises(ConfigError):
        load_config(path)
