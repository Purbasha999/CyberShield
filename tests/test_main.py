"""Command-line entry point."""

import json

import main


def write_config(tmp_path, config):
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps(config))
    return str(path)


def test_once_prints_report(tmp_path, config, capsys):
    assert main.main(["--once", "--config", write_config(tmp_path, config)]) == 0
    out = capsys.readouterr().out
    assert "CYBERSHIELD OS" in out
    assert "SYSTEM STATUS:" in out


def test_rebaseline_command(tmp_path, config, capsys):
    assert main.main(["--rebaseline", "--config", write_config(tmp_path, config)]) == 0
    assert "2 files recorded" in capsys.readouterr().out


def test_bad_config_returns_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{oops")
    assert main.main(["--once", "--config", str(bad)]) == 2
    assert "Config error" in capsys.readouterr().out
