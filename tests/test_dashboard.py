"""Web API, static files, request safety, and the terminal renderer."""

import json
import urllib.error
import urllib.request

import pytest

from dashboard.dashboard import serve_in_background
from dashboard.terminal import render
from security.engine import SecurityEngine
from tests.conftest import auth_line


@pytest.fixture
def running(config):
    engine = SecurityEngine(config)
    engine.run_once()
    server, _ = serve_in_background(engine, "127.0.0.1", 0)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    yield engine, base
    server.shutdown()
    server.server_close()
    engine.stop()


def get(url, headers=None, method="GET", data=None):
    req = urllib.request.Request(url, headers=headers or {}, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read()


def test_index_page_served(running):
    _, base = running
    status, headers, body = get(base + "/")
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert b"CyberShield OS" in body
    assert headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in headers["Content-Security-Policy"]


@pytest.mark.parametrize("asset, ctype", [("app.js", "javascript"), ("style.css", "text/css")])
def test_static_assets_served(running, asset, ctype):
    _, base = running
    status, headers, body = get(f"{base}/static/{asset}")
    assert status == 200 and ctype in headers["Content-Type"] and body


def test_state_api(running):
    _, base = running
    status, _, body = get(base + "/api/state")
    state = json.loads(body)
    assert status == 200
    assert state["overall"] == "SECURE"
    assert set(state["modules"]) == {"process", "file", "login", "resource"}
    res = state["modules"]["resource"]["snapshot"]
    assert 0 <= res["cpu_percent"] <= 100


def test_alerts_api_filters(running, auth_log):
    engine, base = running
    with open(auth_log, "a") as fh:
        fh.writelines(auth_line("sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2") for _ in range(4))
    engine.run_once()
    status, _, body = get(base + "/api/alerts?severity=HIGH")
    alerts = json.loads(body)
    assert status == 200
    assert [a["title"] for a in alerts] == ["Multiple failed login attempts"]
    status, _, body = get(base + "/api/alerts?severity=INFO&module=login&limit=2")
    assert status == 200 and len(json.loads(body)) == 2


@pytest.mark.parametrize("query", ["severity=EXTREME", "limit=abc"])
def test_alerts_api_rejects_bad_input(running, query):
    _, base = running
    assert get(f"{base}/api/alerts?{query}")[0] == 400


@pytest.mark.parametrize("path", ["/static/../dashboard.py", "/static/%2e%2e/dashboard.py", "/static/../../main.py", "/nope"])
def test_path_traversal_and_unknown_paths_blocked(running, path):
    _, base = running
    status, _, body = get(base + path)
    assert status == 404
    assert b"import" not in body


def test_rebaseline_requires_custom_header(running):
    _, base = running
    assert get(base + "/api/files/rebaseline", method="POST")[0] == 403
    status, _, body = get(base + "/api/files/rebaseline", headers={"X-CyberShield": "1"}, method="POST")
    assert status == 200 and json.loads(body) == {"ok": True}


def test_approval_flow_through_api(running, watch_dir):
    engine, base = running
    target = watch_dir / "a.txt"
    target.unlink()
    engine.run_once()

    state = json.loads(get(base + "/api/state")[2])
    assert state["approvals"]["enabled"] is True
    pending = json.loads(get(base + "/api/approvals")[2])["pending"]
    assert len(pending) == 1 and pending[0]["summary"] == str(target)
    url = f"{base}/api/approvals/{pending[0]['id']}"

    def post(body, headers={"X-CyberShield": "1", "Content-Type": "application/json"}, target_url=url):
        return get(target_url, headers=headers, method="POST", data=json.dumps(body).encode())

    assert post({"decision": "rewind"}, headers={})[0] == 403, "custom header required"
    assert post({"decision": "maybe"})[0] == 400
    assert post({"decision": "rewind"}, target_url=f"{base}/api/approvals/9999")[0] == 404
    status, _, body = post({"decision": "rewind"})
    assert status == 200 and json.loads(body)["status"] == "rewound"
    assert target.read_text() == "alpha\n"
    assert json.loads(get(base + "/api/approvals")[2])["pending"] == []


def test_terminal_render_matches_spec_layout(config, watch_dir):
    engine = SecurityEngine(config)
    try:
        engine.run_once()
        (watch_dir / "a.txt").write_text("changed")
        engine.run_once()
        text = render(engine.get_state(), color=False)
    finally:
        engine.stop()
    for heading in ["CYBERSHIELD OS", "SECURITY MONITORING SYSTEM", "SYSTEM STATUS", "SECURITY STATUS", "RECENT ALERTS"]:
        assert heading in text
    assert "Running Processes" in text
    assert "File Integrity     : WARNING" in text
    assert "[MED]" in text and "File modification detected" in text
    assert "SYSTEM STATUS: SECURITY WARNING" in text
    assert "\033[" not in text
