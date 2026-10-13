from flask import Flask, jsonify, render_template_string


HTML = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>CyberShield OS Dashboard</title>
<style>
body { font-family: Arial, sans-serif; background:#10141a; color:#eef2f7; margin:0; }
header { padding:24px 32px; background:#171d25; border-bottom:1px solid #303945; }
h1 { margin:0 0 6px; }
.grid { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; padding:24px 32px; }
.card { background:#171d25; border:1px solid #303945; border-radius:12px; padding:20px; }
.value { font-size:30px; font-weight:bold; margin-top:8px; }
.section { padding:0 32px 24px; }
table { width:100%; border-collapse:collapse; background:#171d25; }
th,td { padding:10px; border-bottom:1px solid #303945; text-align:left; }
.badge { padding:4px 8px; border-radius:6px; font-weight:bold; }
.HIGH { background:#7f1d1d; }
.MEDIUM { background:#854d0e; }
.LOW { background:#14532d; }
.CRITICAL { background:#991b1b; }
.small { color:#aab4c0; }
</style>
</head>
<body>
<header>
<h1>CyberShield OS</h1>
<div class="small">Linux Security Monitoring Dashboard • auto-refresh: 5 seconds</div>
</header>

<div class="grid">
<div class="card">CPU<div class="value">{{ resource.cpu }}%</div></div>
<div class="card">RAM<div class="value">{{ resource.memory }}%</div></div>
<div class="card">Disk<div class="value">{{ resource.disk }}%</div></div>
<div class="card">Processes<div class="value">{{ resource.processes }}</div></div>
</div>

<div class="section">
<h2>Recent Security Alerts</h2>
<table>
<tr><th>Time</th><th>Source</th><th>Severity</th><th>Message</th></tr>
{% for alert in alerts %}
<tr>
<td>{{ alert.timestamp }}</td>
<td>{{ alert.source }}</td>
<td><span class="badge {{ alert.severity }}">{{ alert.severity }}</span></td>
<td>{{ alert.message }}</td>
</tr>
{% else %}
<tr><td colspan="4">No alerts yet.</td></tr>
{% endfor %}
</table>
</div>

<div class="section">
<h2>Top Processes</h2>
<table>
<tr><th>PID</th><th>Name</th><th>Owner</th><th>CPU</th><th>RAM</th><th>Status</th></tr>
{% for p in processes[:15] %}
<tr><td>{{p.pid}}</td><td>{{p.name}}</td><td>{{p.owner}}</td><td>{{p.cpu}}%</td><td>{{p.memory}}%</td><td>{{p.status}}</td></tr>
{% endfor %}
</table>
</div>
</body>
</html>
"""


def create_app(logger, alerts, process_monitor, resource_monitor):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(
            HTML,
            resource=resource_monitor.latest_snapshot(),
            processes=process_monitor.latest_snapshot(),
            alerts=logger.recent_events(50)
        )

    @app.route("/api/resources")
    def resources():
        return jsonify(resource_monitor.latest_snapshot())

    @app.route("/api/processes")
    def processes():
        return jsonify(process_monitor.latest_snapshot())

    @app.route("/api/events")
    def events():
        return jsonify(logger.recent_events(100))

    @app.route("/api/alerts")
    def alert_list():
        return jsonify(alerts.recent_alerts(100))

    return app
