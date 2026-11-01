#!/usr/bin/env python3
"""
dashboard.py — Flask SIEM Dashboard (Project #61)
Serves a static HTML dashboard with Chart.js, data injected via JSON.
"""
import os
import json
from flask import Flask, Response, jsonify

app = Flask(__name__)
REPORTS_DIR = "reports"

def load_report():
    json_path = os.path.join(REPORTS_DIR, "log_analysis.json")
    if not os.path.exists(json_path):
        return None
    with open(json_path) as f:
        return json.load(f)

def build_dashboard_html(report):
    """Build the dashboard HTML with data embedded (no Jinja templating)."""
    parse = report["phases"]["parse"]
    detect = report["phases"]["detect"]
    alerts = report["phases"]["alerts"]

    # Aggregate type counts
    type_counts = {}
    for ip, attacks in detect.items():
        for atype, count in attacks.items():
            if count > 0:
                type_counts[atype] = type_counts.get(atype, 0) + count

    # Aggregate IP counts
    ip_counts = {}
    for ip, attacks in detect.items():
        total = sum(attacks.values())
        if total > 0:
            ip_counts[ip] = total

    # Aggregate by hour
    hour_counts = {}
    for alert in alerts:
        hour_counts["10"] = hour_counts.get("10", 0) + alert["count"]

    # Build alert rows
    alert_rows = ""
    for a in alerts:
        color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800",
                 "MEDIUM": "#ffcc00"}.get(a["severity"], "#888")
        alert_rows += f"""<tr>
            <td style="color:{color};font-weight:bold">{a['severity']}</td>
            <td>{a['ip']}</td>
            <td>{a['attack_type']}</td>
            <td>{a['count']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SIEM Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: monospace; background: #0a0a0a; color: #e0e0e0;
    padding: 20px;
}}
header {{
    text-align: center; padding: 30px;
    background: linear-gradient(135deg, #1a1a2e, #16213e);
    border-radius: 12px; margin-bottom: 20px;
}}
h1 {{ color: #ff4444; font-size: 2.5em; }}
.subtitle {{ color: #888; margin-top: 10px; }}
.stats {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 15px; margin: 20px 0;
}}
.stat {{
    background: #1a1a1a; padding: 20px; border-radius: 8px;
    text-align: center; border: 1px solid #333;
}}
.stat-num {{ font-size: 2em; color: #ff4444; font-weight: bold; }}
.stat-label {{ color: #888; font-size: 0.9em; margin-top: 5px; }}
.charts {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 20px; margin: 20px 0;
}}
.chart-container {{
    background: #1a1a1a; padding: 20px; border-radius: 8px;
    border: 1px solid #333;
}}
.chart-container h3 {{ color: #55ff55; margin-bottom: 15px; }}
.alerts-table {{
    background: #1a1a1a; border-radius: 8px; padding: 20px;
    margin-top: 20px; border: 1px solid #333;
}}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
th {{ color: #ff4444; }}
</style>
</head>
<body>
<header>
    <h1>SIEM Dashboard</h1>
    <p class="subtitle">Log Analysis & Attack Detection</p>
    <p class="subtitle">Log: {report['log_file']}</p>
</header>

<div class="stats">
    <div class="stat"><div class="stat-num">{parse['total_lines']}</div><div class="stat-label">Lines Parsed</div></div>
    <div class="stat"><div class="stat-num">{parse['unique_ips']}</div><div class="stat-label">Unique IPs</div></div>
    <div class="stat"><div class="stat-num">{len(ip_counts)}</div><div class="stat-label">Attacker IPs</div></div>
    <div class="stat"><div class="stat-num">{len(alerts)}</div><div class="stat-label">Alerts</div></div>
</div>

<div class="charts">
    <div class="chart-container">
        <h3>Attacks by Type</h3>
        <canvas id="pieChart"></canvas>
    </div>
    <div class="chart-container">
        <h3>Top Attackers</h3>
        <canvas id="barChart"></canvas>
    </div>
</div>

<div class="chart-container">
    <h3>Attack Timeline</h3>
    <canvas id="lineChart"></canvas>
</div>

<div class="alerts-table">
    <h3 style="color:#55ff55; margin-bottom:15px">Recent Alerts</h3>
    <table>
        <tr><th>Severity</th><th>IP</th><th>Attack Type</th><th>Count</th></tr>
        {alert_rows}
    </table>
</div>

<script>
const typeCounts = {json.dumps(type_counts)};
const ipCounts = {json.dumps(ip_counts)};
const hourCounts = {json.dumps(hour_counts)};

new Chart(document.getElementById('pieChart'), {{
    type: 'pie',
    data: {{
        labels: Object.keys(typeCounts),
        datasets: [{{
            data: Object.values(typeCounts),
            backgroundColor: ['#ff4444', '#ff8800', '#ffcc00', '#55ff55']
        }}]
    }},
    options: {{ plugins: {{ legend: {{ labels: {{ color: '#e0e0e0' }} }} }} }}
}});

new Chart(document.getElementById('barChart'), {{
    type: 'bar',
    data: {{
        labels: Object.keys(ipCounts),
        datasets: [{{
            label: 'Attacks',
            data: Object.values(ipCounts),
            backgroundColor: '#ff4444'
        }}]
    }},
    options: {{
        plugins: {{ legend: {{ labels: {{ color: '#e0e0e0' }} }} }},
        scales: {{
            x: {{ ticks: {{ color: '#e0e0e0' }} }},
            y: {{ ticks: {{ color: '#e0e0e0' }} }}
        }}
    }}
}});

new Chart(document.getElementById('lineChart'), {{
    type: 'line',
    data: {{
        labels: Object.keys(hourCounts).sort(),
        datasets: [{{
            label: 'Attacks per hour',
            data: Object.values(hourCounts),
            borderColor: '#ff4444',
            backgroundColor: 'rgba(255,68,68,0.2)',
            fill: true
        }}]
    }},
    options: {{
        plugins: {{ legend: {{ labels: {{ color: '#e0e0e0' }} }} }},
        scales: {{
            x: {{ ticks: {{ color: '#e0e0e0' }} }},
            y: {{ ticks: {{ color: '#e0e0e0' }} }}
        }}
    }}
}});
</script>
</body>
</html>"""
    return html

@app.route("/")
def index():
    report = load_report()
    if not report:
        return "No report found. Run siem_analyzer.py first.", 404
    html = build_dashboard_html(report)
    return Response(html, mimetype="text/html")

@app.route("/api/alerts")
def api_alerts():
    report = load_report()
    if not report:
        return jsonify({"error": "No report found"}), 404
    return jsonify(report["phases"]["alerts"])

if __name__ == "__main__":
    print("[*] SIEM Dashboard starting on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
