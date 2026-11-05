#!/usr/bin/env python3
"""
phishing_simulator.py — Safe Phishing Simulation (Project #65)
6-phase simulation. NO real emails sent. NO real credentials harvested.
All data is local and simulated for security awareness training.
"""
import os, sys, json, time, threading, logging
from datetime import datetime
from flask import Flask, request, render_template_string, redirect

REPORTS_DIR = "reports"
EMAILS_DIR = "emails"
HARVEST_DIR = "harvest"
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(EMAILS_DIR, exist_ok=True)
os.makedirs(HARVEST_DIR, exist_ok=True)

# Configure harvest logging
harvest_log = os.path.join(HARVEST_DIR, "harvest.log")
logging.basicConfig(filename=harvest_log, level=logging.INFO,
                    format="%(asctime)s | %(message)s")

app = Flask(__name__)
SIMULATED_TARGET = "target@example.com"

# ============================================================
# PHASE 1 — OSINT Simulation
# ============================================================
def phase1_osint():
    print("\n[PHASE 1] OSINT (SIMULATED)")
    print(f"    Target: {SIMULATED_TARGET}")

    osint_data = {
        "email": SIMULATED_TARGET,
        "breaches": [
            {"name": "Adobe", "year": 2013, "records": "153M"},
            {"name": "LinkedIn", "year": 2012, "records": "117M"},
        ],
        "social_media": ["LinkedIn", "Twitter"],
        "domain_info": {
            "MX": "mail.example.com",
            "SPF": "v=spf1 include:_spf.example.com ~all",
            "DMARC": "v=DMARC1; p=none",
        },
    }

    print(f"    Social media: {', '.join(osint_data['social_media'])}")
    print(f"    Breaches: {len(osint_data['breaches'])}")
    for b in osint_data["breaches"]:
        print(f"      - {b['name']} ({b['year']}) — {b['records']} records")
    print(f"    [+] {len(osint_data['breaches'])} breaches found (SIMULATED)")

    return osint_data

# ============================================================
# PHASE 2 — Phishing Page (Flask server)
# ============================================================
LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Secure Login</title>
<style>
body { font-family: Arial; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; }
h2 { text-align: center; color: #333; }
input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
.warning { color: #e74c3c; font-size: 12px; text-align: center; margin-top: 15px; }
</style></head>
<body>
<div class="login-box">
<h2>Secure Login</h2>
<form method="POST" action="/harvest">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Login</button>
</form>
<p class="warning">TRAINING SIMULATION — Do not enter real credentials.</p>
</div>
</body>
</html>
"""

@app.route("/login")
def login_page():
    return render_template_string(LOGIN_PAGE)

@app.route("/harvest", methods=["POST"])
def harvest():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ip = request.remote_addr
    logging.info(f"CREDENTIAL_SUBMITTED user={username} pass_length={len(password)} ip={ip}")
    print(f"    [+] Captured submission: {username} (password length: {len(password)})")
    return "Login failed. <a href='/login'>Try again</a>"

def phase2_phishing_page():
    print("\n[PHASE 2] PHISHING PAGE (LOCAL SERVER)")
    print(f"    Starting Flask on http://127.0.0.1:5002/login")
    print(f"    [!] Server will run in background thread for 60 seconds")
    print(f"    [!] Harvest endpoint: POST /harvest → {harvest_log}")
    return True

# ============================================================
# PHASE 3 — Phishing Email Templates (NOT sent)
# ============================================================
EMAIL_TEMPLATES = {
    "password_reset": {
        "subject": "Urgent: Password Reset Required",
        "body": """Your account has been compromised.

Click here to reset your password: http://127.0.0.1:5002/login

This link expires in 24 hours.

- IT Security Team
""",
    },
    "invoice": {
        "subject": "Invoice #12345 - Payment Due",
        "body": """Please review the attached invoice.

Click here: http://127.0.0.1:5002/login

Payment due within 7 days.

- Accounts Payable
""",
    },
    "account_suspended": {
        "subject": "Account Suspended - Action Required",
        "body": """Your account has been suspended due to suspicious activity.

Verify here: http://127.0.0.1:5002/login

- Security Team
""",
    },
}

def phase3_email():
    print("\n[PHASE 3] PHISHING EMAIL TEMPLATES (GENERATED, NOT SENT)")
    paths = []
    for name, tmpl in EMAIL_TEMPLATES.items():
        path = os.path.join(EMAILS_DIR, f"{name}.eml")
        with open(path, "w") as f:
            f.write(f"To: {SIMULATED_TARGET}\n")
            f.write(f"Subject: {tmpl['subject']}\n")
            f.write(f"Date: {datetime.now().isoformat()}\n")
            f.write(f"MIME-Version: 1.0\n")
            f.write(f"Content-Type: text/plain; charset=UTF-8\n\n")
            f.write(tmpl["body"])
        paths.append(path)
        print(f"    [+] Generated: {path}")
    print(f"\n    [!] These are TEXT FILES ONLY — not sent via SMTP.")
    print(f"    [!] Review manually to understand common phishing patterns.")
    return paths

# ============================================================
# PHASE 4 — Credential Harvest Simulation
# ============================================================
def phase4_harvest():
    print("\n[PHASE 4] CREDENTIAL HARVEST SIMULATION")
    # Simulate a victim submitting credentials
    simulated_creds = {
        "username": SIMULATED_TARGET,
        "password_length": 12,
        "source_ip": "192.168.1.100",
        "timestamp": datetime.now().isoformat(),
    }
    logging.info(f"SIMULATED_VICTIM user={simulated_creds['username']} ip={simulated_creds['source_ip']}")
    print(f"    [+] Simulated victim: {simulated_creds['username']}")
    print(f"    [+] Logged to: {harvest_log}")
    print(f"    [!] No real credentials were captured.")
    return simulated_creds

# ============================================================
# PHASE 5 — Awareness Report
# ============================================================
def phase5_awareness(osint, harvest):
    print("\n[PHASE 5] AWARENESS REPORT")
    report = {
        "target": SIMULATED_TARGET,
        "timestamp": datetime.now().isoformat(),
        "breaches_exposed": osint["breaches"],
        "simulated_submissions": 1,
        "email_templates_generated": 3,
        "findings": [
            f"Email exposed in {len(osint['breaches'])} breaches",
            "Simulated credential submission captured",
            "Phishing email templates created",
            "Link not flagged by simulated filters",
        ],
        "recommendations": [
            "Security awareness training for all staff",
            "Enable MFA on all accounts",
            "Implement SPF, DKIM, DMARC",
            "Use password manager",
            "Deploy phishing simulation program (GoPhish, KnowBe4)",
            "Email attachment sandboxing",
            "Report-phishing button in email client",
        ],
    }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"{REPORTS_DIR}/phishing_report_{ts}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"    [+] JSON: {json_path}")

    html_path = f"{REPORTS_DIR}/awareness_report_{ts}.html"
    with open(html_path, "w") as f:
        f.write(build_awareness_html(report))
    print(f"    [+] HTML: {html_path}")
    return report, json_path, html_path

def build_awareness_html(report):
    findings_li = "".join(f"<li>{f}</li>" for f in report["findings"])
    recs_li = "".join(f"<li>{r}</li>" for r in report["recommendations"])
    breaches_li = "".join(f"<li>{b['name']} ({b['year']}) — {b['records']}</li>" for b in report["breaches_exposed"])
    return f"""<!DOCTYPE html>
<html><head><title>Phishing Awareness Report</title>
<style>
body {{ font-family: Arial, max-width: 900px; margin: 40px auto; padding: 20px; background: #f9f9f9; }}
h1 {{ color: #c0392b; }}
h2 {{ color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 5px; }}
.note {{ background: #fff3cd; padding: 15px; border-left: 4px solid #f39c12; margin: 20px 0; }}
ul {{ line-height: 1.8; }}
</style></head><body>
<h1>Phishing Simulation — Awareness Report</h1>
<div class="note">
<b>⚠️ TRAINING SIMULATION:</b> This report was generated in a controlled, local
environment. No real emails were sent, no real credentials were captured, and no
real organizations were targeted.
</div>
<p><b>Target (simulated):</b> {report['target']}</p>
<p><b>Timestamp:</b> {report['timestamp']}</p>
<h2>Breach Exposure (Simulated)</h2>
<ul>{breaches_li}</ul>
<h2>Findings</h2>
<ul>{findings_li}</ul>
<h2>Recommendations</h2>
<ul>{recs_li}</ul>
</body></html>"""

# ============================================================
# PHASE 6 — Ethical Guidelines
# ============================================================
def phase6_ethics():
    print("\n[PHASE 6] ETHICAL GUIDELINES")
    ethics = """# Ethical Guidelines — Phishing Simulation

## Legal Framework

This tool is for **security awareness training only** and must be used within
the following legal constraints:

- **CFAA (US)**: Unauthorized access to computer systems is a crime.
- **GDPR (EU)**: Processing personal data requires explicit consent.
- **Computer Misuse Act (UK)**: Similar to CFAA.
- **Digital Millennium Copyright Act (US)**: Don't clone real websites.

## Rules

1. **Only test on your own accounts** — never target someone else.
2. **Get written permission** before testing an organization (use a signed
   "Rules of Engagement" document).
3. **Never clone real login pages** — use generic training pages (like this
   project's `login.html`).
4. **Never send real phishing emails** — use local templates and review them
   manually, or use a professional platform (GoPhish, KnowBe4) that handles
   consent and disclosure.
5. **Never harvest real credentials** — this project logs only simulated data.
6. **Never use found credentials** — even from a legitimate simulation, do not
   log into accounts.
7. **Report findings responsibly** — disclose vulnerabilities through proper
   channels (CVE, bug bounty, internal security team).
8. **Provide training** — any simulation must include follow-up awareness
   training for victims.
9. **Destroy captured data** — after the simulation, securely delete all
   harvested data and logs.
10. **Comply with all laws** — local, state, federal, and international.

## When in Doubt

- Ask your legal team.
- Ask your security team.
- **Don't do it.**

## Reporting Vulnerabilities

If you find a real vulnerability, report it via:
- The organization's security.txt (`/.well-known/security.txt`)
- Bug bounty platform (HackerOne, Bugcrowd)
- CISA (US), NCSC (UK), ENISA (EU)

## References

- GoPhish: https://getgophish.com/
- KnowBe4: https://www.knowbe4.com/
- OWASP Phishing: https://owasp.org/www-community/attacks/Phishing
"""
    path = "ethics.md"
    with open(path, "w") as f:
        f.write(ethics)
    print(f"    [+] Ethics guidelines: {path}")
    return path

# ============================================================
# MAIN
# ============================================================
def run_server_background():
    """Run Flask in a daemon thread for 60 seconds."""
    def _server():
        app.run(host="127.0.0.1", port=5002, debug=False, use_reloader=False)
    t = threading.Thread(target=_server, daemon=True)
    t.start()
    time.sleep(1)  # Give it time to start

def main():
    print("=" * 64)
    print(" Phishing Simulation Toolkit - Project #65")
    print("=" * 64)
    print(f"[+] Target (simulated): {SIMULATED_TARGET}")
    print(f"[+] This is a SAFE, LOCAL simulation — no real emails sent.")

    osint = phase1_osint()
    phase2_phishing_page()
    run_server_background()
    phase3_email()
    harvest = phase4_harvest()
    report, json_path, html_path = phase5_awareness(osint, harvest)
    ethics_path = phase6_ethics()

    print("\n" + "=" * 64)
    print("[✓] Simulation complete")
    print(f"    JSON report:    {json_path}")
    print(f"    HTML report:    {html_path}")
    print(f"    Ethics:         {ethics_path}")
    print(f"    Emails:         {EMAILS_DIR}/ (3 .eml files — NOT sent)")
    print(f"    Harvest log:    {harvest_log}")
    print(f"    Phishing page:  http://127.0.0.1:5002/login (background, 60s)")
    print("=" * 64)

if __name__ == "__main__":
    main()
