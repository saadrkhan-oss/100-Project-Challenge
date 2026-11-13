#!/usr/bin/env python3
"""
assessment_toolkit.py — Complete Security Assessment & Portfolio (Project #70)
10 phases: scope, recon, scan, exploit, post-exploit, standards, remediation,
business impact, PDF report, HTML portfolio.
"""
import os, sys, json
from datetime import datetime
from collections import defaultdict

MOCK_DIR = "mock"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

class FinalAssessmentToolkit:
    def __init__(self):
        with open(os.path.join(MOCK_DIR, "assessment.json")) as f:
            self.data = json.load(f)
        self.report = {
            "timestamp": datetime.now().isoformat(),
            "target": self.data["scope"]["target"],
            "phases": {},
        }

    # ------------------------------------------------------------------
    # PHASE 1 — Scope
    # ------------------------------------------------------------------
    def phase1_scope(self):
        print("\n[PHASE 1] SCOPE")
        s = self.data["scope"]
        print(f"    Target:      {s['target']}")
        print(f"    Type:        {s['type']}")
        print(f"    Methodology: {s['methodology']}")
        print(f"    Standards:   {', '.join(s['standards'])}")
        print(f"    Date:        {s['date']}")
        print(f"    Assessor:    {s['assessor']}")
        self.report["phases"]["scope"] = s

    # ------------------------------------------------------------------
    # PHASE 2 — Reconnaissance
    # ------------------------------------------------------------------
    def phase2_recon(self):
        print("\n[PHASE 2] RECONNAISSANCE")
        r = self.data["recon"]
        print(f"    Subdomains:   {len(r['subdomains'])}")
        for sub in r["subdomains"]:
            print(f"      - {sub}.vulnerable-app.local")
        print(f"    Open ports:   {r['open_ports']}")
        print(f"    Technologies: {', '.join(r['technologies'])}")
        print(f"    [+] Recon complete")
        self.report["phases"]["recon"] = r

    # ------------------------------------------------------------------
    # PHASE 3 — Vulnerability Scanning
    # ------------------------------------------------------------------
    def phase3_scan(self):
        print("\n[PHASE 3] VULNERABILITY SCANNING")
        vulns = self.data["vulnerabilities"]
        by_sev = defaultdict(list)
        for v in vulns:
            by_sev[v["severity"]].append(v)
            print(f"    [{v['id']}] {v['name']}")
            print(f"      CVSS {v['cvss']} ({v['severity']}) — {v['owasp']}")
        print(f"\n    [+] {len(vulns)} vulnerabilities found")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if by_sev[sev]:
                print(f"        {sev}: {len(by_sev[sev])}")
        self.report["phases"]["scan"] = {v["id"]: v for v in vulns}

    # ------------------------------------------------------------------
    # PHASE 4 — Exploitation (PoC Evidence)
    # ------------------------------------------------------------------
    def phase4_exploit(self):
        print("\n[PHASE 4] EXPLOITATION (PoC EVIDENCE)")
        for v in self.data["vulnerabilities"]:
            print(f"\n    [{v['id']}] {v['name']}")
            print(f"      PoC: {v['evidence']}")
            print(f"      Impact: {v['impact']}")
        print(f"\n    [+] All PoCs documented")
        self.report["phases"]["exploit"] = {
            v["id"]: {"evidence": v["evidence"], "impact": v["impact"]}
            for v in self.data["vulnerabilities"]
        }

    # ------------------------------------------------------------------
    # PHASE 5 — Post-Exploitation (Documented)
    # ------------------------------------------------------------------
    def phase5_post_exploit(self):
        print("\n[PHASE 5] POST-EXPLOITATION (DOCUMENTED, NOT EXECUTED)")
        post = {
            "privesc": "Local user → root via sudo misconfig (documented)",
            "lateral": "Pivot to 2 hosts via SSH keys (documented)",
            "persistence": "Cron backdoor (documented, not installed)",
        }
        for k, v in post.items():
            print(f"    [{k.upper()}] {v}")
        print(f"    [!] All post-exploitation is documented, not executed")
        self.report["phases"]["post_exploit"] = post

    # ------------------------------------------------------------------
    # PHASE 6 — Standards Mapping
    # ------------------------------------------------------------------
    def phase6_standards(self):
        print("\n[PHASE 6] STANDARDS MAPPING")
        owasp = defaultdict(int)
        for v in self.data["vulnerabilities"]:
            owasp[v["owasp"]] += 1

        print(f"\n    [OWASP TOP 10 2021]")
        for cat, count in owasp.items():
            print(f"      - {cat} ({count})")

        print(f"\n    [NIST 800-115]")
        print(f"      - Phase 1: Planning (✓)")
        print(f"      - Phase 2: Discovery (✓)")
        print(f"      - Phase 3: Attack (✓)")
        print(f"      - Phase 4: Reporting (✓)")

        print(f"\n    [CIS BENCHMARKS]")
        print(f"      - Web Server 5.1, 5.2, 5.3")
        print(f"      - Database 4.1, 4.2")

        self.report["phases"]["standards"] = {
            "owasp": dict(owasp),
            "nist": ["Planning", "Discovery", "Attack", "Reporting"],
            "cis": ["Web Server 5.1-5.3", "Database 4.1-4.2"],
        }

    # ------------------------------------------------------------------
    # PHASE 7 — Remediation Plan
    # ------------------------------------------------------------------
    def phase7_remediation(self):
        print("\n[PHASE 7] REMEDIATION PLAN")
        immediate = [
            "SQL Injection (VULN-001): parameterized queries (PDO/MySQLi)",
            "Weak JWT (VULN-006): rotate secret, 32+ random bytes",
            "Reflected XSS (VULN-002): output encoding + CSP",
        ]
        short = [
            "XXE (VULN-004): disable external entities (defusedxml)",
            "SSRF (VULN-003): URL whitelist + block 169.254.169.254",
            "IDOR (VULN-005): ownership check (user_id == token.sub)",
            "Debug (VULN-007): set debug=False in production",
        ]
        long = [
            "Implement WAF (ModSecurity / Cloudflare)",
            "Security awareness training for all developers",
            "Quarterly penetration testing",
        ]

        print(f"\n    [IMMEDIATE] (24 hours)")
        for i in immediate:
            print(f"      - {i}")
        print(f"\n    [SHORT_TERM] (1-2 weeks)")
        for i in short:
            print(f"      - {i}")
        print(f"\n    [LONG_TERM] (1-3 months)")
        for i in long:
            print(f"      - {i}")

        self.report["phases"]["remediation"] = {
            "immediate": immediate,
            "short_term": short,
            "long_term": long,
        }

    # ------------------------------------------------------------------
    # PHASE 8 — Business Impact
    # ------------------------------------------------------------------
    def phase8_business_impact(self):
        print("\n[PHASE 8] BUSINESS IMPACT")
        impact = {
            "financial": "$500,000 (average data breach cost)",
            "reputation": "High (customer trust loss)",
            "legal": "GDPR fines (up to 4% annual revenue)",
            "operational": "2 weeks downtime",
        }
        for k, v in impact.items():
            print(f"    {k.title()}: {v}")
        self.report["phases"]["business_impact"] = impact

    # ------------------------------------------------------------------
    # PHASE 9 — PDF Report
    # ------------------------------------------------------------------
    def phase9_pdf(self):
        print("\n[PHASE 9] PDF REPORT")
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
            )

            pdf_path = f"{REPORTS_DIR}/security_assessment_report.pdf"
            doc = SimpleDocTemplate(pdf_path, pagesize=letter,
                                     topMargin=0.75*inch, bottomMargin=0.75*inch,
                                     leftMargin=0.75*inch, rightMargin=0.75*inch)
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle("title", parent=styles["Title"],
                                          fontSize=24, textColor=colors.HexColor("#cc0000"))
            h1 = ParagraphStyle("h1", parent=styles["Heading1"],
                                 fontSize=18, textColor=colors.HexColor("#cc0000"))
            h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12)
            body = styles["BodyText"]

            story = []

            # Cover
            story.append(Spacer(1, 2*inch))
            story.append(Paragraph("SECURITY ASSESSMENT REPORT", title_style))
            story.append(Spacer(1, 0.3*inch))
            story.append(Paragraph(f"Target: {self.data['scope']['target']}", body))
            story.append(Paragraph(f"Date: {self.data['scope']['date']}", body))
            story.append(Paragraph(f"Assessor: {self.data['scope']['assessor']}", body))
            story.append(PageBreak())

            # Executive Summary
            story.append(Paragraph("Executive Summary", h1))
            n_crit = sum(1 for v in self.data["vulnerabilities"] if v["severity"] == "CRITICAL")
            n_high = sum(1 for v in self.data["vulnerabilities"] if v["severity"] == "HIGH")
            story.append(Paragraph(
                f"This assessment identified <b>{len(self.data['vulnerabilities'])} vulnerabilities</b> "
                f"in the target application: <b>{n_crit} CRITICAL</b> and <b>{n_high} HIGH</b>. "
                f"Immediate remediation is required for the CRITICAL findings to prevent full system compromise.",
                body))
            story.append(Spacer(1, 0.2*inch))

            # Findings Table
            story.append(Paragraph("Findings Summary", h1))
            table_data = [["ID", "Vulnerability", "CVSS", "Severity", "OWASP"]]
            for v in self.data["vulnerabilities"]:
                table_data.append([v["id"], v["name"], str(v["cvss"]), v["severity"], v["owasp"][:20]])
            t = Table(table_data, colWidths=[0.7*inch, 1.8*inch, 0.5*inch, 0.8*inch, 1.7*inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#cc0000")),
                ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 8),
                ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ]))
            story.append(t)
            story.append(PageBreak())

            # Per-Vulnerability Details
            story.append(Paragraph("Vulnerability Details", h1))
            for v in self.data["vulnerabilities"]:
                story.append(Paragraph(f"{v['id']} — {v['name']}", h2))
                story.append(Paragraph(f"<b>CVSS:</b> {v['cvss']} ({v['severity']})", body))
                story.append(Paragraph(f"<b>OWASP:</b> {v['owasp']}", body))
                story.append(Paragraph(f"<b>CWE:</b> {v['cwe']}", body))
                story.append(Paragraph(f"<b>Evidence:</b> {v['evidence']}", body))
                story.append(Paragraph(f"<b>Impact:</b> {v['impact']}", body))
                story.append(Paragraph(f"<b>Remediation:</b> {v['remediation']}", body))
                story.append(Spacer(1, 0.15*inch))

            story.append(PageBreak())

            # Remediation Plan
            story.append(Paragraph("Remediation Plan", h1))
            rem = self.report["phases"]["remediation"]
            for tier in ["immediate", "short_term", "long_term"]:
                story.append(Paragraph(tier.replace("_", " ").title(), h2))
                for item in rem[tier]:
                    story.append(Paragraph(f"• {item}", body))
                story.append(Spacer(1, 0.1*inch))

            story.append(PageBreak())

            # Business Impact
            story.append(Paragraph("Business Impact", h1))
            for k, v in self.report["phases"]["business_impact"].items():
                story.append(Paragraph(f"<b>{k.title()}:</b> {v}", body))

            doc.build(story)
            print(f"    [+] PDF: {pdf_path}")
            print(f"    [+] Pages: ~{len(story)//15}")
            self.report["phases"]["pdf"] = {"path": pdf_path, "size": os.path.getsize(pdf_path)}
        except Exception as e:
            print(f"    [!] PDF error: {e}")

    # ------------------------------------------------------------------
    # PHASE 10 — HTML Portfolio
    # ------------------------------------------------------------------
    def phase10_portfolio(self):
        print("\n[PHASE 10] HTML PORTFOLIO")
        html_path = f"{REPORTS_DIR}/portfolio.html"

        rows = ""
        for v in self.data["vulnerabilities"]:
            color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800",
                     "MEDIUM": "#ffcc00", "LOW": "#44cc44"}[v["severity"]]
            rows += f"""
            <div class="vuln" style="border-left:6px solid {color}">
                <h3>{v['id']}: {v['name']}</h3>
                <p><b>CVSS:</b> {v['cvss']} <span style="color:{color}">{v['severity']}</span></p>
                <p><b>OWASP:</b> {v['owasp']}</p>
                <p><b>CWE:</b> {v['cwe']}</p>
                <p><b>Evidence:</b> {v['evidence']}</p>
                <p><b>Impact:</b> {v['impact']}</p>
                <p><b>Fix:</b> {v['remediation']}</p>
            </div>"""

        html = f"""<!DOCTYPE html>
<html><head><title>Security Portfolio</title>
<style>
body {{ font-family: monospace; background:#0a0a0a; color:#e0e0e0; padding:20px; }}
h1 {{ color:#ff4444; }}
h2 {{ color:#55ff55; border-bottom:1px solid #333; padding-bottom:10px; }}
.vuln {{ background:#1a1a1a; padding:15px; margin:15px 0; border-radius:6px; }}
.vuln h3 {{ color:#e0e0e0; margin-bottom:10px; }}
.vuln p {{ margin:5px 0; }}
.header {{ text-align:center; padding:40px; background:linear-gradient(135deg,#1a1a2e,#16213e); border-radius:12px; margin-bottom:20px; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:15px; margin:20px 0; }}
.stat {{ background:#1a1a1a; padding:20px; text-align:center; border-radius:8px; }}
.stat-num {{ font-size:2em; color:#ff4444; }}
</style></head><body>
<div class="header">
    <h1>Security Assessment Portfolio</h1>
    <p>Target: {self.data['scope']['target']}</p>
    <p>Date: {self.data['scope']['date']}</p>
    <p>Assessor: {self.data['scope']['assessor']}</p>
</div>
<div class="stats">
    <div class="stat"><div class="stat-num">{len(self.data['vulnerabilities'])}</div><div>Vulnerabilities</div></div>
    <div class="stat"><div class="stat-num">{sum(1 for v in self.data['vulnerabilities'] if v['severity']=='CRITICAL')}</div><div>Critical</div></div>
    <div class="stat"><div class="stat-num">{sum(1 for v in self.data['vulnerabilities'] if v['severity']=='HIGH')}</div><div>High</div></div>
</div>
<h2>Findings</h2>
{rows}
</body></html>"""

        with open(html_path, "w") as f:
            f.write(html)
        print(f"    [+] HTML: {html_path}")
        print(f"    [+] Size: {os.path.getsize(html_path)} bytes")
        self.report["phases"]["portfolio"] = {"path": html_path, "size": os.path.getsize(html_path)}

    # ------------------------------------------------------------------
    def run_all(self):
        print("=" * 64)
        print(" Complete Security Assessment - Project #70")
        print("=" * 64)
        print(f"[+] Target: {self.data['scope']['target']}")
        self.phase1_scope()
        self.phase2_recon()
        self.phase3_scan()
        self.phase4_exploit()
        self.phase5_post_exploit()
        self.phase6_standards()
        self.phase7_remediation()
        self.phase8_business_impact()
        self.phase9_pdf()
        self.phase10_portfolio()

        # Save JSON report
        json_path = f"{REPORTS_DIR}/assessment_report.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")
        print("\n" + "=" * 64)
        print("[✓] ASSESSMENT COMPLETE")
        print(f"    PDF:       {REPORTS_DIR}/security_assessment_report.pdf")
        print(f"    Portfolio: {REPORTS_DIR}/portfolio.html")
        print(f"    JSON:      {json_path}")
        print("=" * 64)

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("ERROR: Linux only")
        sys.exit(1)
    FinalAssessmentToolkit().run_all()
