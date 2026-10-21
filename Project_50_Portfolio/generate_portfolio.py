#!/usr/bin/env python3
"""generate_portfolio.py — Build portfolio artifacts from findings.json"""
import json
import os
from datetime import datetime

with open("findings.json") as f:
    DATA = json.load(f)

PROJECTS = DATA["projects"]
OWNER = DATA.get("portfolio_owner", "Saad")
NOW = datetime.utcnow().strftime("%Y-%m-%d")

SEV_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44cc44",
}

def build_html():
    total_findings = sum(p["finding_count"] for p in PROJECTS)
    categories = sorted({p["category"] for p in PROJECTS})

    cards = ""
    for p in PROJECTS:
        sev = p["severity"]
        color = SEV_COLOR.get(sev, "#888")
        tool = p.get("tool", "-")
        cards += (
            f'<div class="card" data-category="{p["category"]}">'
            f'<div class="card-header" style="border-left:6px solid {color}">'
            f'<span class="pid">#{p["id"]}</span>'
            f'<span class="pname">{p["name"]}</span>'
            f'<span class="sev" style="background:{color}">{sev}</span>'
            f'</div>'
            f'<div class="card-body">'
            f'<p><b>Category:</b> {p["category"]}</p>'
            f'<p><b>Vuln Class:</b> {p["vuln_class"]}</p>'
            f'<p><b>CVSS:</b> {p["cvss"]}</p>'
            f'<p><b>Tool:</b> <code>{tool}</code></p>'
            f'<p><b>Findings:</b> {p["finding_count"]}</p>'
            f'<details><summary>Remediation</summary>'
            f'<p>{p["remediation"]}</p></details>'
            f'</div></div>'
        )

    cat_buttons = '<button class="filter-btn active" data-filter="all">All</button>'
    for c in categories:
        cat_buttons += f'<button class="filter-btn" data-filter="{c}">{c}</button>'

    css = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: monospace; background: #0a0a0a; color: #e0e0e0; padding: 20px; line-height: 1.6; }
    header { text-align: center; padding: 40px 20px; background: linear-gradient(135deg, #1a1a2e, #16213e); border-radius: 12px; margin-bottom: 30px; }
    h1 { color: #ff4444; font-size: 2.5em; }
    .subtitle { color: #888; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 30px 0; }
    .stat { background: #1a1a1a; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #333; }
    .stat-num { font-size: 2em; color: #ff4444; font-weight: bold; }
    .stat-label { color: #888; }
    .filters { margin: 20px 0; }
    .filter-btn { background: #1a1a1a; color: #e0e0e0; border: 1px solid #333; padding: 8px 16px; margin: 4px; border-radius: 6px; cursor: pointer; }
    .filter-btn:hover, .filter-btn.active { background: #ff4444; border-color: #ff4444; color: white; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
    .card { background: #1a1a1a; border-radius: 8px; overflow: hidden; border: 1px solid #333; }
    .card:hover { transform: translateY(-2px); border-color: #ff4444; transition: 0.2s; }
    .card-header { padding: 15px; display: flex; justify-content: space-between; align-items: center; background: #0f0f0f; }
    .pid { color: #888; }
    .pname { flex: 1; margin: 0 15px; font-weight: bold; }
    .sev { color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; }
    .card-body { padding: 15px; }
    .card-body p { margin: 5px 0; font-size: 0.9em; }
    code { background: #0a0a0a; padding: 2px 6px; border-radius: 3px; color: #44cc44; }
    footer { text-align: center; color: #666; margin-top: 50px; padding: 30px; border-top: 1px solid #333; }
    """

    js = """
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const f = btn.dataset.filter;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.card').forEach(c => {
                c.style.display = (f === 'all' || c.dataset.category === f) ? 'block' : 'none';
            });
        });
    });
    """

    html = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        f'<title>Bug Bounty Portfolio - {OWNER}</title>'
        f'<style>{css}</style></head><body>'
        f'<header><h1>Bug Bounty Portfolio</h1>'
        f'<p class="subtitle">{OWNER}</p>'
        f'<p class="subtitle">Generated {NOW}</p></header>'
        f'<div class="stats">'
        f'<div class="stat"><div class="stat-num">{len(PROJECTS)}</div><div class="stat-label">Projects</div></div>'
        f'<div class="stat"><div class="stat-num">{total_findings}</div><div class="stat-label">Findings</div></div>'
        f'<div class="stat"><div class="stat-num">{len(categories)}</div><div class="stat-label">Categories</div></div>'
        f'</div>'
        f'<div class="filters">{cat_buttons}</div>'
        f'<div class="grid">{cards}</div>'
        f'<footer><p>Built with Python, boto3, ysoserial</p><p>Legal labs only</p></footer>'
        f'<script>{js}</script></body></html>'
    )
    with open("index.html", "w") as f:
        f.write(html)
    print("[OK] index.html created")

def build_readme():
    total_findings = sum(p["finding_count"] for p in PROJECTS)
    categories = sorted({p["category"] for p in PROJECTS})

    sev_count = {}
    for p in PROJECTS:
        sev_count[p["severity"]] = sev_count.get(p["severity"], 0) + p["finding_count"]

    lines = []
    lines.append(f"# Bug Bounty Portfolio — {OWNER}\n")
    lines.append(f"> **{len(PROJECTS)} offensive security projects** • **{total_findings} confirmed findings** • **100% legal targets**\n")
    lines.append(f"Generated {NOW}\n")
    lines.append("## At a Glance\n")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Projects | {len(PROJECTS)} |")
    lines.append(f"| Confirmed Findings | {total_findings} |")
    lines.append(f"| Categories | {len(categories)} |")
    lines.append(f"| Critical Severity | {sev_count.get('CRITICAL', 0)} findings |")
    lines.append(f"| High Severity | {sev_count.get('HIGH', 0)} findings |\n")
    lines.append("## Vulnerability Coverage\n")
    lines.append("| # | Project | Category | Severity | Findings |")
    lines.append("|---|---|---|---|---|")
    for p in PROJECTS:
        lines.append(f"| #{p['id']} | {p['name']} | {p['category']} | **{p['severity']}** | {p['finding_count']} |")
    lines.append("\n## Tools Built\n")
    for p in PROJECTS:
        tool = p.get("tool", "-")
        lines.append(f"- **#{p['id']} {p['name']}** -> `{tool}`")
    lines.append("\n## Quick Start\n")
    lines.append("Each project has a self-contained lab:\n")
    lines.append("```bash")
    lines.append("# Example: SSRF (Project #42)")
    lines.append("cd Project_42_SSRF_Toolkit")
    lines.append("python vulnerable_app.py &      # start target")
    lines.append("python ssrf_toolkit.py -t http://127.0.0.1:8000/fetch")
    lines.append("```\n")
    lines.append("## Legal\n")
    lines.append("All testing performed on:")
    lines.append("- Locally hosted vulnerable apps (Flask/Java)")
    lines.append("- LocalStack (AWS emulator)")
    lines.append("- Intentionally vulnerable labs\n")
    lines.append("**No production systems were harmed.**\n")
    lines.append("---\n")
    lines.append(f"*Built with Python, boto3, ysoserial. Tested on WSL2/Ubuntu.*")

    with open("README.md", "w") as f:
        f.write("\n".join(lines))
    print("[OK] README.md created")

def build_methodology():
    lines = []
    lines.append("# Methodology — Attack Chain\n")
    lines.append(f"> How I approach offensive security engagements, applied across {len(PROJECTS)} projects.\n")
    lines.append("## Phase 1 — Reconnaissance\n")
    lines.append("**Goal**: Map the attack surface without touching the target.\n")
    lines.append("- Subdomain enumeration (passive + active)")
    lines.append("- Port scanning (service discovery)")
    lines.append("- Technology fingerprinting\n")
    lines.append("## Phase 2 — Vulnerability Discovery\n")
    lines.append("**Goal**: Identify classes of bugs in the target's attack surface.\n")
    lines.append("### Web Vulnerabilities")
    lines.append("- **Injection**: SSI, LDAP, NoSQL, XXE")
    lines.append("- **Server-Side**: SSRF, deserialization")
    lines.append("- **Client-Side**: XSS\n")
    lines.append("### Cloud Vulnerabilities")
    lines.append("- S3 public buckets")
    lines.append("- IAM over-permissioning")
    lines.append("- Open security groups\n")
    lines.append("## Phase 3 — Exploitation\n")
    lines.append("**Goal**: Prove impact with safe, legal PoCs.\n")
    lines.append("For each vulnerability:")
    lines.append("1. Build minimal PoC")
    lines.append("2. Demonstrate impact (data read / RCE / priv esc)")
    lines.append("3. Document with screenshots")
    lines.append("4. Calculate CVSS score\n")
    lines.append("## Phase 4 — Reporting\n")
    lines.append("**Goal**: Communicate findings to stakeholders.\n")
    lines.append("- Executive summary")
    lines.append("- Technical details")
    lines.append("- Remediation\n")
    lines.append("## Phase 5 — Verification\n")
    lines.append("**Goal**: Confirm the fix works.\n")
    lines.append("- Re-run the exploit after patch")
    lines.append("- Check for variants (bypass techniques)\n")
    lines.append("---\n")
    lines.append("## Applied Across Projects\n")
    for p in PROJECTS:
        lines.append(f"### #{p['id']} — {p['name']}")
        lines.append(f"- **Class**: {p['vuln_class']}")
        lines.append(f"- **Severity**: {p['severity']} (CVSS {p['cvss']})")
        lines.append(f"- **Findings**: {p['finding_count']}")
        lines.append(f"- **Remediation**: {p['remediation']}\n")

    with open("methodology.md", "w") as f:
        f.write("\n".join(lines))
    print("[OK] methodology.md created")

if __name__ == "__main__":
    print("[*] Generating portfolio artifacts...")
    build_html()
    build_readme()
    build_methodology()
    print("")
    print("[OK] Done!")
    print("    index.html      - open in browser")
    print("    README.md       - GitHub-ready")
    print("    methodology.md  - attack chain")
