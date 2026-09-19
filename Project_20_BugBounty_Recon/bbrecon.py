#!/usr/bin/env python3
"""
Bug Bounty Reconnaissance Automation Framework
Project #20: Bug Bounty Recon Framework

LEGAL: Only run against domains you own or bug bounty programs
       that explicitly allow automated scanning.
"""

import sys
import os
import json
import time
import argparse
from datetime import datetime
from pathlib import Path

# Add modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.passive_recon import PassiveRecon
from modules.active_recon import ActiveRecon
from modules.content_discovery import ContentDiscovery
from modules.vuln_scanner import VulnScanner

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# ---------------------------------------------------------------------- #
# REPORT GENERATOR
# ---------------------------------------------------------------------- #
def generate_html_report(results, target, output_file):
    """Generate a simple HTML report."""
    css = """
    body { font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
    h1, h2, h3 { color: #58a6ff; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin: 12px 0; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
    .badge.high { background: #da3633; color: white; }
    .badge.med { background: #d29922; color: black; }
    .badge.low { background: #2ea043; color: white; }
    .badge.info { background: #1f6feb; color: white; }
    ul { line-height: 1.6; }
    code { background: #21262d; padding: 2px 4px; border-radius: 3px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #30363d; }
    th { color: #58a6ff; }
    """

    html = [
        '<!DOCTYPE html><html><head>',
        f'<title>Bug Bounty Recon — {target}</title>',
        f'<style>{css}</style>',
        '</head><body>',
        f'<h1>🎯 Bug Bounty Recon Report</h1>',
        f'<p><strong>Target:</strong> <code>{target}</code></p>',
        f'<p><strong>Date:</strong> {datetime.now():%Y-%m-%d %H:%M:%S}</p>',
    ]

    p1 = results.get('phase_1', {})
    p2 = results.get('phase_2', {})
    p3 = results.get('phase_3', {})
    p4 = results.get('phase_4', {})

    # Phase 1
    html.append('<div class="card"><h2>📊 Phase 1: Passive Recon</h2>')
    subs = p1.get('subdomains', [])
    html.append(f'<p><strong>Subdomains found:</strong> {len(subs)}</p>')
    if subs:
        html.append('<ul>' + ''.join(f'<li><code>{s}</code></li>' for s in subs[:50]) + '</ul>')
        if len(subs) > 50:
            html.append(f'<p>... and {len(subs)-50} more</p>')

    dns = p1.get('dns_records', {})
    if dns:
        html.append('<h3>DNS Records</h3><ul>')
        for rtype, records in dns.items():
            html.append(f'<li><strong>{rtype}:</strong> {", ".join(records[:5])}</li>')
        html.append('</ul>')

    whois = p1.get('whois', {})
    if whois:
        html.append('<h3>WHOIS</h3><ul>')
        for k, v in whois.items():
            if v:
                html.append(f'<li><strong>{k}:</strong> {str(v)[:200]}</li>')
        html.append('</ul>')
    html.append('</div>')

    # Phase 2
    html.append('<div class="card"><h2>📊 Phase 2: Active Recon</h2>')
    live = p2.get('live_hosts', [])
    with_ports = [h for h in live if h.get('ports')]
    html.append(f'<p><strong>Live hosts:</strong> {len(with_ports)}</p>')
    if with_ports:
        html.append('<table><tr><th>Host</th><th>IP</th><th>Open Ports</th></tr>')
        for h in with_ports[:30]:
            ports = ', '.join(f"{p['port']}/{p['service']}" for p in h['ports'])
            html.append(f'<tr><td><code>{h["host"]}</code></td><td>{h["ip"]}</td>'
                        f'<td>{ports}</td></tr>')
        html.append('</table>')
    html.append('</div>')

    # Phase 3
    html.append('<div class="card"><h2>📊 Phase 3: Content Discovery</h2>')
    urls = p3.get('urls', [])
    interesting = p3.get('interesting', [])
    params = p3.get('parameters', [])
    html.append(f'<p><strong>URLs discovered:</strong> {len(urls)}</p>')
    html.append(f'<p><strong>Interesting URLs:</strong> {len(interesting)}</p>')
    html.append(f'<p><strong>Parameters:</strong> {len(params)}</p>')
    if interesting:
        html.append('<h3>Interesting URLs</h3><ul>')
        for u in interesting[:30]:
            html.append(f'<li><code>{u[:150]}</code></li>')
        html.append('</ul>')
    html.append('</div>')

    # Phase 4
    html.append('<div class="card"><h2>📊 Phase 4: Vulnerability Scan</h2>')
    xss = p4.get('xss', [])
    sqli = p4.get('sqli', [])
    redir = p4.get('open_redirect', [])

    if xss:
        html.append(f'<h3><span class="badge high">XSS</span> ({len(xss)})</h3><ul>')
        for f in xss[:20]:
            html.append(f'<li><code>{f["url"][:120]}</code> — param: <code>{f["param"]}</code></li>')
        html.append('</ul>')

    if sqli:
        html.append(f'<h3><span class="badge high">SQLi</span> ({len(sqli)})</h3><ul>')
        for f in sqli[:20]:
            html.append(f'<li><code>{f["url"][:120]}</code> — param: <code>{f["param"]}</code></li>')
        html.append('</ul>')

    if redir:
        html.append(f'<h3><span class="badge med">Open Redirect</span> ({len(redir)})</h3><ul>')
        for f in redir[:20]:
            html.append(f'<li><code>{f["url"][:120]}</code> — param: <code>{f["param"]}</code></li>')
        html.append('</ul>')

    if not (xss or sqli or redir):
        html.append('<p>No vulnerabilities found. ✅</p>')
    html.append('</div>')

    # Summary
    html.append('<div class="card"><h2>📋 Summary</h2><ul>')
    html.append(f'<li>Subdomains: {len(subs)}</li>')
    html.append(f'<li>Live hosts: {len(with_ports)}</li>')
    html.append(f'<li>URLs: {len(urls)}</li>')
    html.append(f'<li>Vulnerabilities: {len(xss) + len(sqli) + len(redir)}</li>')
    html.append('</ul></div>')

    html.append('</body></html>')

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html))

# ---------------------------------------------------------------------- #
# MAIN
# ---------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description="Bug Bounty Reconnaissance Automation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bbrecon.py example.com
  python bbrecon.py yourdomain.com --skip-vuln
  python bbrecon.py example.com --output reports/

LEGAL: Only run against domains you own or bug bounty programs
       that explicitly allow automated scanning.
        """
    )
    p.add_argument('domain', help='Target domain')
    p.add_argument('--output', default='reports', help='Output directory')
    p.add_argument('--skip-vuln', action='store_true',
                   help='Skip vulnerability scanning phase')
    p.add_argument('--max-hosts', type=int, default=20,
                   help='Max hosts to scan')
    p.add_argument('--timeout', type=int, default=5,
                   help='Request timeout')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    # Legal banner
    print(f"{Colors.YELLOW}{Colors.BOLD}")
    print("=" * 70)
    print("  LEGAL NOTICE")
    print("=" * 70)
    print("  Only run against domains you own or have explicit permission")
    print("  to test. Bug bounty programs usually require you to stay in")
    print("  scope. Unauthorized scanning is illegal.")
    print("=" * 70)
    print(f"{Colors.RESET}")

    confirm = input("Do you have permission to test this domain? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print(f"{Colors.RED}Exiting.{Colors.RESET}")
        sys.exit(0)

    # Setup output dir
    os.makedirs(args.output, exist_ok=True)
    domain = args.domain.lower().strip()
    safe = domain.replace('/', '_').replace(':', '_')

    print(f"\n{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print(f"  BUG BOUNTY RECON FRAMEWORK")
    print(f"  Target: {domain}")
    print(f"  Output: {args.output}/")
    print("=" * 70)
    print(f"{Colors.RESET}")

    start = time.time()
    results = {}

    # ---- PHASE 1 ----
    phase1 = PassiveRecon(domain, timeout=args.timeout, verbose=args.verbose)
    results['phase_1'] = phase1.run()

    # Save phase 1
    with open(f"{args.output}/subdomains.txt", 'w') as f:
        for s in results['phase_1']['subdomains']:
            f.write(s + '\n')

    # ---- PHASE 2 ----
    phase2 = ActiveRecon(domain,
                         subdomains=results['phase_1']['subdomains'][:args.max_hosts],
                         timeout=args.timeout,
                         verbose=args.verbose)
    results['phase_2'] = phase2.run()

    # Save live hosts + ports
    with open(f"{args.output}/live_hosts.txt", 'w') as f:
        for h in results['phase_2']['live_hosts']:
            if h.get('ports'):
                f.write(f"{h['host']} ({h['ip']})\n")

    with open(f"{args.output}/ports.txt", 'w') as f:
        for h in results['phase_2']['live_hosts']:
            for p in h.get('ports', []):
                f.write(f"{h['host']}:{p['port']} ({p['service']})\n")

    # ---- PHASE 3 ----
    phase3 = ContentDiscovery(domain,
                              live_hosts=results['phase_2']['live_hosts'],
                              timeout=args.timeout,
                              verbose=args.verbose)
    results['phase_3'] = phase3.run()

    with open(f"{args.output}/urls.txt", 'w') as f:
        for u in results['phase_3']['urls']:
            f.write(u + '\n')

    # ---- PHASE 4 ----
    if not args.skip_vuln:
        phase4 = VulnScanner(results['phase_3']['urls'],
                             timeout=args.timeout,
                             verbose=args.verbose)
        results['phase_4'] = phase4.run(results['phase_3']['parameters'])

        with open(f"{args.output}/vulnerabilities.txt", 'w') as f:
            for category, items in results['phase_4'].items():
                if items:
                    f.write(f"\n=== {category.upper()} ===\n")
                    for item in items:
                        f.write(f"{item}\n")
    else:
        results['phase_4'] = {'xss': [], 'sqli': [], 'open_redirect': []}

    # ---- REPORT ----
    results['target'] = domain
    results['timestamp'] = datetime.now().isoformat()
    results['duration_seconds'] = time.time() - start

    # JSON
    with open(f"{args.output}/report.json", 'w') as f:
        json.dump(results, f, indent=2, default=str)

    # HTML
    generate_html_report(results, domain, f"{args.output}/report.html")

    # ---- SUMMARY ----
    elapsed = time.time() - start
    print(f"\n{Colors.BOLD}{Colors.GREEN}")
    print("=" * 70)
    print("  RECON COMPLETE")
    print("=" * 70)
    print(f"{Colors.RESET}")
    print(f"  Subdomains:      {len(results['phase_1']['subdomains'])}")
    print(f"  Live hosts:      {len(results['phase_2']['live_hosts'])}")
    print(f"  Open ports:      {len(results['phase_2']['all_open_ports'])}")
    print(f"  URLs:            {len(results['phase_3']['urls'])}")
    print(f"  Interesting:     {len(results['phase_3']['interesting'])}")
    print(f"  Vulnerabilities: "
          f"{len(results['phase_4'].get('xss', [])) + len(results['phase_4'].get('sqli', [])) + len(results['phase_4'].get('open_redirect', []))}")
    print(f"  Duration:        {elapsed:.1f}s")
    print(f"\n{Colors.CYAN}Output files:{Colors.RESET}")
    for fname in ['subdomains.txt', 'live_hosts.txt', 'ports.txt',
                  'urls.txt', 'vulnerabilities.txt', 'report.json', 'report.html']:
        path = f"{args.output}/{fname}"
        if os.path.exists(path):
            print(f"    ✓ {path}")
    print(f"\n{Colors.GREEN}[✓] Done.{Colors.RESET}")

if __name__ == '__main__':
    main()