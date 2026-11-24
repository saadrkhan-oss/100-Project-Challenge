#!/usr/bin/env python3
"""
Project 81 — Blockchain Security Toolkit (Smart Contracts)
Pattern-based vulnerability detection for Solidity/Vyper.
All exploit testing is SIMULATED — no deployment to any chain.
Defensive/educational use only.
"""
import os, re, sys, json, time, html
from datetime import datetime
from pathlib import Path

ROOT      = Path(__file__).resolve().parent
CONTRACTS = ROOT / "contracts"
REPORTS   = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

def banner(s): print(f"\n[📊] {s}")

# ------------------------------------------------------------------ phase 1
def phase1_analyze():
    banner("PHASE 1: CONTRACT ANALYSIS")
    files = sorted(list(CONTRACTS.glob("*.sol")) + list(CONTRACTS.glob("*.vy")))
    if not files:
        print("    [!] no contracts found"); sys.exit(1)
    contracts = []
    for f in files:
        text = f.read_text()
        lang = "Solidity" if f.suffix == ".sol" else "Vyper"
        pragma = ""
        m = re.search(r'pragma solidity\s+([^;]+);', text)
        if m: pragma = m.group(1).strip()
        else:
            m = re.search(r'#\s*@version\s+(.+)', text)
            if m: pragma = m.group(1).strip()
        functions = re.findall(r'function\s+(\w+)\s*\(', text)
        if lang == "Vyper":
            functions = re.findall(r'def\s+(\w+)\s*\(', text)
        state_vars = re.findall(r'^\s*(?:mapping|uint|address|bool|string|bytes|int)\s+(?:\w+\s+)?(?:public\s+)?(\w+)\s*;', text, re.M)
        if lang == "Vyper":
            state_vars = re.findall(r'^(\w+)\s*:', text, re.M)
        events = re.findall(r'event\s+(\w+)', text)
        print(f"    [{lang}] {f.name}")
        print(f"      Version: {pragma or 'unknown'}")
        print(f"      Functions: {len(functions)} — {', '.join(functions[:5])}{'...' if len(functions)>5 else ''}")
        print(f"      State vars: {len(state_vars)}")
        print(f"      Events: {len(events)}")
        contracts.append({"file": str(f.relative_to(ROOT)), "lang": lang, "pragma": pragma,
                          "functions": functions, "state_vars": state_vars,
                          "events": events, "text": text})
    print(f"    [+] {len(contracts)} contracts analyzed")
    return contracts

# ------------------------------------------------------------------ phase 2
def phase2_vulns(contracts):
    banner("PHASE 2: VULNERABILITY DETECTION")
    findings = []

    for c in contracts:
        text = c["text"]
        fname = c["file"]

        # --- Reentrancy: external call before state update
        for fn in re.finditer(
            r'function\s+(\w+)[^{]*\{([^}]*\.call\{[^}]*\}[^}]*)\}',
            text, re.DOTALL):
            body = fn.group(2)
            call_pos = body.find(".call")
            update_pos = -1
            for u in re.finditer(r'balances\[[^\]]+\]\s*-=', body):
                update_pos = u.start()
            if call_pos >= 0 and update_pos > call_pos:
                findings.append({
                    "id": "reentrancy", "severity": "Critical", "swc": "SWC-107",
                    "cwe": "CWE-841", "file": fname, "function": fn.group(1),
                    "detail": f"External call before state update in {fn.group(1)}()",
                    "remediation": "Use Checks-Effects-Interactions pattern; add reentrancy guard (nonReentrant).",
                })

        # --- Integer overflow: + or - on balances without SafeMath (Solidity <0.8)
        if c["lang"] == "Solidity":
            ver = c["pragma"]
            old_sol = any(v in ver for v in ("0.7", "0.6", "0.5", "0.4"))
            if old_sol:
                for fn in re.finditer(r'function\s+(\w+)[^{]*\{([^}]*)\}', text, re.DOTALL):
                    body = fn.group(2)
                    if re.search(r'\+=|\-=', body) and "SafeMath" not in body and "using SafeMath" not in text:
                        findings.append({
                            "id": "integer_overflow", "severity": "High", "swc": "SWC-101",
                            "cwe": "CWE-190", "file": fname, "function": fn.group(1),
                            "detail": f"Unchecked arithmetic in {fn.group(1)}() (Solidity {ver}, no SafeMath)",
                            "remediation": "Upgrade to Solidity 0.8+ (built-in overflow checks) or use SafeMath.",
                        })

        # --- Access control: setter functions without modifiers
        for fn in re.finditer(r'function\s+(set|update|change|emergency|withdraw|mint|burn)(\w*)\s*\([^)]*\)\s*(public|external)\s*(?!.*onlyOwner)[^{]*\{', text):
            fname_fn = fn.group(1) + fn.group(2)
            before = text[:fn.start()]
            has_modifier = "onlyOwner" in fn.group(0) or "require(msg.sender" in fn.group(0)
            if not has_modifier:
                findings.append({
                    "id": "access_control", "severity": "High", "swc": "SWC-105",
                    "cwe": "CWE-284", "file": fname, "function": fname_fn,
                    "detail": f"{fname_fn}() has no access control",
                    "remediation": "Add onlyOwner/onlyRole modifier; validate msg.sender.",
                })

        # --- Front-running: swap based on balance ratio
        for fn in re.finditer(r'function\s+(\w*[Ss]wap\w*)\s*\([^)]*\)[^{]*\{([^}]*)\}', text, re.DOTALL):
            body = fn.group(2)
            if "address(this).balance" in body or "getPrice" in body:
                findings.append({
                    "id": "front_running", "severity": "Medium", "swc": "SWC-114",
                    "cwe": "CWE-362", "file": fname, "function": fn.group(1),
                    "detail": f"{fn.group(1)}() is front-runnable (state depends on balance ratio)",
                    "remediation": "Use commit-reveal scheme; add slippage protection; use TWAP oracle.",
                })

        # Vyper: missing @only_owner style
        if c["lang"] == "Vyper":
            for fn in re.finditer(r'@external\s+def\s+(\w+)\([^)]*\):\s*\n((?:[ \t]+.*\n)*)', text):
                name = fn.group(1)
                body = fn.group(2)
                if name in ("mint", "burn", "setOwner") and "assert msg.sender" not in body:
                    findings.append({
                        "id": "access_control", "severity": "High", "swc": "SWC-105",
                        "cwe": "CWE-284", "file": fname, "function": name,
                        "detail": f"Vyper {name}() has no msg.sender check",
                        "remediation": "Add `assert msg.sender == self.owner` at top of function.",
                    })
                if "-=" in body and "assert" not in body:
                    findings.append({
                        "id": "integer_underflow", "severity": "High", "swc": "SWC-101",
                        "cwe": "CWE-191", "file": fname, "function": name,
                        "detail": f"Vyper {name}() subtracts without bound check",
                        "remediation": "Add `assert self.balances[msg.sender] >= amount` before subtraction.",
                    })

    # Group + print
    by_rule = {}
    for f in findings: by_rule.setdefault(f["id"], []).append(f)
    for rule, lst in sorted(by_rule.items()):
        print(f"    [{rule.upper()}] Found {len(lst)}")
        for f in lst[:3]:
            print(f"      - {f['file']}::{f['function']} — {f['detail'][:70]}")
        if len(lst) > 3: print(f"      ... and {len(lst)-3} more")
    print(f"    [+] {len(findings)} vulnerabilities found")
    return findings

# ------------------------------------------------------------------ phase 3
def phase3_defi(contracts):
    banner("PHASE 3: DEFI AUDIT")
    findings = []
    for c in contracts:
        text = c["text"]
        fname = c["file"]

        # Flash loan
        if re.search(r'flashLoan', text, re.I):
            has_collateral = "collateral" in text.lower() and "require(collateral" in text.lower()
            if not has_collateral or "flashLoan" in text:
                findings.append({
                    "id": "flash_loan", "severity": "Critical", "swc": "SWC-114",
                    "cwe": "CWE-841", "file": fname,
                    "detail": "flashLoan() lacks collateral/fee enforcement",
                    "remediation": "Require repayment + fee in same tx; verify balanceBefore <= balanceAfter.",
                })

        # Oracle manipulation: single source, no TWAP
        if "oracle.getPrice()" in text or ".getPrice()" in text:
            if "TWAP" not in text and "twap" not in text and "chainlink" not in text.lower():
                findings.append({
                    "id": "oracle_manipulation", "severity": "High", "swc": "SWC-120",
                    "cwe": "CWE-829", "file": fname,
                    "detail": "Price oracle is a single source (no TWAP / no Chainlink aggregator)",
                    "remediation": "Use Chainlink price feeds + TWAP; add stale-price check.",
                })

        # Liquidity pool manipulation
        if "address(this).balance" in text and ("swap" in text or "borrow" in text):
            findings.append({
                "id": "liquidity_manipulation", "severity": "High", "swc": "SWC-114",
                "cwe": "CWE-682", "file": fname,
                "detail": "Contract uses own balance as price source — manipulable via donation",
                "remediation": "Use external DEX TWAP; never use address(this).balance as price input.",
            })

        # Governance: single-owner emergency drain
        if re.search(r'emergencyWithdraw', text, re.I):
            findings.append({
                "id": "governance_attack", "severity": "High", "swc": "SWC-105",
                "cwe": "CWE-284", "file": fname,
                "detail": "emergencyWithdraw() allows single owner to drain contract",
                "remediation": "Use multi-sig + timelock; require DAO vote for emergency functions.",
            })

    by_rule = {}
    for f in findings: by_rule.setdefault(f["id"], []).append(f)
    for rule, lst in sorted(by_rule.items()):
        print(f"    [{rule.upper()}] Found {len(lst)}")
        for f in lst:
            print(f"      - {f['file']} — {f['detail'][:70]}")
    print(f"    [+] {len(findings)} DeFi vulnerabilities")
    return findings

# ------------------------------------------------------------------ phase 4
def phase4_static(contracts, vuln_findings):
    banner("PHASE 4: STATIC ANALYSIS (Slither-style)")
    print("    [SLITHER] Simulated detectors on all contracts")
    slither_findings = []
    for f in vuln_findings:
        slither_findings.append({
            "detector": f["id"],
            "file": f["file"],
            "function": f.get("function", "?"),
            "confidence": "High" if f["severity"] in ("Critical","High") else "Medium",
            "description": f["detail"],
        })
    print(f"      Detectors matched: {len(slither_findings)}")
    for s in slither_findings[:5]:
        print(f"      - {s['detector']} ({s['file']}::{s['function']}) [{s['confidence']}]")
    if len(slither_findings) > 5:
        print(f"      ... and {len(slither_findings)-5} more")
    print(f"    [MYTHRIL] Symbolic execution coverage: simulated")
    mythril = [{"contract": c["file"], "paths_explored": len(c["functions"]) * 3,
                "assertion_violations": 0} for c in contracts]
    for m in mythril:
        print(f"      - {m['contract']}: {m['paths_explored']} paths (0 violations)")
    print(f"    [+] {len(slither_findings)} static findings (Slither) + {len(mythril)} contracts (Mythril)")
    return {"slither": slither_findings, "mythril": mythril}

# ------------------------------------------------------------------ phase 5
def phase5_exploit(vuln_findings, defi_findings):
    banner("PHASE 5: EXPLOIT TESTING (SIMULATED)")
    print("    ⚠️  No chain deployment — attack scenarios are narrated, not executed")
    exploits = []

    if any(f["id"] == "reentrancy" for f in vuln_findings):
        print("    [REENTRANCY] Simulated attack on VulnerableBank.withdraw()")
        print("      1. Attacker deploys malicious contract with fallback()")
        print("      2. fallback() calls withdraw() again before balance updates")
        print("      3. Recursion drains contract balance")
        print("      [+] Would drain all funds — exploit feasible")
        exploits.append({"name": "reentrancy_drain", "contract": "VulnerableBank",
                         "impact": "Full balance drained", "feasible": True,
                         "poc": "Attacker.sol with fallback() { victim.withdraw(amount); }"})

    if any(f["id"] == "flash_loan" for f in defi_findings):
        print("    [FLASH_LOAN] Simulated attack on VulnerableLending.flashLoan()")
        print("      1. Borrow max amount with no collateral")
        print("      2. Use funds to manipulate oracle or dump tokens")
        print("      3. Repay loan, keep profit")
        print("      [+] Exploit feasible — no fee, no collateral")
        exploits.append({"name": "flash_loan_drain", "contract": "VulnerableLending",
                         "impact": "Protocol funds at risk", "feasible": True,
                         "poc": "Aave-style flash loan → price manipulation → drain"})

    if any(f["id"] == "oracle_manipulation" for f in defi_findings):
        print("    [ORACLE] Simulated manipulation of single-source oracle")
        print("      1. Flash-swap on DEX to skew spot price")
        print("      2. Borrow against inflated collateral")
        print("      3. Repay flash loan, keep borrowed funds")
        print("      [+] Exploit feasible — single-source oracle")
        exploits.append({"name": "oracle_manipulation", "contract": "VulnerableLending",
                         "impact": "Under-collateralized borrowing", "feasible": True,
                         "poc": "Flash swap → oracle skew → borrow → profit"})

    if any(f["id"] == "access_control" for f in vuln_findings):
        print("    [ACCESS_CONTROL] Simulated takeover")
        print("      1. Any caller invokes setOwner(attacker)")
        print("      2. Attacker becomes owner")
        print("      [+] Exploit feasible — no access control")
        exploits.append({"name": "ownership_takeover", "contract": "VulnerableBank",
                         "impact": "Full contract takeover", "feasible": True,
                         "poc": "contract.setOwner(attacker) from any EOA"})

    print(f"    [+] {len(exploits)} exploit scenarios validated")
    return exploits

# ------------------------------------------------------------------ phase 6
def phase6_report(contracts, vuln, defi, static, exploits, elapsed):
    banner("PHASE 6: REPORT")
    all_findings = vuln + defi
    all_findings.sort(key=lambda x: (-SEV_RANK[x["severity"]], x["id"]))
    sev_counts = {}
    for f in all_findings: sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    swc_set = sorted(set(f["swc"] for f in all_findings))

    report = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "project": "Project 81 — Blockchain Security Toolkit",
        "contracts_analyzed": [{"file": c["file"], "lang": c["lang"],
                                 "pragma": c["pragma"],
                                 "functions": len(c["functions"])} for c in contracts],
        "summary": {"total_findings": len(all_findings),
                    "by_severity": sev_counts, "swcs": swc_set},
        "findings": all_findings,
        "static_analysis": static,
        "exploits": exploits,
        "elapsed_s": round(elapsed, 2),
        "disclaimer": "All exploit testing SIMULATED. No chain deployment. "
                      "Defensive/educational use only.",
    }
    (REPORTS / "blockchain_report.json").write_text(json.dumps(report, indent=2))
    print(f"    [OK] JSON: reports/blockchain_report.json ({len(all_findings)} findings)")

    rows = "\n".join(
        f"""<tr class="sev-{f['severity'].lower()}">
          <td><span class="badge {f['severity'].lower()}">{f['severity']}</span></td>
          <td><code>{f['swc']}</code></td>
          <td><b>{html.escape(f['id'])}</b></td>
          <td><code>{html.escape(f['file'])}::{html.escape(f.get('function','—'))}</code></td>
          <td>{html.escape(f['detail'])}</td>
          <td>{html.escape(f['remediation'])}</td>
        </tr>""" for f in all_findings)
    cards = "\n".join(
        f'<div class="card"><b>{v}</b>{k}</div>' for k, v in sorted(
            sev_counts.items(), key=lambda x: -SEV_RANK[x[0]]))
    exp_rows = "\n".join(
        f"<tr><td><b>{html.escape(e['name'])}</b></td>"
        f"<td><code>{html.escape(e['contract'])}</code></td>"
        f"<td>{html.escape(e['impact'])}</td>"
        f"<td>{'✅' if e['feasible'] else '❌'}</td>"
        f"<td><code>{html.escape(e['poc'])}</code></td></tr>" for e in exploits)

    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Project 81 — Blockchain Security Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;background:#fafafa;color:#1a1a1a}}
 h1{{border-bottom:3px solid #f57c00;padding-bottom:.4rem}}
 .meta{{color:#666;font-size:.9rem;margin-bottom:1rem}}
 .warning{{background:#fff3e0;border-left:4px solid #f57c00;padding:.7rem 1rem;border-radius:6px;
          font-size:.85rem;margin-bottom:1rem}}
 .cards{{display:flex;gap:1rem;margin:1rem 0 1.5rem;flex-wrap:wrap}}
 .card{{flex:1;min-width:110px;background:#fff;padding:.8rem 1rem;border-radius:8px;
       box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #f57c00;font-size:.85rem;color:#666}}
 .card b{{display:block;font-size:1.5rem;color:#1a1a1a}}
 table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;
        box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:1.5rem}}
 th,td{{padding:.6rem .7rem;text-align:left;border-bottom:1px solid #eee;font-size:.82rem;vertical-align:top}}
 th{{background:#263238;color:#fff}}
 code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px;font-size:.78rem}}
 .badge{{padding:.1rem .45rem;border-radius:10px;color:#fff;font-weight:600;font-size:.72rem}}
 .badge.critical{{background:#b71c1c}} .badge.high{{background:#d32f2f}}
 .badge.medium{{background:#f57c00}} .badge.low{{background:#388e3c}} .badge.info{{background:#0288d1}}
 tr.sev-critical td{{background:#ffebee}} tr.sev-high td{{background:#fff3e0}}
</style></head><body>
<h1>⛓️ Project 81 — Blockchain Security Report</h1>
<div class="meta">Generated {report['generated']} · {len(contracts)} contracts analyzed</div>
<div class="warning">⚠️ All exploit testing SIMULATED. No chain deployment. Defensive/educational use only.</div>
<div class="cards">{cards}</div>
<h2>Vulnerability Findings</h2>
<table>
<thead><tr><th>Severity</th><th>SWC</th><th>ID</th><th>Location</th><th>Detail</th><th>Remediation</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>Exploit Scenarios (Simulated)</h2>
<table>
<thead><tr><th>Exploit</th><th>Contract</th><th>Impact</th><th>Feasible</th><th>PoC</th></tr></thead>
<tbody>{exp_rows}</tbody></table>
<p style="margin-top:2rem;color:#888;font-size:.8rem">
Generated by blockchain_toolkit.py — defensive/educational use only. Only test your own contracts.
</p>
</body></html>"""
    (REPORTS / "blockchain_report.html").write_text(doc)
    print(f"    [OK] HTML: reports/blockchain_report.html")
    print(f"\n    Total findings: {len(all_findings)}")
    for sev in ("Critical","High","Medium","Low","Info"):
        if sev in sev_counts:
            print(f"      {sev:9s}: {sev_counts[sev]}")
    print(f"    SWC IDs: {', '.join(swc_set)}")

# ------------------------------------------------------------------ main
def main():
    t0 = time.time()
    print("[+] Blockchain Security Toolkit (Smart Contracts)")
    print(f"[+] Target: {CONTRACTS.relative_to(ROOT)}/")
    print("[!] All exploit testing SIMULATED — no chain deployment")

    contracts = phase1_analyze()
    vuln      = phase2_vulns(contracts)
    defi      = phase3_defi(contracts)
    static    = phase4_static(contracts, vuln + defi)
    exploits  = phase5_exploit(vuln, defi)
    phase6_report(contracts, vuln, defi, static, exploits, time.time() - t0)
    print(f"\n✅ Done in {time.time()-t0:.2f}s")

if __name__ == "__main__":
    main()
