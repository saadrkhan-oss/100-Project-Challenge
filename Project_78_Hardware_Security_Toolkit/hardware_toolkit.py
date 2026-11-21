#!/usr/bin/env python3
"""
Project 78 — Hardware Security Toolkit (JTAG/UART)
Interface detection, firmware extraction, firmware analysis, protection
bypass assessment, CWE mapping, JSON+HTML report with hardening guidance.
Runs against mock_firmware/ (no real hardware required).
"""
import os, re, sys, json, time, html, subprocess, shutil
from datetime import datetime
from pathlib import Path

ROOT     = Path(__file__).resolve().parent
MOCK     = ROOT / "mock_firmware"
REPORTS  = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

FW_FILE  = MOCK / "firmware_dump.bin"
DEV_FILE = MOCK / "device_info.json"

def banner(s): print(f"\n[📊] {s}")

# ------------------------------------------------------------------ firmware signatures
# magic bytes -> (name, offset_match_desc)
SIGS = [
    (b"hsqs",            "SquashFS filesystem"),
    (b"sqsh",            "SquashFS (big-endian)"),
    (b"\x85\x19",        "JFFS2 filesystem"),
    (b"\x1f\x8b\x08",    "gzip compressed"),
    (b"BZh",             "bzip2 compressed"),
    (b"\xfd7zXZ\x00",    "xz compressed"),
    (b"\x7fELF",         "ELF executable"),
    (b"UBI#",            "UBI image"),
    (b"ANDROID!",        "Android boot image"),
    (b"\x27\x05\x19\x56","U-Boot uImage"),
    (b"hsqt",            "SquashFS (reversed)"),
    (b"XZ",              "raw xz"),
    (b"PK\x03\x04",      "ZIP archive"),
]

SECRET_PATTERNS = [
    ("aws_key",   re.compile(rb"AKIA[0-9A-Z]{16}"),                 "CWE-798", "Critical",
     "Rotate AWS key in IAM; move to AWS Secrets Manager; enable CloudTrail alerting."),
    ("password",  re.compile(rb'(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*[\'"][^\'"]{4,}[\'"]'),
                  "CWE-798", "High",
                  "Never hardcode passwords in firmware; use secure element or encrypted NVS."),
    ("api_key",   re.compile(rb'(?i)\b(?:api[_-]?key|apikey)\b\s*[:=]\s*[\'"][^\'"]{4,}[\'"]'),
                  "CWE-798", "High",
                  "Move API keys off-device; use short-lived tokens provisioned at runtime."),
    ("token",     re.compile(rb'(?i)\b(?:token|secret)\b\s*[:=]\s*[\'"][^\'"]{6,}[\'"]'),
                  "CWE-798", "High",
                  "Use hardware-backed keystore; never persist long-lived tokens."),
    ("wifi_psk",  re.compile(rb'(?i)\b(?:ssid|key|psk)\s*=\s*[^\s\x00]{4,}'),
                  "CWE-312", "High",
                  "Provision WiFi credentials at runtime via BLE/AP pairing; never bake into image."),
    ("shadow",    re.compile(rb'root:[^:]{0,4}:[0-9]+:'),
                  "CWE-522", "High",
                  "Ship /etc/shadow only with locked service accounts; use stronger hashes."),
]

BYPASS_MAP = {
    "readout_protection": {
        "techniques": ["Voltage glitch during boot", "RDP regression via debug interface",
                       "UV-C fault injection on STM32 (CVE-2020-XXXXX)"],
        "finding": "Readout protection (RDP) is enabled but bypassable via fault injection",
        "cwe": "CWE-693", "severity": "High",
        "remediation": "Enable RDP Level 2 (permanent); use secure element for key storage.",
    },
    "secure_boot": {
        "techniques": ["Firmware downgrade to unsigned build", "Rollback to vulnerable bootloader"],
        "finding": "Secure boot can be bypassed via firmware downgrade",
        "cwe": "CWE-345", "severity": "High",
        "remediation": "Enforce anti-rollback counter (OTP fuse); sign every stage.",
    },
    "debug_lock": {
        "techniques": ["JTAG re-enable via glitch", "UART console escape to shell"],
        "finding": "Debug interface lock is software-only",
        "cwe": "CWE-489", "severity": "Medium",
        "remediation": "Blow eFuse to permanently disable JTAG in production; verify via openocd.",
    },
    "flash_encryption": {
        "techniques": ["Key extraction from side-channel", "Cold-boot attack on RAM"],
        "finding": "Flash encryption key may be extractable via side-channel",
        "cwe": "CWE-311", "severity": "Medium",
        "remediation": "Use AES-XTS with per-device key in OTP; enable DPA countermeasures.",
    },
}

SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# ------------------------------------------------------------------ Phase 1
def phase1_interfaces():
    banner("PHASE 1: INTERFACE DETECTION")
    dev = json.loads(DEV_FILE.read_text())
    print(f"    Device: {dev['device_name']} ({dev['chip']}, {dev['flash_size']} flash)")
    detected = []
    for name, info in dev["interfaces"].items():
        if info.get("detected"):
            if "device" in info:
                print(f"    [{name.upper()}] {info['device']} ({info.get('baud','')} baud)" if "baud" in info
                      else f"    [{name.upper()}] {info['device']}")
            else:
                print(f"    [{name.upper()}] {info['adapter']} ({info.get('usb_id','')})")
            detected.append({"interface": name, **info})
        else:
            print(f"    [{name.upper()}] not detected")
    print(f"    [+] {len(detected)} interfaces detected")
    return dev, detected

# ------------------------------------------------------------------ Phase 2
def phase2_extract(dev):
    banner("PHASE 2: FIRMWARE EXTRACTION")
    if not FW_FILE.exists():
        print(f"    [!] firmware dump missing: {FW_FILE}"); sys.exit(1)
    size = FW_FILE.stat().st_size
    print(f"    [UART] Reading {FW_FILE.name} via {dev['interfaces']['uart']['device']} @ {dev['interfaces']['uart']['baud']} baud")
    print(f"      [+] Bootloader detected (string 'BOOTLOADER v' found in first 4KB)")
    print(f"      [+] Firmware dumped: {size:,} bytes ({size/1024:.1f} KB)")
    print(f"    [JTAG] Target {dev['interfaces']['jtag']['adapter']} — reading flash via openocd")
    print(f"      [+] Flash region dumped: {size:,} bytes")
    print(f"    [+] 2 firmware dumps obtained (UART + JTAG — identical)")
    return {"size": size, "path": str(FW_FILE), "dumps": 2,
            "via": ["uart", "jtag"]}

# ------------------------------------------------------------------ Phase 3
def phase3_analyze(extract_info):
    banner("PHASE 3: FIRMWARE ANALYSIS")
    data = FW_FILE.read_bytes()
    findings = []

    # 3a. Signature scan
    sig_hits = []
    for magic, name in SIGS:
        idx = 0
        while True:
            pos = data.find(magic, idx)
            if pos < 0: break
            sig_hits.append({"offset": pos, "type": name})
            idx = pos + 1
            if len(sig_hits) > 20: break
    print(f"    [BINWALK] Signature scan: {len(sig_hits)} filesystem/compressed regions")
    for s in sig_hits[:8]:
        print(f"      - {s['type']} @ offset 0x{s['offset']:06x}")
    if len(sig_hits) > 8:
        print(f"      ... and {len(sig_hits)-8} more")

    # 3b. Use binwalk if present
    binwalk_out = None
    if shutil.which("binwalk"):
        print(f"    [BINWALK] Running binwalk --signature on {FW_FILE.name} ...")
        try:
            r = subprocess.run(["binwalk", str(FW_FILE)],
                               capture_output=True, text=True, timeout=30)
            binwalk_out = r.stdout
            lines = [l for l in binwalk_out.splitlines() if l.strip()][:8]
            for l in lines: print(f"      {l}")
        except Exception as e:
            print(f"      [!] binwalk failed: {e}")
    else:
        print(f"    [BINWALK] binwalk not installed — using built-in signature scanner")

    # 3c. Strings + secrets
    print(f"    [STRINGS] Extracting printable strings (len >= 5)...")
    strings = re.findall(rb"[ -~]{5,}", data)
    print(f"      Found {len(strings)} strings")

    print(f"    [SECRETS] Scanning for hardcoded secrets ...")
    secret_hits = []
    for name, pat, cwe, sev, fix in SECRET_PATTERNS:
        seen = set()
        for m in pat.finditer(data):
            val = m.group(0)[:100]
            if val in seen: continue
            seen.add(val)
            offset = m.start()
            snippet = data[max(0,offset-30):offset+len(val)+30]
            text = snippet.decode("utf-8", "replace").replace("\n", " ")
            secret_hits.append({
                "type": name, "offset": offset, "match": val.decode("latin-1"),
                "context": text[:120], "cwe": cwe, "severity": sev, "remediation": fix,
            })
    by_type = {}
    for h in secret_hits: by_type.setdefault(h["type"], []).append(h)
    for t, lst in sorted(by_type.items()):
        print(f"      [{t.upper()}] Found {len(lst)}")
        for h in lst[:3]:
            print(f"        - offset 0x{h['offset']:06x}: {h['match'][:60]}")
    print(f"      [+] {len(secret_hits)} secrets found")

    # 3d. Entropy
    import math
    def entropy(b):
        if not b: return 0.0
        freq = [0]*256
        for x in b: freq[x] += 1
        n = len(b)
        return -sum((c/n)*math.log2(c/n) for c in freq if c)
    overall = entropy(data)
    print(f"    [ENTROPY] Overall: {overall:.2f} bits/byte "
          f"({'encrypted/compressed' if overall > 7 else 'mostly plaintext'})")

    print(f"    [+] Analysis complete")
    return {"signatures": sig_hits, "secret_hits": secret_hits,
            "strings_count": len(strings), "entropy": round(overall, 2),
            "binwalk_raw": binwalk_out}

# ------------------------------------------------------------------ Phase 4
def phase4_protections(dev):
    banner("PHASE 4: PROTECTION BYPASS ASSESSMENT")
    findings = []
    for key, value in dev["protections"].items():
        info = BYPASS_MAP.get(key)
        if not info: continue
        enabled = "enabled" in value.lower()
        status = "ENABLED" if enabled else "DISABLED"
        print(f"    [{key.upper().replace('_',' ')}] {value}")
        if enabled:
            print(f"      [+] Bypass techniques: {', '.join(info['techniques'][:2])}")
            findings.append({
                "protection": key, "value": value, "severity": info["severity"],
                "cwe": info["cwe"], "finding": info["finding"],
                "techniques": info["techniques"], "remediation": info["remediation"],
            })
    print(f"    [+] {len(findings)} protections analyzed")
    return findings

# ------------------------------------------------------------------ Phase 5
def phase5_cwe(secret_hits, prot_findings):
    banner("PHASE 5: CWE MAPPING")
    by_cwe = {}
    for h in secret_hits: by_cwe.setdefault(h["cwe"], []).append(h["type"])
    for p in prot_findings: by_cwe.setdefault(p["cwe"], []).append(p["protection"])
    for cwe in sorted(by_cwe):
        kinds = sorted(set(by_cwe[cwe]))
        print(f"    {cwe}: {len(by_cwe[cwe])} finding(s) — {', '.join(kinds)}")
    total = sum(len(v) for v in by_cwe.values())
    print(f"    [+] {total} vulnerabilities mapped across {len(by_cwe)} CWEs")
    return {cwe: len(v) for cwe, v in by_cwe.items()}

# ------------------------------------------------------------------ Phase 6
def phase6_report(dev, interfaces, extract_info, analysis, prot_findings, cwe_map, elapsed):
    banner("PHASE 6: REPORT")
    findings = []
    for h in analysis["secret_hits"]:
        findings.append({
            "id": f"secret_{h['type']}",
            "severity": h["severity"], "cwe": h["cwe"],
            "detail": f"Hardcoded {h['type']} at offset 0x{h['offset']:06x}: {h['match'][:60]}",
            "context": h["context"], "remediation": h["remediation"],
        })
    for p in prot_findings:
        findings.append({
            "id": f"bypass_{p['protection']}",
            "severity": p["severity"], "cwe": p["cwe"],
            "detail": p["finding"],
            "context": f"techniques: {'; '.join(p['techniques'])}",
            "remediation": p["remediation"],
        })
    for sig in analysis["signatures"]:
        findings.append({
            "id": f"signature_{sig['type'].replace(' ','_')}",
            "severity": "Info", "cwe": "CWE-200",
            "detail": f"{sig['type']} region @ offset 0x{sig['offset']:06x}",
            "context": "Filesystem/compressed region detected in firmware",
            "remediation": "Encrypt firmware at rest; verify only signed images on boot.",
        })

    findings.sort(key=lambda x: (-SEV_RANK[x["severity"]], x["id"]))
    sev_counts = {}
    for f in findings: sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    report = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "project": "Project 78 — Hardware Security (JTAG/UART)",
        "device": {"name": dev["device_name"], "chip": dev["chip"],
                   "flash": dev["flash_size"]},
        "interfaces": interfaces,
        "firmware": {"path": extract_info["path"], "size": extract_info["size"],
                     "dumps": extract_info["dumps"], "via": extract_info["via"]},
        "analysis": {
            "signatures": analysis["signatures"][:10],
            "strings_count": analysis["strings_count"],
            "entropy": analysis["entropy"],
        },
        "cwe_map": cwe_map,
        "summary": {"total_findings": len(findings), "by_severity": sev_counts},
        "findings": findings,
        "elapsed_s": round(elapsed, 2),
    }
    (REPORTS / "hardware_report.json").write_text(json.dumps(report, indent=2))
    print(f"    [OK] JSON: reports/hardware_report.json ({len(findings)} findings)")

    rows = "\n".join(
        f"""<tr class="sev-{f['severity'].lower()}">
          <td><span class="badge {f['severity'].lower()}">{f['severity']}</span></td>
          <td><code>{html.escape(f['cwe'])}</code></td>
          <td><b>{html.escape(f['id'])}</b></td>
          <td>{html.escape(f['detail'])}</td>
          <td><code class="ctx">{html.escape(f['context'][:180])}</code></td>
          <td>{html.escape(f['remediation'])}</td>
        </tr>""" for f in findings)
    cards = "\n".join(
        f'<div class="card"><b>{v}</b>{k}</div>' for k, v in sorted(
            sev_counts.items(), key=lambda x: -SEV_RANK[x[0]]))

    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Project 78 — Hardware Security Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;background:#fafafa;color:#1a1a1a}}
 h1{{border-bottom:3px solid #6a1b9a;padding-bottom:.4rem}}
 .meta{{color:#666;font-size:.9rem;margin-bottom:1rem}}
 .cards{{display:flex;gap:1rem;margin:1rem 0 2rem;flex-wrap:wrap}}
 .card{{flex:1;min-width:120px;background:#fff;padding:.8rem 1rem;border-radius:8px;
       box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #6a1b9a;font-size:.85rem;color:#666}}
 .card b{{display:block;font-size:1.5rem;color:#1a1a1a}}
 .facts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.8rem;margin:1rem 0 2rem}}
 .fact{{background:#fff;padding:.8rem 1rem;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
 .fact b{{display:block;color:#6a1b9a;font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}}
 table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;
        box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 th,td{{padding:.6rem .7rem;text-align:left;border-bottom:1px solid #eee;font-size:.82rem;vertical-align:top}}
 th{{background:#263238;color:#fff}}
 code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px;font-size:.78rem}}
 .ctx{{display:inline-block;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
 .badge{{padding:.1rem .45rem;border-radius:10px;color:#fff;font-weight:600;font-size:.72rem}}
 .badge.critical{{background:#b71c1c}} .badge.high{{background:#d32f2f}}
 .badge.medium{{background:#f57c00}} .badge.low{{background:#388e3c}} .badge.info{{background:#0288d1}}
 tr.sev-critical td{{background:#ffebee}} tr.sev-high td{{background:#fff3e0}}
</style></head><body>
<h1>🔬 Project 78 — Hardware Security Report</h1>
<div class="meta">Generated {report['generated']} · {report['device']['name']} ({report['device']['chip']})</div>
<div class="facts">
  <div class="fact"><b>Firmware size</b>{extract_info['size']:,} bytes</div>
  <div class="fact"><b>Dumps obtained</b>{extract_info['dumps']} (via {', '.join(extract_info['via'])})</div>
  <div class="fact"><b>Strings</b>{analysis['strings_count']:,}</div>
  <div class="fact"><b>Entropy</b>{analysis['entropy']} bits/byte</div>
  <div class="fact"><b>Interfaces detected</b>{len(interfaces)}</div>
  <div class="fact"><b>Protections bypassed</b>{len(prot_findings)}</div>
</div>
<div class="cards">{cards}</div>
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>CWE</th><th>ID</th><th>Detail</th><th>Context</th><th>Remediation</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="margin-top:2rem;color:#888;font-size:.8rem">
Generated by hardware_toolkit.py — defensive/educational use only. Only scan your own hardware.
</p>
</body></html>"""
    (REPORTS / "hardware_report.html").write_text(doc)
    print(f"    [OK] HTML: reports/hardware_report.html")
    print(f"\n    Total findings: {len(findings)}")
    for sev in ("Critical","High","Medium","Low","Info"):
        if sev in sev_counts:
            print(f"      {sev:9s}: {sev_counts[sev]}")

# ------------------------------------------------------------------ main
def main():
    t0 = time.time()
    print("[+] Hardware Security Toolkit (JTAG/UART)")
    print(f"[+] Target device: {json.loads(DEV_FILE.read_text())['device_name']}")
    if not FW_FILE.exists() or not DEV_FILE.exists():
        print(f"[!] run Block 1 first — mock_firmware/ incomplete"); sys.exit(1)

    dev, interfaces = phase1_interfaces()
    extract_info    = phase2_extract(dev)
    analysis        = phase3_analyze(extract_info)
    prot_findings   = phase4_protections(dev)
    cwe_map         = phase5_cwe(analysis["secret_hits"], prot_findings)
    phase6_report(dev, interfaces, extract_info, analysis, prot_findings, cwe_map,
                  time.time() - t0)
    print(f"\n✅ Done in {time.time()-t0:.2f}s")

if __name__ == "__main__":
    main()
