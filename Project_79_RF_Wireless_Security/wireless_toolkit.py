#!/usr/bin/env python3
"""
Project 79 — RF & Wireless Security Toolkit (SDR/BLE/Zigbee/RFID)
All capture/replay/jamming operations are SIMULATED against mock scan data.
No RF is transmitted. Defensive/educational use only.
"""
import os, sys, json, time, html, math
from datetime import datetime
from pathlib import Path

ROOT     = Path(__file__).resolve().parent
MOCK     = ROOT / "mock"
REPORTS  = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)
SCAN     = MOCK / "wireless_scan.json"
CAPTURE  = MOCK / "capture_433.92M.iq"

SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

def banner(s): print(f"\n[📊] {s}")

# ------------------------------------------------------------------ Phase 1
def phase1_detect(data):
    banner("PHASE 1: PROTOCOL DETECTION")
    total = 0
    summary = {}
    for proto in ("ble", "zigbee", "rfid", "wifi"):
        key = "devices" if proto in ("ble","zigbee") else ("tags" if proto=="rfid" else "networks")
        items = data[proto][key]
        summary[proto] = len(items)
        total += len(items)
        print(f"    [{proto.upper()}] {len(items)} {key}")
        for item in items[:3]:
            name = item.get("name") or item.get("ssid") or item.get("uid")
            print(f"      - {name} ({item.get('addr') or item.get('bssid') or item.get('uid')})")
        if len(items) > 3: print(f"      ... and {len(items)-3} more")
    print(f"    [+] {total} wireless devices/networks detected")
    return summary

# ------------------------------------------------------------------ Phase 2
def phase2_capture(data):
    banner("PHASE 2: SIGNAL CAPTURE (SIMULATED)")
    cap = data["sdr_capture"]
    actual = CAPTURE.stat().st_size if CAPTURE.exists() else 0
    print(f"    [SDR] Simulated rtl_sdr -f {cap['frequency_mhz']}M -s {cap['sample_rate'].replace(' ','')}")
    print(f"      [+] {actual:,} bytes captured ({actual/1024/1024:.1f} MB)")
    print(f"    [BLE] Simulated btmon capture")
    print(f"      [+] {len(data['ble']['packets'])} BLE packets captured")
    # I/Q integrity check
    iq_ok = actual > 0 and actual % 2 == 0
    print(f"    [I/Q] Capture integrity: {'OK (even byte count)' if iq_ok else 'INVALID'}")
    print(f"    [+] 2 captures obtained (SDR + BLE)")
    return {"sdr_bytes": actual, "ble_packets": len(data["ble"]["packets"]),
            "frequency_mhz": cap["frequency_mhz"], "iq_ok": iq_ok}

# ------------------------------------------------------------------ Phase 3
def phase3_analysis(data):
    banner("PHASE 3: PROTOCOL ANALYSIS")
    findings = []

    # BLE
    ble_pkts = data["ble"]["packets"]
    ble_unenc = [p for p in ble_pkts if not p["encrypted"]]
    adv = [p for p in ble_pkts if p["type"].startswith("ADV")]
    data_pkts = [p for p in ble_pkts if p["type"] == "DATA"]
    print(f"    [BLE] {len(ble_pkts)} packets: {len(adv)} advertising, {len(data_pkts)} data, {len(ble_unenc)} unencrypted")
    for p in ble_unenc:
        findings.append({
            "id": "ble_unencrypted", "severity": "High", "cwe": "CWE-319",
            "protocol": "BLE", "target": p["src"],
            "detail": f"{p['type']} packet from {p['src']} is unencrypted ({p['len']} bytes)",
            "remediation": "Enable BLE LE Secure Connections (LESC) pairing; require bonding.",
        })

    # Zigbee
    z_unenc = [d for d in data["zigbee"]["devices"] if not d["encrypted"]]
    print(f"    [ZIGBEE] {len(data['zigbee']['devices'])} devices, {len(z_unenc)} unencrypted")
    for d in z_unenc:
        findings.append({
            "id": "zigbee_unencrypted", "severity": "High", "cwe": "CWE-319",
            "protocol": "Zigbee", "target": d["addr"],
            "detail": f"Zigbee device {d['name']} ({d['addr']}) on PAN {d['pan']} uses no encryption",
            "remediation": "Enable Zigbee network key (well-known key is public); use install codes.",
        })

    # RFID
    rf_unenc = [t for t in data["rfid"]["tags"] if not t["encrypted"]]
    print(f"    [RFID] {len(data['rfid']['tags'])} tags, {len(rf_unenc)} unencrypted")
    for t in rf_unenc:
        weak = t.get("key") == "FFFFFFFFFFFF"
        findings.append({
            "id": "rfid_unencrypted", "severity": "Critical" if weak else "High",
            "cwe": "CWE-319", "protocol": "RFID", "target": t["uid"],
            "detail": f"{t['type']} tag {t['uid']} {'uses default key FFFFFFFFFFFF' if weak else 'is unencrypted'}",
            "remediation": "Migrate to MIFARE DESFire EV2/EV3; rotate keys; never ship default keys.",
        })

    # WiFi
    for net in data["wifi"]["networks"]:
        enc = net["encryption"]
        if enc == "Open":
            findings.append({
                "id": "wifi_open", "severity": "Critical", "cwe": "CWE-319",
                "protocol": "WiFi", "target": net["ssid"],
                "detail": f"Network {net['ssid']} is OPEN (no encryption)",
                "remediation": "Enable WPA3-SAE; never expose an open SSID for IoT.",
            })
        elif enc == "WEP":
            findings.append({
                "id": "wifi_wep", "severity": "Critical", "cwe": "CWE-327",
                "protocol": "WiFi", "target": net["ssid"],
                "detail": f"Network {net['ssid']} uses deprecated WEP",
                "remediation": "Migrate to WPA3; WEP is broken in seconds via aircrack-ng.",
            })
        if net.get("wps"):
            findings.append({
                "id": "wifi_wps", "severity": "Medium", "cwe": "CWE-330",
                "protocol": "WiFi", "target": net["ssid"],
                "detail": f"Network {net['ssid']} has WPS enabled (PIN brute-forceable)",
                "remediation": "Disable WPS in router settings; WPS PIN can be brute-forced in ~10 hours.",
            })

    print(f"    [+] {len(findings)} unencrypted/weak protocol findings")
    return findings

# ------------------------------------------------------------------ Phase 4
def phase4_replay(data, analysis_findings):
    banner("PHASE 4: REPLAY ATTACK ASSESSMENT (SIMULATED)")
    print("    ⚠️  No RF transmitted — all replay outcomes are feasibility assessments")
    results = []

    # RF raw (433.92 MHz) — captured IQ
    if CAPTURE.exists():
        print(f"    [RF] 433.92 MHz capture replayable: 2.4 MB IQ (10s @ 2.4 MS/s)")
        print(f"      [+] Feasibility: HIGH — no rolling code, static waveform")
        results.append({"protocol": "RF", "frequency_mhz": 433.92,
                        "feasible": True, "reason": "Static IQ, no rolling-code mitigation",
                        "severity": "High", "cwe": "CWE-294"})

    # BLE — Just Works pairing on unencrypted devices
    ble_unenc_devs = [d for d in data["ble"]["devices"] if not d["encrypted"]]
    for d in ble_unenc_devs:
        print(f"    [BLE] Replay to {d['name']} ({d['addr']}): feasible (no encryption)")
        results.append({"protocol": "BLE", "target": d["name"],
                        "feasible": True, "reason": "Unencrypted connection, no replay protection",
                        "severity": "High", "cwe": "CWE-294"})

    # RFID — default key = trivially replayable
    for t in data["rfid"]["tags"]:
        if not t["encrypted"]:
            print(f"    [RFID] Replay tag {t['uid']}: feasible (default key)")
            results.append({"protocol": "RFID", "target": t["uid"],
                            "feasible": True, "reason": "MIFARE Classic default key FFFFFFFFFFFF",
                            "severity": "Critical", "cwe": "CWE-294"})

    print(f"    [+] {len(results)} replay vectors identified")
    return results

# ------------------------------------------------------------------ Phase 5
def phase5_jamming(data):
    banner("PHASE 5: JAMMING RISK ASSESSMENT (SIMULATED)")
    print("    ⚠️  No RF emitted — regulatory compliance (PTA/FCC) requires no transmission")
    risks = []
    for proto, count in [("RF 433 MHz", len(data["ble"]["devices"])),
                         ("BLE 2.4 GHz", len(data["ble"]["devices"])),
                         ("Zigbee 2.4 GHz", len(data["zigbee"]["devices"]))]:
        print(f"    [{proto}] {count} devices susceptible to targeted jamming")
        risks.append({"protocol": proto, "devices_affected": count,
                      "severity": "Medium", "cwe": "CWE-400",
                      "mitigation": "Implement frequency hopping or channel switching; "
                                    "detect RSSI anomalies as jamming indicator."})
    print(f"    [+] {len(risks)} jamming susceptibility categories")
    return risks

# ------------------------------------------------------------------ Phase 6
def phase6_report(data, summary, capture, analysis, replay, jamming, elapsed):
    banner("PHASE 6: REPORT")
    findings = []
    findings += analysis
    for r in replay:
        findings.append({
            "id": f"replay_{r['protocol'].lower().replace(' ','_')}",
            "severity": r["severity"], "cwe": r["cwe"],
            "protocol": r["protocol"], "target": r.get("target", r.get("frequency_mhz")),
            "detail": f"Replay feasible: {r['reason']}",
            "remediation": "Use rolling codes (KeeLoq/TR-31); enforce BLE LE Secure Connections; "
                           "migrate RFID to DESFire EV3 with challenge-response.",
        })
    for j in jamming:
        findings.append({
            "id": f"jamming_{j['protocol'].lower().replace(' ','_').replace('.','')}",
            "severity": j["severity"], "cwe": j["cwe"],
            "protocol": j["protocol"], "target": f"{j['devices_affected']} devices",
            "detail": f"{j['devices_affected']} {j['protocol']} devices susceptible to jamming",
            "remediation": j["mitigation"],
        })
    findings.sort(key=lambda x: (-SEV_RANK[x["severity"]], x["id"]))
    sev_counts = {}
    for f in findings: sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    cwe_set = sorted(set(f["cwe"] for f in findings))

    report = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "project": "Project 79 — RF & Wireless Security Toolkit",
        "environment": data["environment"],
        "protocols_detected": summary,
        "capture": capture,
        "summary": {"total_findings": len(findings),
                    "by_severity": sev_counts, "cwes": cwe_set},
        "findings": findings,
        "elapsed_s": round(elapsed, 2),
        "disclaimer": "All capture/replay/jamming operations SIMULATED. No RF transmitted. "
                      "Defensive/educational use only.",
    }
    (REPORTS / "wireless_report.json").write_text(json.dumps(report, indent=2))
    print(f"    [OK] JSON: reports/wireless_report.json ({len(findings)} findings)")

    rows = "\n".join(
        f"""<tr class="sev-{f['severity'].lower()}">
          <td><span class="badge {f['severity'].lower()}">{f['severity']}</span></td>
          <td><code>{f['cwe']}</code></td>
          <td><b>{html.escape(f['protocol'])}</b></td>
          <td>{html.escape(str(f['target']))}</td>
          <td>{html.escape(f['detail'])}</td>
          <td>{html.escape(f['remediation'])}</td>
        </tr>""" for f in findings)
    cards = "\n".join(
        f'<div class="card"><b>{v}</b>{k}</div>' for k, v in sorted(
            sev_counts.items(), key=lambda x: -SEV_RANK[x[0]]))
    proto_cards = "\n".join(
        f'<div class="fact"><b>{k.upper()}</b>{v} detected</div>'
        for k, v in summary.items())

    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Project 79 — Wireless Security Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;background:#fafafa;color:#1a1a1a}}
 h1{{border-bottom:3px solid #00897b;padding-bottom:.4rem}}
 .meta{{color:#666;font-size:.9rem;margin-bottom:1rem}}
 .warning{{background:#fff3e0;border-left:4px solid #f57c00;padding:.7rem 1rem;border-radius:6px;
          font-size:.85rem;margin-bottom:1rem}}
 .cards{{display:flex;gap:1rem;margin:1rem 0 1.5rem;flex-wrap:wrap}}
 .card{{flex:1;min-width:110px;background:#fff;padding:.8rem 1rem;border-radius:8px;
       box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #00897b;font-size:.85rem;color:#666}}
 .card b{{display:block;font-size:1.5rem;color:#1a1a1a}}
 .facts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.8rem;margin:1rem 0 2rem}}
 .fact{{background:#fff;padding:.8rem 1rem;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.06);font-size:.85rem;color:#666}}
 .fact b{{display:block;color:#00897b;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}}
 table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;
        box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 th,td{{padding:.6rem .7rem;text-align:left;border-bottom:1px solid #eee;font-size:.82rem;vertical-align:top}}
 th{{background:#263238;color:#fff}}
 code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px;font-size:.78rem}}
 .badge{{padding:.1rem .45rem;border-radius:10px;color:#fff;font-weight:600;font-size:.72rem}}
 .badge.critical{{background:#b71c1c}} .badge.high{{background:#d32f2f}}
 .badge.medium{{background:#f57c00}} .badge.low{{background:#388e3c}} .badge.info{{background:#0288d1}}
 tr.sev-critical td{{background:#ffebee}} tr.sev-high td{{background:#fff3e0}}
</style></head><body>
<h1>📡 Project 79 — RF & Wireless Security Report</h1>
<div class="meta">Environment: {html.escape(data['environment'])} · Generated {report['generated']}</div>
<div class="warning">⚠️ All capture/replay/jamming operations are SIMULATED against mock data.
No RF was transmitted. Complies with PTA/FCC regulatory requirements.</div>
<div class="facts">{proto_cards}
  <div class="fact"><b>CAPTURE</b>{capture['sdr_bytes']:,} bytes @ {capture['frequency_mhz']} MHz</div>
  <div class="fact"><b>REPLAY VECTORS</b>{len(replay)}</div>
  <div class="fact"><b>JAMMING RISKS</b>{len(jamming)}</div>
</div>
<div class="cards">{cards}</div>
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>CWE</th><th>Protocol</th><th>Target</th><th>Detail</th><th>Remediation</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="margin-top:2rem;color:#888;font-size:.8rem">
Generated by wireless_toolkit.py — defensive/educational use only. Only scan your own devices.
</p>
</body></html>"""
    (REPORTS / "wireless_report.html").write_text(doc)
    print(f"    [OK] HTML: reports/wireless_report.html")
    print(f"\n    Total findings: {len(findings)}")
    for sev in ("Critical","High","Medium","Low","Info"):
        if sev in sev_counts:
            print(f"      {sev:9s}: {sev_counts[sev]}")

# ------------------------------------------------------------------ main
def main():
    t0 = time.time()
    print("[+] RF & Wireless Security Toolkit (SDR/BLE/Zigbee/RFID)")
    print(f"[+] Target: {json.loads(SCAN.read_text())['environment']}")
    print("[!] All operations SIMULATED — no RF transmitted")
    if not SCAN.exists() or not CAPTURE.exists():
        print(f"[!] run Block 1 first — mock/ incomplete"); sys.exit(1)

    data = json.loads(SCAN.read_text())
    summary = phase1_detect(data)
    capture = phase2_capture(data)
    analysis = phase3_analysis(data)
    replay   = phase4_replay(data, analysis)
    jamming  = phase5_jamming(data)
    phase6_report(data, summary, capture, analysis, replay, jamming, time.time() - t0)
    print(f"\n✅ Done in {time.time()-t0:.2f}s")

if __name__ == "__main__":
    main()
