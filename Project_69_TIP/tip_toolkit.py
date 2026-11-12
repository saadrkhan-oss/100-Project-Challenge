#!/usr/bin/env python3
"""
tip_toolkit.py — Threat Intelligence Platform (Project #69)
7-phase TIP: collection, enrichment, correlation, scoring, STIX, API, report.
"""
import os, sys, json
from datetime import datetime
from collections import defaultdict

MOCK_DIR = "mock"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

class TIPToolkit:
    def __init__(self):
        with open(os.path.join(MOCK_DIR, "iocs.json")) as f:
            self.iocs = json.load(f)["iocs"]
        self.report = {
            "timestamp": datetime.now().isoformat(),
            "ioc_count": len(self.iocs),
            "phases": {},
        }

    # ------------------------------------------------------------------
    # PHASE 1 — IOC Collection
    # ------------------------------------------------------------------
    def phase1_collect(self):
        print("\n[PHASE 1] IOC COLLECTION")
        by_type = defaultdict(list)
        for ioc in self.iocs:
            by_type[ioc["type"]].append(ioc)

        for t in ["ip", "domain", "hash", "url"]:
            items = by_type.get(t, [])
            print(f"\n    {t.upper()}s: {len(items)}")
            for i in items:
                print(f"      - {i['value']} ({i['role']}, {i['campaign']})")

        self.report["phases"]["collection"] = {
            "count": len(self.iocs),
            "by_type": {t: len(v) for t, v in by_type.items()},
        }

    # ------------------------------------------------------------------
    # PHASE 2 — Enrichment
    # ------------------------------------------------------------------
    def phase2_enrichment(self):
        print("\n[PHASE 2] ENRICHMENT (SIMULATED)")
        results = {"virustotal": [], "alienvault": [], "misp": []}

        print(f"\n    [VIRUSTOTAL] Checking hashes...")
        for ioc in self.iocs:
            if ioc["type"] == "hash" and "virustotal" in ioc:
                vt = ioc["virustotal"]
                print(f"      - {ioc['value']}: {vt['positives']}/{vt['total']} detections ({ioc['malware']})")
                results["virustotal"].append({
                    "ioc": ioc["value"], "positives": vt["positives"], "total": vt["total"],
                })

        print(f"\n    [ALIENVAULT] Checking IPs...")
        for ioc in self.iocs:
            if ioc["type"] == "ip" and "alienvault" in ioc:
                av = ioc["alienvault"]
                print(f"      - {ioc['value']}: {av['pulses']} pulses ({ioc['role']})")
                results["alienvault"].append({
                    "ioc": ioc["value"], "pulses": av["pulses"],
                })

        print(f"\n    [MISP] Checking domains...")
        for ioc in self.iocs:
            if ioc["type"] == "domain" and "misp" in ioc:
                mp = ioc["misp"]
                print(f"      - {ioc['value']}: {mp['events']} events ({ioc['role']})")
                results["misp"].append({
                    "ioc": ioc["value"], "events": mp["events"],
                })

        self.report["phases"]["enrichment"] = results

    # ------------------------------------------------------------------
    # PHASE 3 — Correlation
    # ------------------------------------------------------------------
    def phase3_correlation(self):
        print("\n[PHASE 3] CORRELATION")

        # Campaigns
        campaigns = defaultdict(list)
        for ioc in self.iocs:
            campaigns[ioc["campaign"]].append(ioc["value"])
        print(f"\n    [CAMPAIGNS] {len(campaigns)}")
        for c, vals in campaigns.items():
            print(f"      - {c}: {len(vals)} IOCs")
            for v in vals:
                print(f"          {v}")

        # Actors
        actors = defaultdict(list)
        for ioc in self.iocs:
            actors[ioc["actor"]].append(ioc["value"])
        print(f"\n    [ACTORS] {len(actors)}")
        for a, vals in actors.items():
            print(f"      - {a}: {len(vals)} IOCs")

        # Malware families
        families = defaultdict(list)
        for ioc in self.iocs:
            families[ioc["malware"]].append(ioc["value"])
        print(f"\n    [MALWARE FAMILIES] {len(families)}")
        for f, vals in families.items():
            print(f"      - {f}: {len(vals)} IOCs")

        self.report["phases"]["correlation"] = {
            "campaigns": {c: v for c, v in campaigns.items()},
            "actors": {a: v for a, v in actors.items()},
            "malware": {m: v for m, v in families.items()},
        }

    # ------------------------------------------------------------------
    # PHASE 4 — Risk Scoring
    # ------------------------------------------------------------------
    def phase4_scoring(self):
        print("\n[PHASE 4] RISK SCORING")
        results = {"by_cvss": [], "by_confidence": defaultdict(int), "by_risk": defaultdict(int)}

        print(f"\n    [CVSS]")
        for ioc in self.iocs:
            cvss = ioc["cvss"]
            if cvss >= 9.0:
                sev = "CRITICAL"
            elif cvss >= 7.0:
                sev = "HIGH"
            elif cvss >= 4.0:
                sev = "MEDIUM"
            else:
                sev = "LOW"
            print(f"      - {ioc['value']}: CVSS {cvss} ({sev})")
            results["by_cvss"].append({"ioc": ioc["value"], "cvss": cvss, "severity": sev})
            results["by_risk"][sev] += 1

        print(f"\n    [CONFIDENCE]")
        for ioc in self.iocs:
            results["by_confidence"][ioc["confidence"]] += 1
        for c, n in results["by_confidence"].items():
            print(f"      - {c}: {n} IOCs")

        print(f"\n    [OVERALL RISK]")
        for r, n in results["by_risk"].items():
            print(f"      - {r}: {n} IOCs")

        self.report["phases"]["scoring"] = {
            "by_cvss": results["by_cvss"],
            "by_confidence": dict(results["by_confidence"]),
            "by_risk": dict(results["by_risk"]),
        }

    # ------------------------------------------------------------------
    # PHASE 5 — STIX/TAXII Sharing
    # ------------------------------------------------------------------
    def phase5_stix(self):
        print("\n[PHASE 5] STIX/TAXII SHARING")
        # Build a STIX 2.1 bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{datetime.now().timestamp()}",
            "objects": [],
        }

        # Add indicators
        for ioc in self.iocs:
            bundle["objects"].append({
                "type": "indicator",
                "id": f"indicator--{ioc['id']}",
                "name": ioc["value"],
                "pattern": f"[{ioc['type']}:value = '{ioc['value']}']",
                "valid_from": datetime.now().isoformat() + "Z",
                "confidence": {"HIGH": 90, "MEDIUM": 60, "LOW": 30}[ioc["confidence"]],
            })

        # Add campaigns
        campaigns = set(i["campaign"] for i in self.iocs)
        for c in campaigns:
            bundle["objects"].append({
                "type": "campaign",
                "id": f"campaign--{hash(c)}",
                "name": c,
            })

        # Add threat actors
        actors = set(i["actor"] for i in self.iocs)
        for a in actors:
            bundle["objects"].append({
                "type": "threat-actor",
                "id": f"threat-actor--{hash(a)}",
                "name": a,
            })

        # Add malware families
        families = set(i["malware"] for i in self.iocs)
        for m in families:
            bundle["objects"].append({
                "type": "malware",
                "id": f"malware--{hash(m)}",
                "name": m,
            })

        stix_path = f"{REPORTS_DIR}/threat_intel_bundle.json"
        with open(stix_path, "w") as f:
            json.dump(bundle, f, indent=2)

        print(f"\n    [STIX 2.1] Bundle created")
        print(f"      - Indicators: {len(self.iocs)}")
        print(f"      - Campaigns: {len(campaigns)}")
        print(f"      - Threat Actors: {len(actors)}")
        print(f"      - Malware Families: {len(families)}")
        print(f"      - Total objects: {len(bundle['objects'])}")
        print(f"    [+] Saved: {stix_path}")

        self.report["phases"]["stix"] = {
            "indicators": len(self.iocs),
            "campaigns": len(campaigns),
            "actors": len(actors),
            "malware": len(families),
            "total_objects": len(bundle["objects"]),
            "file": stix_path,
        }

    # ------------------------------------------------------------------
    # PHASE 6 — REST API (informational — actual server in api_server.py)
    # ------------------------------------------------------------------
    def phase6_api(self):
        print("\n[PHASE 6] REST API")
        print("    Endpoints (see api_server.py):")
        print("      GET  /iocs          — List all IOCs")
        print("      GET  /iocs/<id>     — Get one IOC")
        print("      GET  /campaigns     — List campaigns")
        print("      GET  /actors        — List actors")
        print("      GET  /stats         — Summary stats")
        print("    Start: python3 api_server.py")
        print("    URL:   http://127.0.0.1:5003")

        self.report["phases"]["api"] = {
            "endpoints": ["/iocs", "/iocs/<id>", "/campaigns", "/actors", "/stats"],
            "port": 5003,
        }

    # ------------------------------------------------------------------
    # PHASE 7 — Report
    # ------------------------------------------------------------------
    def phase7_report(self):
        print("\n[PHASE 7] REPORT")
        total = len(self.iocs)
        confirmed = [
            f"collection.total ({total})",
            f"enrichment.virustotal ({len(self.report['phases']['enrichment']['virustotal'])})",
            f"enrichment.alienvault ({len(self.report['phases']['enrichment']['alienvault'])})",
            f"enrichment.misp ({len(self.report['phases']['enrichment']['misp'])})",
            f"correlation.campaigns ({len(self.report['phases']['correlation']['campaigns'])})",
            f"correlation.actors ({len(self.report['phases']['correlation']['actors'])})",
            f"correlation.malware ({len(self.report['phases']['correlation']['malware'])})",
            f"scoring.cvss ({len(self.report['phases']['scoring']['by_cvss'])})",
            f"stix.objects ({self.report['phases']['stix']['total_objects']})",
            f"api.endpoints ({len(self.report['phases']['api']['endpoints'])})",
        ]

        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/threat_intel_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/threat_intel_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Threat Intel Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ffaa00; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ffaa00; overflow:auto; }}
</style></head><body>
<h1>Threat Intelligence Platform Report</h1>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>IOCs:</b> {self.report['ioc_count']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" Threat Intelligence Platform - Project #69")
        print("=" * 64)
        self.phase1_collect()
        self.phase2_enrichment()
        self.phase3_correlation()
        self.phase4_scoring()
        self.phase5_stix()
        self.phase6_api()
        self.phase7_report()

if __name__ == "__main__":
    TIPToolkit().run_all()
