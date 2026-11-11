#!/usr/bin/env python3
"""
purple_team_toolkit.py — Purple Team Collaboration Toolkit (Project #68)
Bridges Red Team attacks and Blue Team detections with metrics.
"""
import os, sys, json
from datetime import datetime

MOCK_DIR = "mock"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

class PurpleTeamToolkit:
    def __init__(self):
        self.report = {
            "timestamp": datetime.now().isoformat(),
            "mock_dir": MOCK_DIR,
            "phases": {},
        }

    def _load(self, name):
        with open(os.path.join(MOCK_DIR, name)) as f:
            return json.load(f)

    # ------------------------------------------------------------------
    # PHASE 1 — Red Team Attack Simulation
    # ------------------------------------------------------------------
    def phase1_red_team(self):
        print("\n[PHASE 1] RED TEAM ATTACK SIMULATION")
        data = self._load("red_traces.json")
        attacks = data["attacks"]

        for a in attacks:
            print(f"\n    [{a['technique']}] {a['name']}")
            print(f"      Target: {a['target']}")
            print(f"      Outcome: {a['outcome']}")
            print(f"      [!] SIMULATED — not executed")

        print(f"\n    [+] {len(attacks)} attacks simulated (safe)")
        self.report["phases"]["red_team"] = attacks

    # ------------------------------------------------------------------
    # PHASE 2 — Blue Team Detection
    # ------------------------------------------------------------------
    def phase2_blue_team(self):
        print("\n[PHASE 2] BLUE TEAM DETECTION")
        data = self._load("blue_signals.json")
        detections = data["detections"]

        red = self._load("red_traces.json")["attacks"]
        red_map = {a["id"]: a for a in red}

        for d in detections:
            print(f"\n    [{d['rule']}]")
            print(f"      Matches: {d['matches']}")
            print(f"      Detected at: {d['detected_at']}")
            print(f"      MTTD: {d['mttd_seconds']}s")
            print(f"      Responded at: {d['response_at']}")
            print(f"      MTTR: {d['mttr_seconds']}s")
            print(f"      [+] Detection confirmed")

        print(f"\n    [+] {len(detections)} detections")
        self.report["phases"]["blue_team"] = detections
        return detections, red

    # ------------------------------------------------------------------
    # PHASE 3 — Correlation (MTTD / MTTR)
    # ------------------------------------------------------------------
    def phase3_correlation(self, detections, red):
        print("\n[PHASE 3] CORRELATION (MTTD / MTTR)")

        mttd_values = [d["mttd_seconds"] for d in detections]
        mttr_values = [d["mttr_seconds"] for d in detections]

        mttd_avg = sum(mttd_values) / len(mttd_values) if mttd_values else 0
        mttr_avg = sum(mttr_values) / len(mttr_values) if mttr_values else 0

        detected_ids = set(d["matches"] for d in detections)
        all_red_ids = set(a["id"] for a in red)
        missed = all_red_ids - detected_ids

        detection_rate = len(detected_ids) / len(all_red_ids) * 100 if all_red_ids else 0

        print(f"\n    [MTTD] Mean Time to Detect")
        for d in detections:
            print(f"      {d['matches']}: {d['mttd_seconds']}s")
        print(f"      Average: {mttd_avg:.1f}s ({mttd_avg/60:.1f} min)")

        print(f"\n    [MTTR] Mean Time to Respond")
        for d in detections:
            print(f"      {d['matches']}: {d['mttr_seconds']}s")
        print(f"      Average: {mttr_avg:.1f}s ({mttr_avg/60:.1f} min)")

        print(f"\n    [DETECTION RATE]")
        print(f"      Detected: {len(detected_ids)}/{len(all_red_ids)}")
        print(f"      Missed:   {len(missed)} ({', '.join(sorted(missed)) if missed else 'none'})")
        print(f"      Rate:     {detection_rate:.1f}%")

        results = {
            "mttd_avg_seconds": round(mttd_avg, 1),
            "mttd_avg_minutes": round(mttd_avg/60, 1),
            "mttr_avg_seconds": round(mttr_avg, 1),
            "mttr_avg_minutes": round(mttr_avg/60, 1),
            "detected": len(detected_ids),
            "total_attacks": len(all_red_ids),
            "missed": sorted(missed),
            "detection_rate_pct": round(detection_rate, 1),
        }
        self.report["phases"]["correlation"] = results
        return results, missed

    # ------------------------------------------------------------------
    # PHASE 4 — Detection Gaps
    # ------------------------------------------------------------------
    def phase4_gaps(self, missed):
        print("\n[PHASE 4] DETECTION GAPS")
        coverage = self._load("mitre_coverage.json")

        uncovered = [tid for tid, info in coverage.items() if not info["covered"]]
        print(f"\n    [UNCOVERED TECHNIQUES] {len(uncovered)}")
        for tid in uncovered:
            info = coverage[tid]
            print(f"      {tid}: {info['red']} → NO DETECTION ({info['blue']} missing)")

        print(f"\n    [MISSED ATTACKS] {len(missed)}")
        for m in missed:
            print(f"      {m}: no Blue detection")

        recommendations = []
        for tid in uncovered:
            recommendations.append(f"Add detection for {tid} ({coverage[tid]['red']})")
        if missed:
            recommendations.append(f"Add rule for {len(missed)} missed attack(s)")

        print(f"\n    [IMPROVEMENTS] {len(recommendations)}")
        for r in recommendations:
            print(f"      - {r}")

        results = {
            "uncovered_techniques": uncovered,
            "missed_attacks": missed,
            "recommendations": recommendations,
        }
        self.report["phases"]["gaps"] = results
        return results

    # ------------------------------------------------------------------
    # PHASE 5 — Collaborative Report
    # ------------------------------------------------------------------
    def phase5_collab_report(self, red, detections, corr, gaps):
        print("\n[PHASE 5] COLLABORATIVE REPORT")

        print(f"\n    RED TEAM:")
        print(f"      Attacks simulated: {len(red)}")
        print(f"      Techniques: {', '.join(a['technique'] for a in red)}")

        print(f"\n    BLUE TEAM:")
        print(f"      Detections: {len(detections)}")
        print(f"      MTTD: {corr['mttd_avg_minutes']} min")
        print(f"      MTTR: {corr['mttr_avg_minutes']} min")
        print(f"      Detection rate: {corr['detection_rate_pct']}%")

        print(f"\n    COLLABORATION:")
        print(f"      Detection gaps: {len(gaps['uncovered_techniques'])}")
        print(f"      Missed attacks: {len(gaps['missed_attacks'])}")
        print(f"      Improvements: {len(gaps['recommendations'])}")

        self.report["phases"]["collaborative_report"] = {
            "red_attacks": len(red),
            "blue_detections": len(detections),
            "detection_rate": corr["detection_rate_pct"],
            "mttd_min": corr["mttd_avg_minutes"],
            "mttr_min": corr["mttr_avg_minutes"],
            "gaps": len(gaps["uncovered_techniques"]),
        }

    # ------------------------------------------------------------------
    # PHASE 6 — Continuous Improvement
    # ------------------------------------------------------------------
    def phase6_continuous(self, corr, gaps):
        print("\n[PHASE 6] CONTINUOUS IMPROVEMENT")

        print(f"\n    [FEEDBACK LOOP]")
        print(f"      1. Red Team → Blue Team: attack traces shared")
        print(f"      2. Blue Team → Red Team: detection gaps returned")
        print(f"      3. Red Team retests: validate new rules")
        print(f"      4. Repeat: continuous cycle")

        print(f"\n    [NEXT ITERATION]")
        for r in gaps["recommendations"]:
            print(f"      - {r}")

        print(f"\n    [KPIs]")
        print(f"      Current MTTD: {corr['mttd_avg_minutes']} min")
        print(f"      Current MTTR: {corr['mttr_avg_minutes']} min")
        print(f"      Current detection rate: {corr['detection_rate_pct']}%")
        print(f"      Target MTTD: < 5 min")
        print(f"      Target MTTR: < 15 min")
        print(f"      Target detection rate: > 95%")

        self.report["phases"]["continuous_improvement"] = {
            "kpis": {
                "current_mttd_min": corr["mttd_avg_minutes"],
                "current_mttr_min": corr["mttr_avg_minutes"],
                "current_detection_rate": corr["detection_rate_pct"],
                "target_mttd_min": 5,
                "target_mttr_min": 15,
                "target_detection_rate": 95,
            },
            "next_iteration": gaps["recommendations"],
        }

    # ------------------------------------------------------------------
    # PHASE 7 — Report
    # ------------------------------------------------------------------
    def phase7_report(self):
        print("\n[PHASE 7] REPORT")

        confirmed = []
        red = self.report["phases"].get("red_team", [])
        for a in red:
            confirmed.append(f"red.{a['id']} ({a['technique']})")
        blue = self.report["phases"].get("blue_team", [])
        for d in blue:
            confirmed.append(f"blue.{d['id']} ({d['rule']})")
        corr = self.report["phases"].get("correlation", {})
        if corr:
            confirmed.append(f"correlation.mttd ({corr['mttd_avg_minutes']} min)")
            confirmed.append(f"correlation.mttr ({corr['mttr_avg_minutes']} min)")
            confirmed.append(f"correlation.detection_rate ({corr['detection_rate_pct']}%)")
        gaps = self.report["phases"].get("gaps", {})
        for tid in gaps.get("uncovered_techniques", []):
            confirmed.append(f"gaps.uncovered ({tid})")

        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/purple_team_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/purple_team_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Purple Team Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#cc44cc; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #cc44cc; overflow:auto; }}
</style></head><body>
<h1>Purple Team Collaboration Report</h1>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" Purple Team Collaboration Toolkit - Project #68")
        print("=" * 64)
        self.phase1_red_team()
        detections, red = self.phase2_blue_team()
        corr, missed = self.phase3_correlation(detections, red)
        gaps = self.phase4_gaps(missed)
        self.phase5_collab_report(red, detections, corr, gaps)
        self.phase6_continuous(corr, gaps)
        self.phase7_report()

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("ERROR: Linux only")
        sys.exit(1)
    PurpleTeamToolkit().run_all()
