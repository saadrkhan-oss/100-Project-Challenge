#!/usr/bin/env python3
"""
Project 75 — Fuzzing Toolkit
Phases: verify -> fuzz (optional) -> triage -> minimize -> reproduce -> report
Works with AFL++ 2.x layout (findings/crashes/), also tolerates findings/default/crashes/.
"""
import os, sys, json, glob, shutil, subprocess, hashlib, html, re, time
from datetime import datetime
from pathlib import Path

ROOT      = Path(__file__).resolve().parent
TARGET    = ROOT / "target" / "vuln_instrumented"
SEEDS     = ROOT / "seeds"
FINDINGS  = ROOT / "findings"
REPORTS   = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

ASAN_ENV = {
    "ASAN_OPTIONS": "abort_on_error=1:halt_on_error=1:symbolize=1:detect_leaks=0",
}

def run(cmd, env=None, timeout=15):
    e = os.environ.copy()
    if env: e.update(env)
    try:
        p = subprocess.run(cmd, capture_output=True,
                           timeout=timeout, env=e)
        # ASAN dumps raw bytes -> decode with replacement
        out = p.stdout.decode("utf-8", errors="replace") if p.stdout else ""
        err = p.stderr.decode("utf-8", errors="replace") if p.stderr else ""
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        return -9, "", "timeout"
    except FileNotFoundError as ex:
        return -127, "", str(ex)

# ---------------------------------------------------------------- Phase 1
def phase1_setup():
    print("\n=== Phase 1: Setup verification ===")
    ok = True
    if not TARGET.exists():
        print(f"  [!] missing target: {TARGET}"); ok = False
    else:
        print(f"  [+] target: {TARGET} ({TARGET.stat().st_size} bytes)")
    seeds = list(SEEDS.glob("*"))
    if not seeds:
        print(f"  [!] no seeds in {SEEDS}"); ok = False
    else:
        print(f"  [+] seeds: {len(seeds)}")
    rc, out, _ = run(["afl-fuzz", "-h"])
    ver = (out or "").splitlines()[0] if out else "unknown"
    print(f"  [+] afl-fuzz: {ver[:80]}")
    if not FINDINGS.exists():
        print(f"  [!] no findings dir (run afl-fuzz first)"); ok = False
    else:
        print(f"  [+] findings: {FINDINGS}")
    return ok

# ---------------------------------------------------------------- Phase 2
def phase2_campaign(seconds=60):
    print(f"\n=== Phase 2: Fuzzing campaign ({seconds}s) ===")
    stats_file = FINDINGS / "fuzzer_stats"
    if stats_file.exists():
        print("  [i] findings already exist — skipping new campaign")
        return parse_stats()
    env = dict(os.environ, AFL_TMPDIR="/dev/shm", AFL_SKIP_CPUFREQ="1",
               AFL_NO_UI="1", **ASAN_ENV)
    print(f"  [*] launching afl-fuzz for {seconds}s ...")
    try:
        subprocess.run(["timeout", str(seconds), "afl-fuzz",
                        "-i", str(SEEDS), "-o", str(FINDINGS),
                        "-m", "none", "--", str(TARGET), "@@"],
                       env=env, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("  [!] afl-fuzz not found"); return {}
    return parse_stats()

def parse_stats():
    f = FINDINGS / "fuzzer_stats"
    if not f.exists(): return {}
    d = {}
    for line in f.read_text().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d

# ---------------------------------------------------------------- Phase 3
def find_crash_files():
    for sub in ("default/crashes", "crashes"):
        p = FINDINGS / sub
        if p.is_dir():
            return sorted(x for x in p.iterdir()
                          if x.is_file() and not x.name.startswith("README"))
    return []

def gdb_triage(path):
    """Return (signal, fault_addr, classification)."""
    rc, out, err = run(["gdb", "-q", "-batch",
                        "-ex", "run", "-ex", "bt 1",
                        "--args", str(TARGET), str(path)],
                       env=ASAN_ENV, timeout=15)
    text = out + err
    sig = "?"
    m = re.search(r"Program received signal (\w+)", text)
    if m: sig = m.group(1)
    elif "AddressSanitizer" in text:
        sig = "SIGABRT(ASAN)"
    addr = "?"
    m = re.search(r"on address (0x[0-9a-fA-F]+)", text)
    if m: addr = m.group(1)
    else:
        m = re.search(r"SEGV.*?at (0x[0-9a-fA-F]+)", text)
        if m: addr = m.group(1)
    cls = "other"
    if "stack-buffer-overflow" in text: cls = "stack-buffer-overflow"
    elif "heap-buffer-overflow" in text: cls = "heap-buffer-overflow"
    elif "SEGV" in text and "0x000000000000" in text: cls = "null-deref"
    elif "SEGV" in text and "unknown address" in text: cls = "null-deref"
    elif "SIGSEGV" in text: cls = "segfault"
    elif "SIGILL" in text: cls = "null-deref"   # ASAN ud2 on null deref
    if cls == "null-deref" and addr == "?": addr = "0x000000000000"
    return sig, addr, cls

def phase3_triage():
    print("\n=== Phase 3: Crash triage (dedup) ===")
    files = find_crash_files()
    print(f"  [i] {len(files)} raw crash files")
    groups = {}
    triaged = []
    for f in files:
        sig, addr, cls = gdb_triage(f)
        key = (sig, addr)
        rec = {"file": str(f.relative_to(ROOT)), "size": f.stat().st_size,
               "signal": sig, "fault_addr": addr, "class": cls,
               "sha1": hashlib.sha1(f.read_bytes()).hexdigest()[:12]}
        triaged.append(rec)
        groups.setdefault(key, []).append(rec)
        print(f"  - {f.name[:60]:60s} sig={sig:14s} addr={addr:20s} class={cls}")
    print(f"  [+] unique crash groups: {len(groups)}")
    return triaged, groups

# ---------------------------------------------------------------- Phase 4
def _still_crashes(data_bytes, tmp):
    tmp.write_bytes(data_bytes)
    rc, out, err = run([str(TARGET), str(tmp)], env=ASAN_ENV, timeout=10)
    return rc != 0 or "AddressSanitizer" in (out + err)

def phase4_minimize(triaged):
    print("\n=== Phase 4: Input minimization (ddmin) ===")
    out_dir = ROOT / "findings" / "minimized"
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = out_dir / ".tmp_input"
    for rec in triaged:
        src = ROOT / rec["file"]
        data = src.read_bytes()
        orig = len(data)
        # greedy byte-drop: try removing chunks of halving size
        chunk = max(1, orig // 2)
        while chunk >= 1:
            i = 0
            while i < len(data):
                cand = data[:i] + data[i+chunk:]
                if cand and _still_crashes(cand, tmp):
                    data = cand
                else:
                    i += chunk
            chunk //= 2
        dst = out_dir / src.name
        dst.write_bytes(data)
        rec["min_path"] = str(dst.relative_to(ROOT))
        rec["orig_size"] = orig
        rec["min_size"] = len(data)
        print(f"  - {src.name[:50]:50s} {orig:>4} -> {len(data):>4} bytes")
    if tmp.exists(): tmp.unlink()
    return triaged

# ---------------------------------------------------------------- Phase 5
def phase5_reproduce(triaged):
    print("\n=== Phase 5: Reproduction ===")
    for rec in triaged:
        p = ROOT / (rec["min_path"] or rec["file"])
        rc, out, err = run([str(TARGET), str(p)], env=ASAN_ENV, timeout=10)
        text = out + err
        confirmed = rc != 0 or "AddressSanitizer" in text
        rec["reproduced"] = confirmed
        rec["repro_exit"] = rc
        print(f"  - {p.name[:50]:50s} exit={rc:<4} reproduced={confirmed}")
    return triaged

# ---------------------------------------------------------------- Phase 6
SEV = {
    "heap-buffer-overflow":  ("High",  "CWE-122"),
    "stack-buffer-overflow": ("High",  "CWE-121"),
    "null-deref":            ("Medium","CWE-476"),
    "segfault":              ("High",  "CWE-119"),
    "other":                 ("Low",   "CWE-000"),
}

def severity_for(cls):
    return SEV.get(cls, SEV["other"])

def phase6_report(triaged, groups, stats):
    print("\n=== Phase 6: Report generation ===")
    uniq = []
    for key, recs in groups.items():
        r = dict(recs[0])
        r["dup_count"] = len(recs)
        sev, cwe = severity_for(r["class"])
        r["severity"] = sev
        r["cwe"] = cwe
        r["poc_command"] = f"./target/vuln_instrumented {r['min_path'] or r['file']}"
        uniq.append(r)

    report = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "project": "Project 75 — Fuzzing & Bug Discovery",
        "target": str(TARGET.relative_to(ROOT)),
        "afl_stats": stats,
        "raw_crash_count": len(triaged),
        "unique_crash_count": len(uniq),
        "crashes": uniq,
    }
    jpath = REPORTS / "report.json"
    jpath.write_text(json.dumps(report, indent=2))
    print(f"  [+] JSON: {jpath}")

    rows = []
    for r in uniq:
        rows.append(f"""
        <tr>
          <td><span class="sev {r['severity'].lower()}">{r['severity']}</span></td>
          <td>{html.escape(r['class'])}<br><small>{r['cwe']}</small></td>
          <td><code>{html.escape(r['signal'])}</code></td>
          <td><code>{html.escape(r['fault_addr'])}</code></td>
          <td>{r['orig_size']} → {r['min_size']} B</td>
          <td>{r['dup_count']}</td>
          <td><code>{html.escape(r['poc_command'])}</code></td>
        </tr>""")

    doc = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>Project 75 — Fuzzing Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}}
 h1{{border-bottom:3px solid #d32f2f;padding-bottom:.4rem}}
 .meta{{color:#666;font-size:.9rem;margin-bottom:1.5rem}}
 .cards{{display:flex;gap:1rem;margin:1rem 0 2rem}}
 .card{{flex:1;background:#fff;padding:1rem 1.2rem;border-radius:8px;
        box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #1976d2}}
 .card b{{font-size:1.6rem;display:block}}
 table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
        overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 th,td{{padding:.7rem .8rem;text-align:left;border-bottom:1px solid #eee;font-size:.88rem}}
 th{{background:#263238;color:#fff;font-weight:600}}
 tr:last-child td{{border-bottom:none}}
 code{{background:#f2f2f2;padding:.15rem .35rem;border-radius:3px;font-size:.82rem}}
 .sev{{padding:.15rem .5rem;border-radius:10px;font-weight:600;font-size:.75rem;color:#fff}}
 .sev.high{{background:#d32f2f}} .sev.medium{{background:#f57c00}} .sev.low{{background:#388e3c}}
</style></head><body>
<h1>🔬 Project 75 — Fuzzing &amp; Bug Discovery</h1>
<div class="meta">Generated {report['generated']} · Target <code>{report['target']}</code> · AFL++ 2.59d</div>

<div class="cards">
  <div class="card"><b>{report['raw_crash_count']}</b>Raw crashes</div>
  <div class="card"><b>{report['unique_crash_count']}</b>Unique bugs</div>
  <div class="card"><b>{stats.get('execs_done','?')}</b>Executions</div>
  <div class="card"><b>{stats.get('paths_total','?')}</b>Coverage paths</div>
</div>

<h2>Crash inventory</h2>
<table>
<thead><tr><th>Severity</th><th>Class</th><th>Signal</th><th>Fault addr</th>
<th>Size (orig→min)</th><th>Dup</th><th>PoC command</th></tr></thead>
<tbody>{''.join(rows)}
</tbody></table>

<p style="margin-top:2rem;color:#888;font-size:.8rem">
 Generated by fuzzing_toolkit.py · Defensive/educational use only.
</p>
</body></html>"""
    hpath = REPORTS / "report.html"
    hpath.write_text(doc)
    print(f"  [+] HTML: {hpath}")

# ---------------------------------------------------------------- main
def main():
    t0 = time.time()
    if not phase1_setup():
        print("\n[!] setup failed"); sys.exit(1)
    stats = phase2_campaign(seconds=60)
    triaged, groups = phase3_triage()
    if not triaged:
        print("\n[!] no crashes found — aborting"); sys.exit(2)
    triaged = phase4_minimize(triaged)
    triaged = phase5_reproduce(triaged)
    phase6_report(triaged, groups, stats)
    print(f"\n✅ Done in {time.time()-t0:.1f}s")

if __name__ == "__main__":
    main()
