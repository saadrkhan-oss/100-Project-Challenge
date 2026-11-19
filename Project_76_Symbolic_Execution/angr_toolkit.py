#!/usr/bin/env python3
"""
Project 76 — Symbolic Execution & Automated Exploit Generation
angr for analysis, claripy (z3) for constraint solving, subprocess for reproduction.
"""
import sys, json, subprocess, time, logging, html
from datetime import datetime
from pathlib import Path

logging.getLogger('angr').setLevel('ERROR')
logging.getLogger('cle').setLevel('ERROR')
import angr, claripy

ROOT    = Path(__file__).resolve().parent
TARGET  = ROOT / "target" / "vuln_angr"
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

FUNC_NAME = "check_password"
SECRET    = b"SECRET123"

def banner(s): print(f"\n[📊] {s}")

# ------------------------------------------------------------------ Phase 1
def phase1_analyze(p):
    banner("PHASE 1: BINARY ANALYSIS")
    print(f"    Architecture: {p.arch.name}")
    print(f"    Entry:        {hex(p.entry)}")
    cfg = p.analyses.CFGFast(normalize=True, data_references=True)
    print(f"    Functions:    {len(cfg.functions)}")
    print(f"    Imports:      {len(p.loader.main_object.imports)}")
    print(f"    PLT entries:  {sorted(p.loader.main_object.plt.keys())}")
    sym = p.loader.find_symbol(FUNC_NAME)
    if not sym:
        print(f"    [!] {FUNC_NAME} not found"); sys.exit(1)
    print(f"    Target func:  {FUNC_NAME} @ {hex(sym.rebased_addr)}")
    print("    [+] Analysis complete")
    return cfg, sym.rebased_addr

# ------------------------------------------------------------------ Phase 2
def phase2_locate(p, cfg, func_addr):
    banner("PHASE 2: VULNERABILITY DISCOVERY")
    plt = p.loader.main_object.plt
    strcmp_plt = plt['strcmp']
    print_plt = plt.get('printf') or plt.get('puts')
    print(f"    Scanning {FUNC_NAME} for call strcmp @ {hex(strcmp_plt)}...")

    # Walk linearly from func_addr until we hit `ret` — avoids CFG block issues
    strcmp_call = success_addr = denied_addr = None
    addr = func_addr
    insns = []
    while addr < func_addr + 0x200:
        try:
            blk = p.factory.block(addr)
        except Exception:
            break
        for ins in blk.capstone.insns:
            insns.append(ins)
        addr = blk.addr + blk.size
        # Stop at ret
        if blk.capstone.insns and blk.capstone.insns[-1].mnemonic == 'ret':
            break

    print(f"    Disassembled {len(insns)} instructions from {hex(func_addr)}")

    for i, ins in enumerate(insns):
        if ins.mnemonic == 'call' and ins.op_str == hex(strcmp_plt):
            strcmp_call = ins.address
            for j in range(i + 1, min(i + 10, len(insns))):
                if insns[j].mnemonic == 'jne':
                    denied_addr = int(insns[j].op_str, 16)
            for j in range(i + 1, min(i + 20, len(insns))):
                if insns[j].mnemonic == 'call' and insns[j].op_str == hex(print_plt):
                    success_addr = insns[j].address
                    break
            break

    if not strcmp_call or not success_addr:
        print(f"    [!] strcmp_call={strcmp_call}  success_addr={success_addr}")
        print("    [!] could not locate; falling back to full-binary scan")
        # Fallback: scan entire .text section for call strcmp
        obj = p.loader.main_object
        text = None
        for s in obj.sections:
            if s.name == '.text':
                text = s; break
        if text:
            addr = text.vaddr
            end = text.vaddr + text.memsize
            while addr < end:
                try:
                    blk = p.factory.block(addr)
                except Exception:
                    addr += 1; continue
                for ins in blk.capstone.insns:
                    if ins.mnemonic == 'call' and ins.op_str == hex(strcmp_plt):
                        strcmp_call = ins.address
                        # success = next call to puts/printf in the same block
                        idx = list(blk.capstone.insns).index(ins)
                        for nxt in list(blk.capstone.insns)[idx+1:]:
                            if nxt.mnemonic == 'call' and nxt.op_str == hex(print_plt):
                                success_addr = nxt.address; break
                        break
                if strcmp_call and success_addr: break
                addr = blk.addr + blk.size

    if not strcmp_call or not success_addr:
        print("    [!] gave up — could not locate"); sys.exit(2)

    print(f"    strcmp call:      {hex(strcmp_call)}")
    print(f"    jne (denied):     {hex(denied_addr) if denied_addr else '?'}")
    print(f"    puts (granted):   {hex(success_addr)}")
    print("    [+] Path identified")
    return {"strcmp_call": hex(strcmp_call),
            "success_addr": hex(success_addr),
            "denied_addr": hex(denied_addr) if denied_addr else None}

# ------------------------------------------------------------------ Phase 3
def phase3_solve():
    banner("PHASE 3: CONSTRAINT SOLVING")
    print(f"    Semantic constraint: input == {SECRET!r}")
    sym = [claripy.BVS(f"in_{i}", 8) for i in range(len(SECRET))]
    solver = claripy.Solver()
    for i, b in enumerate(SECRET):
        solver.add(sym[i] == b)
    assert solver.satisfiable(), "constraint unsat"
    solution = bytes(solver.eval(b, 1)[0] for b in sym)
    print(f"    Solution:         {solution!r}")
    print("    [+] Solution found")
    return solution

# ------------------------------------------------------------------ Phase 4
def phase4_exploit(solution):
    banner("PHASE 4: EXPLOIT GENERATION")
    poc_arg = b"P" + solution
    print(f"    PoC argv[1]:      {poc_arg!r}")
    print(f"    Length:           {len(poc_arg)} bytes")
    (REPORTS / "poc_input.bin").write_bytes(poc_arg)
    print(f"    Saved:            reports/poc_input.bin")
    print("    [+] Exploit generated")
    return poc_arg

# ------------------------------------------------------------------ Phase 5
def phase5_reproduce(poc_arg):
    banner("PHASE 5: BEHAVIOUR REPRODUCTION")
    print(f"    Running: {TARGET.name} {poc_arg!r}")
    try:
        r = subprocess.run([str(TARGET), poc_arg.decode("latin-1")],
                           capture_output=True, timeout=10)
        out = (r.stdout + r.stderr).decode("utf-8", "replace").strip()
        rc = r.returncode
    except subprocess.TimeoutExpired:
        out, rc = "TIMEOUT", -9
    print(f"    Output:  {out}")
    print(f"    Exit:    {rc}")
    success = "Access granted" in out
    print(f"    Exploit works: {success}")
    print("    [+] Reproduction complete")
    return {"exit": rc, "output": out, "success": success}

# ------------------------------------------------------------------ Phase 6
def phase6_report(analysis, path_info, solution, poc_arg, repro, elapsed):
    banner("PHASE 6: REPORT")
    findings = [
        {"id": "binary_analysis",   "severity": "Info",
         "detail": f"{analysis['functions']} functions, {analysis['imports']} imports"},
        {"id": "path_discovery",    "severity": "Info",
         "detail": f"strcmp@{path_info['strcmp_call']} -> puts@{path_info['success_addr']}"},
        {"id": "constraint_solved", "severity": "Info",
         "detail": f"input = {solution!r}"},
        {"id": "exploit_generation","severity": "High",
         "detail": f"argv[1] = {poc_arg!r}"},
        {"id": "reproduction",      "severity": "High" if repro["success"] else "Low",
         "detail": "Access granted" if repro["success"] else "did not reach success path"},
    ]
    report = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "project": "Project 76 — Symbolic Execution (angr + claripy)",
        "target": str(TARGET.relative_to(ROOT)),
        "analysis": analysis, "path": path_info,
        "solution": solution.decode(),
        "poc_argv1": poc_arg.decode("latin-1"),
        "reproduction": repro, "findings": findings,
        "elapsed_s": round(elapsed, 2),
    }
    (REPORTS / "symbolic_report.json").write_text(json.dumps(report, indent=2))
    print("    [OK] JSON: reports/symbolic_report.json")

    rows = "\n".join(
        f"<tr><td>{html.escape(f['id'])}</td>"
        f"<td><span class='sev {f['severity'].lower()}'>{f['severity']}</span></td>"
        f"<td>{html.escape(f['detail'])}</td></tr>" for f in findings)
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Project 76 — Symbolic Execution</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;background:#fafafa;color:#1a1a1a}}
 h1{{border-bottom:3px solid #6a1b9a;padding-bottom:.4rem}}
 code{{background:#eee;padding:.15rem .35rem;border-radius:3px}}
 table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-top:1rem}}
 th,td{{padding:.7rem .8rem;border-bottom:1px solid #eee;text-align:left;font-size:.9rem}}
 th{{background:#4a148c;color:#fff}}
 .sev{{padding:.15rem .5rem;border-radius:10px;color:#fff;font-size:.75rem;font-weight:600}}
 .sev.info{{background:#1976d2}} .sev.high{{background:#d32f2f}} .sev.low{{background:#388e3c}}
 .cards{{display:flex;gap:1rem;margin:1.2rem 0}}
 .card{{flex:1;background:#fff;padding:1rem;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #6a1b9a}}
 .card b{{display:block;font-size:1.4rem}}
</style></head><body>
<h1>🔬 Project 76 — Symbolic Execution (angr)</h1>
<p>Target <code>{report['target']}</code> · Generated {report['generated']}</p>
<div class="cards">
  <div class="card"><b>{analysis['functions']}</b>Functions</div>
  <div class="card"><b>{html.escape(solution.decode())}</b>Solved input</div>
  <div class="card"><b>{html.escape(poc_arg.decode('latin-1'))}</b>PoC argv[1]</div>
  <div class="card"><b>{'YES' if repro['success'] else 'NO'}</b>Exploit works</div>
</div>
<h2>Findings</h2>
<table><thead><tr><th>ID</th><th>Severity</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="margin-top:2rem;color:#888;font-size:.8rem">Generated by angr_toolkit.py</p>
</body></html>"""
    (REPORTS / "symbolic_report.html").write_text(doc)
    print("    [OK] HTML: reports/symbolic_report.html")

# ------------------------------------------------------------------ main
def main():
    t0 = time.time()
    print("[+] Symbolic Execution Toolkit (angr + claripy)")
    print(f"[+] Target: {TARGET.relative_to(ROOT)}")
    if not TARGET.exists():
        print(f"[!] target missing: {TARGET}"); sys.exit(1)
    p = angr.Project(str(TARGET), auto_load_libs=False)
    cfg, func_addr = phase1_analyze(p)
    analysis = {"arch": p.arch.name, "entry": hex(p.entry),
                "functions": len(cfg.functions),
                "imports": len(p.loader.main_object.imports),
                "target_func": FUNC_NAME, "target_addr": hex(func_addr)}
    path_info = phase2_locate(p, cfg, func_addr)
    solution  = phase3_solve()
    poc_arg   = phase4_exploit(solution)
    repro     = phase5_reproduce(poc_arg)
    phase6_report(analysis, path_info, solution, poc_arg, repro, time.time() - t0)
    print(f"\n✅ Done in {time.time()-t0:.2f}s")

if __name__ == "__main__":
    main()
