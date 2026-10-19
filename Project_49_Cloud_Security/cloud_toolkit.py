#!/usr/bin/env python3
"""
cloud_toolkit.py — Cloud Security Assessment Toolkit (Project #49)
Target: LocalStack (http://127.0.0.1:4566)
"""
import argparse
import json
import os
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

REPORTS_DIR = "reports"
EXTRACTED_DIR = "extracted"
DEFAULT_ENDPOINT = "http://127.0.0.1:4566"
DEFAULT_REGION = "us-east-1"

class Colors:
    GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"
    BLUE="\033[94m"; RESET="\033[0m"; BOLD="\033[1m"

class CloudToolkit:
    def __init__(self, endpoint=DEFAULT_ENDPOINT, region=DEFAULT_REGION):
        self.endpoint = endpoint
        self.region = region
        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.makedirs(EXTRACTED_DIR, exist_ok=True)
        self.report = {
            "endpoint": endpoint,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "phases": {},
        }

    def _client(self, svc):
        return boto3.client(
            svc,
            endpoint_url=self.endpoint,
            region_name=self.region,
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )

    # ------------------------------------------------------------------
    # PHASE 1 — Resource enumeration
    # ------------------------------------------------------------------
    def phase1_enumeration(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 1] RESOURCE ENUMERATION{Colors.RESET}")
        results = {}

        # S3
        try:
            s3 = self._client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            names = [b["Name"] for b in buckets]
            print(f"    [S3] {len(names)} bucket(s): {names}")
            results["s3_buckets"] = {"count": len(names), "names": names}
        except Exception as e:
            print(f"    {Colors.YELLOW}[S3] error: {e}{Colors.RESET}")
            results["s3_buckets"] = {"error": str(e)}

        # IAM users + roles
        try:
            iam = self._client("iam")
            users = iam.list_users().get("Users", [])
            user_names = [u["UserName"] for u in users]
            print(f"    [IAM] {len(user_names)} user(s): {user_names}")
            results["iam_users"] = {"count": len(user_names), "names": user_names}

            roles = iam.list_roles().get("Roles", [])
            role_names = [r["RoleName"] for r in roles]
            print(f"    [IAM] {len(role_names)} role(s): {role_names}")
            results["iam_roles"] = {"count": len(role_names), "names": role_names}
        except Exception as e:
            results["iam_users"] = {"error": str(e)}
            results["iam_roles"] = {"error": str(e)}

        # EC2 security groups
        try:
            ec2 = self._client("ec2")
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
            sg_names = [s["GroupName"] for s in sgs]
            print(f"    [EC2] {len(sg_names)} security group(s): {sg_names}")
            results["ec2_sgs"] = {"count": len(sg_names), "names": sg_names}
        except Exception as e:
            results["ec2_sgs"] = {"error": str(e)}

        self.report["phases"]["enumeration"] = results

    # ------------------------------------------------------------------
    # PHASE 2 — Misconfigurations
    # ------------------------------------------------------------------
    def phase2_misconfigurations(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 2] MISCONFIGURATIONS{Colors.RESET}")
        results = {}

        # --- Public S3 buckets ---
        print(f"\n  [S3] Checking for public buckets...")
        s3 = self._client("s3")
        public_buckets = []
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]
            try:
                policy = s3.get_bucket_policy(Bucket=name).get("Policy", "")
                if '"Principal": "*"' in policy.replace('"Principal":"*"', '"Principal": "*"'):
                    public_buckets.append(name)
                    print(f"    {Colors.RED}[+] PUBLIC: {name}{Colors.RESET}")
                    try:
                        obj = s3.get_object(Bucket=name, Key="secret.txt")
                        content = obj["Body"].read().decode()
                        print(f"        Data: {content.strip()[:100]}")
                        with open(f"{EXTRACTED_DIR}/public_bucket_{name}.txt", "w") as f:
                            f.write(content)
                    except ClientError:
                        pass
            except ClientError:
                pass
        results["public_s3"] = {"count": len(public_buckets), "buckets": public_buckets}

        # --- Open security groups ---
        print(f"\n  [EC2] Checking for open security groups...")
        ec2 = self._client("ec2")
        open_sgs = []
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                for rng in perm.get("IpRanges", []):
                    if rng.get("CidrIp") == "0.0.0.0/0":
                        entry = f"{sg['GroupName']}:{perm.get('FromPort')}"
                        open_sgs.append(entry)
                        print(f"    {Colors.RED}[+] OPEN: {entry} (0.0.0.0/0){Colors.RESET}")
        results["open_sgs"] = {"count": len(open_sgs), "entries": open_sgs}

        # --- Overprivileged IAM ---
        print(f"\n  [IAM] Checking for wildcard policies...")
        iam = self._client("iam")
        overpriv = []
        for u in iam.list_users().get("Users", []):
            name = u["UserName"]
            try:
                policies = iam.list_user_policies(UserName=name).get("PolicyNames", [])
                for pname in policies:
                    doc = iam.get_user_policy(UserName=name, PolicyName=pname)
                    pd = doc.get("PolicyDocument", {})
                    if isinstance(pd, dict):
                        for st in pd.get("Statement", []):
                            if st.get("Action") == "*" and st.get("Resource") == "*":
                                overpriv.append(f"user:{name}/{pname}")
                                print(f"    {Colors.RED}[+] OVERPRIVILEGED: user:{name}{Colors.RESET}")
            except ClientError:
                pass
        results["overprivileged_iam"] = {"count": len(overpriv), "entries": overpriv}

        self.report["phases"]["misconfigurations"] = results

    # ------------------------------------------------------------------
    # PHASE 3 — IAM privilege escalation
    # ------------------------------------------------------------------
    def phase3_iam_privesc(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 3] IAM PRIVILEGE ESCALATION{Colors.RESET}")
        results = {}

        sts = self._client("sts")
        try:
            ident = sts.get_caller_identity()
            print(f"    Current identity: {ident.get('Arn','?')}")
        except Exception as e:
            print(f"    {Colors.YELLOW}{e}{Colors.RESET}")

        iam = self._client("iam")
        privesc_perms = [
            "iam:CreateAccessKey", "iam:CreateLoginProfile",
            "iam:AttachUserPolicy", "iam:PutUserPolicy",
            "iam:AddUserToGroup", "sts:AssumeRole",
        ]
        found = []
        for u in iam.list_users().get("Users", []):
            name = u["UserName"]
            try:
                for pname in iam.list_user_policies(UserName=name).get("PolicyNames", []):
                    doc = iam.get_user_policy(UserName=name, PolicyName=pname)
                    pd = doc.get("PolicyDocument", {})
                    if isinstance(pd, dict):
                        for st in pd.get("Statement", []):
                            actions = st.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            for a in actions:
                                if a in privesc_perms or a == "*":
                                    found.append(f"{name}:{a}")
                                    print(f"    {Colors.RED}[+] ESCALATION: {name} has {a}{Colors.RESET}")
            except ClientError:
                pass
        results["escalation_perms"] = {"count": len(found), "entries": found}

        # Live test: attach admin policy to dev-user
        print(f"\n  [TEST] Attaching AdministratorAccess to dev-user...")
        try:
            iam.attach_user_policy(
                UserName="dev-user",
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )
            print(f"    {Colors.RED}[+] ESCALATION CONFIRMED!{Colors.RESET}")
            results["escalation_confirmed"] = {"hit": True}
        except ClientError as e:
            print(f"    {Colors.YELLOW}[-] blocked: {e}{Colors.RESET}")
            results["escalation_confirmed"] = {"hit": False, "error": str(e)}

        self.report["phases"]["iam_privesc"] = results

    # ------------------------------------------------------------------
    # PHASE 4 — Metadata service
    # ------------------------------------------------------------------
    def phase4_metadata(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 4] METADATA SERVICE (IMDS){Colors.RESET}")
        print(f"    {Colors.YELLOW}LocalStack does not emulate EC2 IMDS natively.{Colors.RESET}")
        print(f"    In real AWS: IMDSv1 = http://169.254.169.254/latest/meta-data/")
        self.report["phases"]["metadata"] = {
            "note": "LocalStack no IMDS support. Real AWS uses IMDSv1/v2.",
            "imds_v1_url": "http://169.254.169.254/latest/meta-data/",
            "imds_v2_url": "PUT http://169.254.169.254/latest/api/token",
        }

    # ------------------------------------------------------------------
    # PHASE 5 — CIS compliance
    # ------------------------------------------------------------------
    def phase5_compliance(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 5] CIS COMPLIANCE{Colors.RESET}")
        results = {}

        # CIS 1.1 — Root MFA
        iam = self._client("iam")
        try:
            summary = iam.get_account_summary().get("SummaryMap", {})
            mfa = summary.get("AccountMFAEnabled", 0)
            status = "PASS" if mfa == 1 else "FAIL"
            color = Colors.GREEN if mfa == 1 else Colors.RED
            print(f"    [{color}CIS 1.1 Root MFA: {status}{Colors.RESET}")
            results["cis_1_1_root_mfa"] = {"status": status}
        except Exception as e:
            results["cis_1_1_root_mfa"] = {"error": str(e)}

        # CIS 2.1 — Password policy
        try:
            pw = iam.get_account_password_policy().get("PasswordPolicy", {})
            min_len = pw.get("MinimumPasswordLength", 0)
            status = "PASS" if min_len >= 14 else "FAIL"
            color = Colors.GREEN if min_len >= 14 else Colors.RED
            print(f"    [{color}CIS 2.1 Password length >= 14: {status} (len={min_len}){Colors.RESET}")
            results["cis_2_1_password_policy"] = {"status": status, "length": min_len}
        except ClientError:
            print(f"    {Colors.RED}CIS 2.1 Password policy: FAIL (none set){Colors.RESET}")
            results["cis_2_1_password_policy"] = {"status": "FAIL", "reason": "no policy"}

        # CIS 3.1.2 — S3 public access block
        s3 = self._client("s3")
        public = 0
        for b in s3.list_buckets().get("Buckets", []):
            try:
                s3.get_public_access_block(Bucket=b["Name"])
            except ClientError:
                public += 1
        status = "PASS" if public == 0 else "FAIL"
        color = Colors.GREEN if public == 0 else Colors.RED
        print(f"    [{color}CIS 3.1.2 S3 public access block: {status} ({public} public){Colors.RESET}")
        results["cis_3_1_2_s3_public"] = {"status": status, "public": public}

        # CIS 6.1 — Security groups
        ec2 = self._client("ec2")
        open_count = 0
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                for rng in perm.get("IpRanges", []):
                    if rng.get("CidrIp") == "0.0.0.0/0":
                        open_count += 1
        status = "PASS" if open_count == 0 else "FAIL"
        color = Colors.GREEN if open_count == 0 else Colors.RED
        print(f"    [{color}CIS 6.1 No 0.0.0.0/0 ingress: {status} ({open_count} open){Colors.RESET}")
        results["cis_6_1_sg"] = {"status": status, "open": open_count}

        self.report["phases"]["compliance"] = results

    # ------------------------------------------------------------------
    # PHASE 6 — Report
    # ------------------------------------------------------------------
    def _collect_confirmed(self):
        confirmed = []
        for phase, data in self.report["phases"].items():
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, dict):
                        if (v.get("hit")
                                or v.get("count", 0) > 0
                                or v.get("status") == "FAIL"):
                            confirmed.append(f"{phase}.{k}")
        return confirmed

    def phase6_report(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 6] EXPLOITATION SUMMARY{Colors.RESET}")
        confirmed = self._collect_confirmed()
        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/cloud_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    {Colors.GREEN}[OK] JSON: {json_path}{Colors.RESET}")

        html_path = f"{REPORTS_DIR}/cloud_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    {Colors.GREEN}[OK] HTML: {html_path}{Colors.RESET}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:2500]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Cloud Security Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>Cloud Security Assessment Report</h1>
<p><b>Endpoint:</b> {self.endpoint}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p>Confirmed: {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print("  Cloud Security Assessment Toolkit - Project #49")
        print("=" * 64)
        print(f"[+] Endpoint: {self.endpoint}")
        self.phase1_enumeration()
        self.phase2_misconfigurations()
        self.phase3_iam_privesc()
        self.phase4_metadata()
        self.phase5_compliance()
        self.phase6_report()

def main():
    ap = argparse.ArgumentParser(description="Cloud Security Assessment Toolkit")
    ap.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    ap.add_argument("--region", default=DEFAULT_REGION)
    args = ap.parse_args()
    CloudToolkit(args.endpoint, args.region).run_all()

if __name__ == "__main__":
    main()
