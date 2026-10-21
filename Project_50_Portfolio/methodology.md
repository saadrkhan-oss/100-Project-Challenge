# Methodology — Attack Chain

> How I approach offensive security engagements, applied across 8 projects.

## Phase 1 — Reconnaissance

**Goal**: Map the attack surface without touching the target.

- Subdomain enumeration (passive + active)
- Port scanning (service discovery)
- Technology fingerprinting

## Phase 2 — Vulnerability Discovery

**Goal**: Identify classes of bugs in the target's attack surface.

### Web Vulnerabilities
- **Injection**: SSI, LDAP, NoSQL, XXE
- **Server-Side**: SSRF, deserialization
- **Client-Side**: XSS

### Cloud Vulnerabilities
- S3 public buckets
- IAM over-permissioning
- Open security groups

## Phase 3 — Exploitation

**Goal**: Prove impact with safe, legal PoCs.

For each vulnerability:
1. Build minimal PoC
2. Demonstrate impact (data read / RCE / priv esc)
3. Document with screenshots
4. Calculate CVSS score

## Phase 4 — Reporting

**Goal**: Communicate findings to stakeholders.

- Executive summary
- Technical details
- Remediation

## Phase 5 — Verification

**Goal**: Confirm the fix works.

- Re-run the exploit after patch
- Check for variants (bypass techniques)

---

## Applied Across Projects

### #42 — SSRF Basic
- **Class**: CWE-918: Server-Side Request Forgery
- **Severity**: HIGH (CVSS 8.1)
- **Findings**: 7
- **Remediation**: Whitelist URLs, block private IPs, disable dangerous protocols

### #43 — XXE Advanced
- **Class**: CWE-611: Improper Restriction of XML External Entity Reference
- **Severity**: CRITICAL (CVSS 9.1)
- **Findings**: 5
- **Remediation**: Disable external entities, use defusedxml, disable DTDs

### #44 — SSI Injection
- **Class**: CWE-94: Code Injection via SSI
- **Severity**: CRITICAL (CVSS 9.8)
- **Findings**: 10
- **Remediation**: Disable SSI, use IncludesNOEXEC, sanitize user input

### #45 — LDAP Injection
- **Class**: CWE-90: LDAP Injection
- **Severity**: CRITICAL (CVSS 9.0)
- **Findings**: 12
- **Remediation**: Parameterized LDAP queries, escape special chars, whitelist input

### #46 — NoSQL Injection
- **Class**: CWE-943: Improper Neutralization of NoSQL Operators
- **Severity**: CRITICAL (CVSS 9.1)
- **Findings**: 19
- **Remediation**: Validate input types, reject $-prefixed keys, use schema validation

### #47 — SSRF Advanced (Blind + OOB)
- **Class**: CWE-918: SSRF with Blind OOB exfiltration
- **Severity**: CRITICAL (CVSS 9.3)
- **Findings**: 17
- **Remediation**: Disable IPv6, block cloud metadata IPs, egress firewall

### #48 — Deserialization (Java + Python)
- **Class**: CWE-502: Deserialization of Untrusted Data
- **Severity**: CRITICAL (CVSS 9.8)
- **Findings**: 7
- **Remediation**: Never deserialize untrusted data, use JSON, class whitelisting

### #49 — Cloud Security (AWS/LocalStack)
- **Class**: CWE-16: Cloud Misconfiguration (S3/IAM/SG)
- **Severity**: CRITICAL (CVSS 9.5)
- **Findings**: 13
- **Remediation**: Block public S3, enforce least-privilege IAM, restrict security groups
