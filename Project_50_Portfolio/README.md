# Bug Bounty Portfolio — Saad

> **8 offensive security projects** • **90 confirmed findings** • **100% legal targets**

Generated 2026-10-21

## At a Glance

| Metric | Value |
|---|---|
| Projects | 8 |
| Confirmed Findings | 90 |
| Categories | 3 |
| Critical Severity | 83 findings |
| High Severity | 7 findings |

## Vulnerability Coverage

| # | Project | Category | Severity | Findings |
|---|---|---|---|---|
| #42 | SSRF Basic | Web Exploitation | **HIGH** | 7 |
| #43 | XXE Advanced | Web Exploitation | **CRITICAL** | 5 |
| #44 | SSI Injection | Web Exploitation | **CRITICAL** | 10 |
| #45 | LDAP Injection | Web Exploitation | **CRITICAL** | 12 |
| #46 | NoSQL Injection | Web Exploitation | **CRITICAL** | 19 |
| #47 | SSRF Advanced (Blind + OOB) | Web Exploitation | **CRITICAL** | 17 |
| #48 | Deserialization (Java + Python) | Advanced Attacks | **CRITICAL** | 7 |
| #49 | Cloud Security (AWS/LocalStack) | Cloud Security | **CRITICAL** | 13 |

## Tools Built

- **#42 SSRF Basic** -> `ssrf_toolkit.py`
- **#43 XXE Advanced** -> `xxe_toolkit.py`
- **#44 SSI Injection** -> `ssi_toolkit.py`
- **#45 LDAP Injection** -> `ldap_toolkit.py`
- **#46 NoSQL Injection** -> `nosql_toolkit.py`
- **#47 SSRF Advanced (Blind + OOB)** -> `ssrf_advanced_toolkit.py`
- **#48 Deserialization (Java + Python)** -> `deserialization_toolkit.py`
- **#49 Cloud Security (AWS/LocalStack)** -> `cloud_toolkit.py`

## Quick Start

Each project has a self-contained lab:

```bash
# Example: SSRF (Project #42)
cd Project_42_SSRF_Toolkit
python vulnerable_app.py &      # start target
python ssrf_toolkit.py -t http://127.0.0.1:8000/fetch
```

## Legal

All testing performed on:
- Locally hosted vulnerable apps (Flask/Java)
- LocalStack (AWS emulator)
- Intentionally vulnerable labs

**No production systems were harmed.**

---

*Built with Python, boto3, ysoserial. Tested on WSL2/Ubuntu.*