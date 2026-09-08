"""
OS Fingerprinting Database
Project #11: Network Scanning & OS Detection
"""

# OS fingerprint signatures
OS_SIGNATURES = {
    'Linux': {
        'ttl': 64,
        'window': 5840,
        'options': 'MSS, SACK',
        'description': 'Linux kernel 2.4+, 3.x, 4.x, 5.x'
    },
    'Linux (older)': {
        'ttl': 64,
        'window': 5792,
        'options': 'MSS, SACK',
        'description': 'Linux kernel 2.2.x'
    },
    'Windows 10/11': {
        'ttl': 128,
        'window': 65535,
        'options': 'NOP, MSS',
        'description': 'Windows 10/11, Server 2016/2019/2022'
    },
    'Windows 8/Server 2012': {
        'ttl': 128,
        'window': 8192,
        'options': 'NOP, MSS',
        'description': 'Windows 8/8.1, Server 2012'
    },
    'Windows 7/Server 2008': {
        'ttl': 128,
        'window': 8192,
        'options': 'NOP, MSS',
        'description': 'Windows 7, Server 2008'
    },
    'Windows XP/2003': {
        'ttl': 128,
        'window': 65535,
        'options': 'NOP, MSS',
        'description': 'Windows XP, Server 2003 (old)'
    },
    'Cisco IOS': {
        'ttl': 255,
        'window': 4128,
        'options': 'MSS',
        'description': 'Cisco IOS routers/switches'
    },
    'Cisco ASA': {
        'ttl': 255,
        'window': 8192,
        'options': 'MSS',
        'description': 'Cisco ASA firewall'
    },
    'OpenBSD': {
        'ttl': 64,
        'window': 16384,
        'options': 'MSS, SACK',
        'description': 'OpenBSD operating system'
    },
    'FreeBSD': {
        'ttl': 64,
        'window': 65535,
        'options': 'MSS, SACK',
        'description': 'FreeBSD operating system'
    },
    'macOS': {
        'ttl': 64,
        'window': 65535,
        'options': 'MSS, SACK, WSCALE',
        'description': 'Apple macOS (Darwin)'
    },
    'Solaris': {
        'ttl': 255,
        'window': 32768,
        'options': 'MSS, SACK',
        'description': 'Oracle Solaris'
    },
    'AIX': {
        'ttl': 255,
        'window': 16384,
        'options': 'MSS, SACK',
        'description': 'IBM AIX'
    },
    'HP-UX': {
        'ttl': 255,
        'window': 32768,
        'options': 'MSS',
        'description': 'HP-UX'
    },
    'Android': {
        'ttl': 64,
        'window': 65535,
        'options': 'MSS, SACK',
        'description': 'Android mobile OS'
    },
    'iOS': {
        'ttl': 64,
        'window': 65535,
        'options': 'MSS, SACK',
        'description': 'Apple iOS'
    },
    'Network Device': {
        'ttl': 255,
        'window': 4128,
        'options': 'MSS',
        'description': 'Generic network device'
    },
    'Unknown': {
        'ttl': None,
        'window': None,
        'options': None,
        'description': 'Unknown operating system'
    }
}

# Service port mapping
SERVICE_PORTS = {
    20: 'FTP-data',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPC',
    135: 'MSRPC',
    139: 'NetBIOS-SSN',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'Microsoft-DS',
    465: 'SMTPS',
    587: 'SMTP',
    993: 'IMAPS',
    995: 'POP3S',
    1080: 'SOCKS',
    1433: 'MSSQL',
    1521: 'Oracle',
    1723: 'PPTP',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}

def identify_os(ttl, window_size=0, options=''):
    """
    Identify operating system based on TTL, window size, and options
    
    Args:
        ttl: TTL value from ICMP reply
        window_size: TCP window size
        options: TCP options string
    
    Returns:
        Tuple of (os_name, confidence)
    """
    # Normalize TTL
    if ttl <= 64:
        ttl_group = 64
    elif ttl <= 128:
        ttl_group = 128
    elif ttl <= 255:
        ttl_group = 255
    else:
        ttl_group = None
    
    # Check exact matches first
    best_match = None
    best_score = 0
    
    for os_name, signature in OS_SIGNATURES.items():
        score = 0
        sig_ttl = signature.get('ttl')
        sig_window = signature.get('window')
        
        # TTL match (weighted heavily)
        if ttl_group and sig_ttl:
            if ttl_group == sig_ttl:
                score += 40
            elif abs(ttl - sig_ttl) <= 5:
                score += 20
        
        # Window size match
        if window_size and sig_window:
            if abs(window_size - sig_window) <= 100:
                score += 30
            elif abs(window_size - sig_window) <= 500:
                score += 15
        
        # Options match (simplified)
        if options and signature.get('options'):
            match_count = sum(1 for opt in signature['options'].split(',') if opt.strip() in options)
            if match_count > 0:
                score += match_count * 10
        
        if score > best_score:
            best_score = score
            best_match = os_name
    
    # Determine confidence
    if best_score >= 70:
        confidence = 'HIGH'
    elif best_score >= 50:
        confidence = 'MEDIUM'
    elif best_score >= 30:
        confidence = 'LOW'
    else:
        best_match = 'Unknown'
        confidence = 'VERY LOW'
    
    return best_match, confidence, best_score

def get_service_name(port):
    """Get service name for a port"""
    return SERVICE_PORTS.get(port, 'Unknown')