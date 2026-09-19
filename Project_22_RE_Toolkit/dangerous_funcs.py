"""
Dangerous Function Database
Project #22: Binary Reverse Engineering Toolkit
"""

DANGEROUS_FUNCTIONS = {
    # Buffer overflow risks
    'strcpy':  {'risk': 'CRITICAL', 'category': 'Buffer Overflow', 'desc': 'No bounds check — classic overflow'},
    'strcat':  {'risk': 'CRITICAL', 'category': 'Buffer Overflow', 'desc': 'No bounds check on append'},
    'sprintf': {'risk': 'HIGH',     'category': 'Buffer Overflow', 'desc': 'No bounds check on format'},
    'gets':    {'risk': 'CRITICAL', 'category': 'Buffer Overflow', 'desc': 'No bounds check — deprecated'},
    'scanf':   {'risk': 'HIGH',     'category': 'Buffer Overflow', 'desc': 'Without width limit'},
    'memcpy':  {'risk': 'HIGH',     'category': 'Buffer Overflow', 'desc': 'Trusts size parameter'},
    'memmove': {'risk': 'MEDIUM',   'category': 'Buffer Overflow', 'desc': 'Trusts size parameter'},
    'strncpy': {'risk': 'MEDIUM',   'category': 'Buffer Overflow', 'desc': 'May miss null terminator'},
    'vsprintf':{'risk': 'HIGH',     'category': 'Buffer Overflow', 'desc': 'No bounds check'},

    # Command injection risks
    'system':  {'risk': 'CRITICAL', 'category': 'Command Injection', 'desc': 'Executes shell command'},
    'popen':   {'risk': 'CRITICAL', 'category': 'Command Injection', 'desc': 'Opens pipe to shell'},
    'exec':    {'risk': 'HIGH',     'category': 'Command Injection', 'desc': 'Replaces process'},
    'execl':   {'risk': 'HIGH',     'category': 'Command Injection', 'desc': 'Exec family'},
    'execlp':  {'risk': 'HIGH',     'category': 'Command Injection', 'desc': 'Exec family'},
    'execv':   {'risk': 'HIGH',     'category': 'Command Injection', 'desc': 'Exec family'},
    'execvp':  {'risk': 'HIGH',     'category': 'Command Injection', 'desc': 'Exec family'},

    # Format string risks
    'printf':  {'risk': 'HIGH',     'category': 'Format String', 'desc': 'If format is user-controlled'},
    'fprintf': {'risk': 'HIGH',     'category': 'Format String', 'desc': 'If format is user-controlled'},
    'syslog':  {'risk': 'MEDIUM',   'category': 'Format String', 'desc': 'Format string risk'},
    'vprintf': {'risk': 'HIGH',     'category': 'Format String', 'desc': 'Format string risk'},

    # Memory management
    'malloc':  {'risk': 'MEDIUM',   'category': 'Memory', 'desc': 'Integer overflow risk in size calc'},
    'calloc':  {'risk': 'MEDIUM',   'category': 'Memory', 'desc': 'Integer overflow risk'},
    'realloc': {'risk': 'MEDIUM',   'category': 'Memory', 'desc': 'Integer overflow risk'},
    'free':    {'risk': 'HIGH',     'category': 'Memory', 'desc': 'Use-after-free / double-free risk'},

    # File operations
    'fopen':   {'risk': 'LOW',      'category': 'File', 'desc': 'Path traversal possible'},
    'open':    {'risk': 'LOW',      'category': 'File', 'desc': 'Path traversal possible'},
    'access':  {'risk': 'LOW',      'category': 'File', 'desc': 'TOCTOU race condition'},

    # Cryptographic weaknesses
    'rand':    {'risk': 'HIGH',     'category': 'Crypto', 'desc': 'Not cryptographically secure'},
    'srand':   {'risk': 'HIGH',     'category': 'Crypto', 'desc': 'Weak seeding'},
    'md5':     {'risk': 'HIGH',     'category': 'Crypto', 'desc': 'Broken hash'},
    'sha1':    {'risk': 'MEDIUM',   'category': 'Crypto', 'desc': 'Deprecated hash'},
    'des':     {'risk': 'HIGH',     'category': 'Crypto', 'desc': 'Broken cipher'},
    'rc4':     {'risk': 'HIGH',     'category': 'Crypto', 'desc': 'Broken cipher'},

    # Other
    'atoi':    {'risk': 'LOW',      'category': 'Parsing', 'desc': 'No error handling'},
    'atof':    {'risk': 'LOW',      'category': 'Parsing', 'desc': 'No error handling'},
    'setuid':  {'risk': 'HIGH',     'category': 'Privilege', 'desc': 'Privilege escalation risk'},
    'setgid':  {'risk': 'HIGH',     'category': 'Privilege', 'desc': 'Privilege escalation risk'},
}

# Interesting strings to look for
INTERESTING_KEYWORDS = [
    'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key',
    'key', 'credential', 'auth', 'login', 'admin', 'root', 'debug',
    'flag', 'ctf', 'backdoor', 'shell', 'cmd', 'exec', 'system',
    'http://', 'https://', 'ftp://', 'ssh://', 'mysql://',
    '/bin/sh', '/bin/bash', 'cmd.exe', 'powershell',
    'BEGIN RSA', 'BEGIN PRIVATE', 'BEGIN CERTIFICATE',
    'AKIA',  # AWS key prefix
    'sk_live_', 'pk_live_',  # Stripe keys
    'ghp_', 'gho_',  # GitHub tokens
]

# Section names of interest
KEY_SECTIONS = ['.text', '.data', '.bss', '.rodata', '.plt', '.got',
                '.init', '.fini', '.comment', '.note', '.dynsym',
                '.rela.text', '.init_array', '.fini_array']