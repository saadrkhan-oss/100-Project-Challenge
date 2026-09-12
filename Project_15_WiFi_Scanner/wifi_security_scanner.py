#!/usr/bin/env python3
"""
WiFi Security Auditor
Project #15: Wireless Network Security Scanner
"""

import subprocess
import sys
import re
import time
import platform
import argparse
from datetime import datetime

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class WiFiSecurityScanner:
    def __init__(self, output_file="wifi_security_report.txt", verbose=False):
        """
        Initialize the WiFi Security Scanner

        Args:
            output_file: Output file name
            verbose: Enable verbose output
        """
        self.output_file = output_file
        self.verbose = verbose
        self.networks = []
        self.current_connection = None

        # Security levels and scores
        self.security_levels = {
            'Open': {'risk': 'CRITICAL', 'score': 0, 'color': Colors.RED, 'grade': 'F'},
            'WEP': {'risk': 'HIGH', 'score': 20, 'color': Colors.RED, 'grade': 'F'},
            'WPA': {'risk': 'MEDIUM', 'score': 50, 'color': Colors.YELLOW, 'grade': 'D'},
            'WPA2-Personal': {'risk': 'LOW', 'score': 80, 'color': Colors.GREEN, 'grade': 'B'},
            'WPA2-Enterprise': {'risk': 'LOW', 'score': 90, 'color': Colors.GREEN, 'grade': 'A'},
            'WPA3-Personal': {'risk': 'VERY LOW', 'score': 100, 'color': Colors.GREEN, 'grade': 'A+'},
            'WPA3-Enterprise': {'risk': 'VERY LOW', 'score': 100, 'color': Colors.GREEN, 'grade': 'A+'},
            'WPA2': {'risk': 'LOW', 'score': 80, 'color': Colors.GREEN, 'grade': 'B'},
            'WPA3': {'risk': 'VERY LOW', 'score': 100, 'color': Colors.GREEN, 'grade': 'A+'},
        }

        # Channel ranges
        self.channel_ranges = {
            '2.4GHz': list(range(1, 15)),
            '5GHz': [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                     116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
        }

    # ------------------------------------------------------------------ #
    # PLATFORM DETECTION
    # ------------------------------------------------------------------ #
    def check_platform(self):
        """Check if running on supported platform"""
        system = platform.system()
        if system == 'Windows':
            return 'windows'
        elif system == 'Linux':
            return 'linux'
        elif system == 'Darwin':
            return 'macos'
        else:
            print(f"{Colors.RED}[!] Unsupported platform: {system}{Colors.RESET}")
            return None

    # ------------------------------------------------------------------ #
    # WINDOWS SCANNING
    # ------------------------------------------------------------------ #
    def scan_windows(self):
        """Scan WiFi networks on Windows using netsh"""
        print(f"{Colors.BOLD}[*] Scanning WiFi networks (Windows)...{Colors.RESET}")

        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                encoding='utf-8',
                errors='ignore'
            )

            if result.returncode != 0:
                print(f"{Colors.RED}[!] Error running netsh: {result.stderr}{Colors.RESET}")
                return []

            return self.parse_windows_output(result.stdout)

        except FileNotFoundError:
            print(f"{Colors.RED}[!] netsh not found. Are you on Windows?{Colors.RESET}")
            return []
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}[!] Scan timed out{Colors.RESET}")
            return []
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {str(e)[:60]}{Colors.RESET}")
            return []

    def parse_windows_output(self, output):
        """Parse netsh output"""
        networks = []
        current_network = None

        lines = output.split('\n')
        for line in lines:
            line = line.strip()

            # SSID line
            ssid_match = re.match(r'^SSID\s+\d+\s*:\s*(.*)$', line)
            if ssid_match:
                if current_network:
                    networks.append(current_network)
                ssid = ssid_match.group(1).strip()
                current_network = {
                    'ssid': ssid if ssid else '(Hidden)',
                    'bssid': None,
                    'signal': None,
                    'channel': None,
                    'encryption': None,
                    'authentication': None,
                    'cipher': None,
                    'network_type': None,
                    'band': None,
                }
                continue

            if not current_network:
                continue

            # Network type
            type_match = re.match(r'^Network type\s*:\s*(.*)$', line)
            if type_match:
                current_network['network_type'] = type_match.group(1).strip()
                continue

            # Authentication
            auth_match = re.match(r'^Authentication\s*:\s*(.*)$', line)
            if auth_match:
                current_network['authentication'] = auth_match.group(1).strip()
                continue

            # Encryption (cipher)
            enc_match = re.match(r'^Encryption\s*:\s*(.*)$', line)
            if enc_match:
                current_network['cipher'] = enc_match.group(1).strip()
                continue

            # BSSID
            bssid_match = re.match(r'^BSSID\s+\d+\s*:\s*(.*)$', line)
            if bssid_match:
                current_network['bssid'] = bssid_match.group(1).strip()
                continue

            # Signal
            signal_match = re.match(r'^Signal\s*:\s*(\d+)%', line)
            if signal_match:
                current_network['signal'] = int(signal_match.group(1))
                continue

            # Channel
            channel_match = re.match(r'^Channel\s*:\s*(\d+)', line)
            if channel_match:
                current_network['channel'] = int(channel_match.group(1))
                continue

        if current_network:
            networks.append(current_network)

        # Process networks
        processed = []
        for net in networks:
            # Determine encryption type
            auth = (net.get('authentication') or '').upper()
            cipher = (net.get('cipher') or '').upper()

            if 'WPA3' in auth:
                if 'ENT' in auth or 'ENTERPRISE' in auth:
                    enc = 'WPA3-Enterprise'
                else:
                    enc = 'WPA3-Personal'
            elif 'WPA2' in auth:
                if 'ENT' in auth or 'ENTERPRISE' in auth:
                    enc = 'WPA2-Enterprise'
                else:
                    enc = 'WPA2-Personal'
            elif 'WPA' in auth:
                enc = 'WPA'
            elif 'WEP' in auth:
                enc = 'WEP'
            elif 'OPEN' in auth:
                enc = 'Open'
            else:
                enc = 'Unknown'

            # Determine band
            channel = net.get('channel')
            if channel:
                if channel <= 14:
                    band = '2.4GHz'
                else:
                    band = '5GHz'
            else:
                band = 'Unknown'

            net['encryption'] = enc
            net['band'] = band
            processed.append(net)

        return processed

    # ------------------------------------------------------------------ #
    # LINUX SCANNING
    # ------------------------------------------------------------------ #
    def scan_linux(self):
        """Scan WiFi networks on Linux using iwlist or nmcli"""
        print(f"{Colors.BOLD}[*] Scanning WiFi networks (Linux)...{Colors.RESET}")

        # Try nmcli first (usually available)
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'SSID,BSSID,SIGNAL,CHAN,SECURITY', 'device', 'wifi', 'list'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                encoding='utf-8',
                errors='ignore'
            )

            if result.returncode == 0 and result.stdout.strip():
                return self.parse_nmcli_output(result.stdout)
        except FileNotFoundError:
            pass

        # Try iwlist
        try:
            # Get wireless interface
            iface_result = subprocess.run(
                ['iwconfig'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                encoding='utf-8',
                errors='ignore'
            )

            iface = None
            for line in iface_result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    iface = line.split()[0]
                    break

            if not iface:
                print(f"{Colors.RED}[!] No wireless interface found{Colors.RESET}")
                return []

            result = subprocess.run(
                ['sudo', 'iwlist', iface, 'scan'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                encoding='utf-8',
                errors='ignore'
            )

            return self.parse_iwlist_output(result.stdout)

        except Exception as e:
            print(f"{Colors.RED}[!] Error on Linux: {str(e)[:60]}{Colors.RESET}")
            return []

    def parse_nmcli_output(self, output):
        """Parse nmcli output"""
        networks = []
        for line in output.strip().split('\n'):
            parts = line.split(':')
            if len(parts) < 5:
                continue

            ssid = parts[0] if parts[0] else '(Hidden)'
            bssid = parts[1]
            signal = int(parts[2]) if parts[2].isdigit() else None
            channel = int(parts[3]) if parts[3].isdigit() else None
            security = parts[4]

            # Determine encryption
            sec_upper = security.upper()
            if 'WPA3' in sec_upper:
                enc = 'WPA3-Personal'
            elif 'WPA2' in sec_upper:
                enc = 'WPA2-Personal'
            elif 'WPA' in sec_upper:
                enc = 'WPA'
            elif 'WEP' in sec_upper:
                enc = 'WEP'
            elif 'OPEN' in sec_upper or security == '' or security == '--':
                enc = 'Open'
            else:
                enc = 'Unknown'

            # Band
            if channel:
                band = '2.4GHz' if channel <= 14 else '5GHz'
            else:
                band = 'Unknown'

            networks.append({
                'ssid': ssid,
                'bssid': bssid,
                'signal': signal,
                'channel': channel,
                'encryption': enc,
                'authentication': security,
                'cipher': None,
                'network_type': 'Infrastructure',
                'band': band,
            })

        return networks

    def parse_iwlist_output(self, output):
        """Parse iwlist output"""
        networks = []
        current = None

        for line in output.split('\n'):
            if 'Cell' in line and 'Address:' in line:
                if current:
                    networks.append(current)
                bssid = line.split('Address:')[1].strip()
                current = {
                    'ssid': '(Hidden)', 'bssid': bssid, 'signal': None,
                    'channel': None, 'encryption': 'Unknown',
                    'authentication': '', 'cipher': None,
                    'network_type': 'Infrastructure', 'band': 'Unknown'
                }
            elif current:
                if 'ESSID:' in line:
                    ssid = line.split('ESSID:')[1].strip().strip('"')
                    current['ssid'] = ssid if ssid else '(Hidden)'
                elif 'Signal level=' in line:
                    m = re.search(r'Signal level=(-?\d+)', line)
                    if m:
                        # Convert dBm to percentage
                        dbm = int(m.group(1))
                        percent = max(0, min(100, 2 * (dbm + 100)))
                        current['signal'] = percent
                elif 'Channel:' in line:
                    m = re.search(r'Channel:(\d+)', line)
                    if m:
                        ch = int(m.group(1))
                        current['channel'] = ch
                        current['band'] = '2.4GHz' if ch <= 14 else '5GHz'
                elif 'Encryption key:on' in line:
                    current['encryption'] = 'WEP'
                elif 'Encryption key:off' in line:
                    current['encryption'] = 'Open'
                elif 'IE: IEEE 802.11i/WPA2' in line:
                    current['encryption'] = 'WPA2-Personal'
                elif 'IE: WPA Version 1' in line:
                    current['encryption'] = 'WPA'
                elif 'WPA3' in line:
                    current['encryption'] = 'WPA3-Personal'

        if current:
            networks.append(current)

        return networks

    # ------------------------------------------------------------------ #
    # SCORING / ANALYSIS
    # ------------------------------------------------------------------ #
    def calculate_score(self, encryption):
        """Calculate security score for encryption type"""
        for key, data in self.security_levels.items():
            if key.lower() in encryption.lower():
                return data['score'], data['risk'], data['grade'], data['color']

        # Default
        return 10, 'UNKNOWN', '?', Colors.YELLOW

    def analyze_networks(self):
        """Analyze and score networks"""
        for net in self.networks:
            score, risk, grade, color = self.calculate_score(net['encryption'])
            net['score'] = score
            net['risk'] = risk
            net['grade'] = grade
            net['color'] = color

        # Sort by signal strength (descending)
        self.networks.sort(key=lambda x: x.get('signal') or 0, reverse=True)

    # ------------------------------------------------------------------ #
    # DISPLAY
    # ------------------------------------------------------------------ #
    def print_networks(self):
        """Print discovered networks"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] NETWORK DISCOVERY:{Colors.RESET}")
        print(f"    Total networks found: {len(self.networks)}\n")

        if not self.networks:
            print(f"{Colors.YELLOW}[!] No networks found. Make sure WiFi is enabled.{Colors.RESET}")
            return

        print(f"{Colors.BOLD}{Colors.BLUE}[🔍] NETWORK DETAILS:{Colors.RESET}\n")

        for i, net in enumerate(self.networks, 1):
            color = net.get('color', Colors.WHITE)
            signal = net.get('signal')
            signal_str = f"{signal}%" if signal is not None else "N/A"
            channel = net.get('channel')
            channel_str = f"{channel} ({net.get('band', '?')})" if channel else "N/A"

            print(f"    {Colors.BOLD}{i}. SSID: {net['ssid']}{Colors.RESET}")
            print(f"       BSSID: {net.get('bssid', 'N/A')}")
            print(f"       Signal: {signal_str}")
            print(f"       Channel: {channel_str}")
            print(f"       Encryption: {color}{net['encryption']}{Colors.RESET}")
            print(f"       Security Score: {color}{net['score']}/100 ({net['grade']}){Colors.RESET}")
            print(f"       Risk: {color}{net['risk']}{Colors.RESET}")

            if net['risk'] in ['CRITICAL', 'HIGH']:
                print(f"       {Colors.RED}⚠️  INSECURE NETWORK{Colors.RESET}")
            print()

    def print_summary(self):
        """Print security summary"""
        print(f"{Colors.BOLD}{Colors.BLUE}[📊] SECURITY SUMMARY:{Colors.RESET}")

        counts = {
            'Open': 0, 'WEP': 0, 'WPA': 0, 'WPA2': 0, 'WPA3': 0, 'Unknown': 0
        }

        for net in self.networks:
            enc = net['encryption']
            if 'WPA3' in enc:
                counts['WPA3'] += 1
            elif 'WPA2' in enc:
                counts['WPA2'] += 1
            elif 'WPA' in enc:
                counts['WPA'] += 1
            elif 'WEP' in enc:
                counts['WEP'] += 1
            elif 'Open' in enc:
                counts['Open'] += 1
            else:
                counts['Unknown'] += 1

        print(f"    Total networks: {len(self.networks)}")

        if counts['Open'] > 0:
            print(f"    {Colors.RED}Open networks: {counts['Open']} (CRITICAL){Colors.RESET}")
        else:
            print(f"    Open networks: 0")

        if counts['WEP'] > 0:
            print(f"    {Colors.RED}WEP networks: {counts['WEP']} (HIGH){Colors.RESET}")
        else:
            print(f"    WEP networks: 0")

        if counts['WPA'] > 0:
            print(f"    {Colors.YELLOW}WPA networks: {counts['WPA']} (MEDIUM){Colors.RESET}")
        else:
            print(f"    WPA networks: 0")

        if counts['WPA2'] > 0:
            print(f"    {Colors.GREEN}WPA2 networks: {counts['WPA2']} (LOW){Colors.RESET}")
        else:
            print(f"    WPA2 networks: 0")

        if counts['WPA3'] > 0:
            print(f"    {Colors.GREEN}WPA3 networks: {counts['WPA3']} (VERY LOW){Colors.RESET}")
        else:
            print(f"    WPA3 networks: 0")

        # Critical findings
        critical = [n for n in self.networks if n['risk'] in ['CRITICAL', 'HIGH']]
        if critical:
            print(f"\n{Colors.BOLD}{Colors.RED}[⚠️] CRITICAL FINDINGS:{Colors.RESET}")
            for net in critical:
                if net['encryption'] == 'Open':
                    print(f"    {Colors.RED}• Open network \"{net['ssid']}\" detected (no encryption!){Colors.RESET}")
                elif net['encryption'] == 'WEP':
                    print(f"    {Colors.RED}• WEP network \"{net['ssid']}\" detected (easily cracked){Colors.RESET}")

    def print_recommendations(self):
        """Print security recommendations"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📋] RECOMMENDATIONS:{Colors.RESET}")

        recommendations = []
        has_open = any(n['encryption'] == 'Open' for n in self.networks)
        has_wep = any(n['encryption'] == 'WEP' for n in self.networks)
        has_wpa = any('WPA' in n['encryption'] and 'WPA2' not in n['encryption']
                     and 'WPA3' not in n['encryption'] for n in self.networks)
        has_wpa3 = any('WPA3' in n['encryption'] for n in self.networks)

        if has_open:
            recommendations.append("Avoid connecting to open networks (use VPN if required)")
        if has_wep:
            recommendations.append("Upgrade WEP routers to WPA2/WPA3 immediately")
        if has_wpa:
            recommendations.append("Upgrade WPA networks to WPA2 or WPA3")
        if not has_wpa3:
            recommendations.append("Consider WPA3 for maximum security")

        recommendations.append("Use a strong, unique WiFi password (16+ characters)")
        recommendations.append("Change default router admin credentials")
        recommendations.append("Keep router firmware up to date")
        recommendations.append("Disable WPS (WiFi Protected Setup) if not needed")
        recommendations.append("Use a VPN on public WiFi networks")

        for i, rec in enumerate(recommendations, 1):
            print(f"    {i}. {rec}")

    # ------------------------------------------------------------------ #
    # REPORT
    # ------------------------------------------------------------------ #
    def generate_report(self):
        """Generate detailed report file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("WIFI SECURITY AUDIT REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Scan Date:     {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"Platform:      {platform.system()} {platform.release()}\n")
            f.write(f"Networks:      {len(self.networks)}\n")
            f.write("=" * 80 + "\n\n")

            if not self.networks:
                f.write("No networks found.\n")
                return

            for i, net in enumerate(self.networks, 1):
                f.write(f"Network #{i}\n")
                f.write("-" * 50 + "\n")
                f.write(f"  SSID:           {net['ssid']}\n")
                f.write(f"  BSSID:          {net.get('bssid', 'N/A')}\n")
                f.write(f"  Signal:         {net.get('signal', 'N/A')}%\n")
                f.write(f"  Channel:        {net.get('channel', 'N/A')} ({net.get('band', '?')})\n")
                f.write(f"  Encryption:     {net['encryption']}\n")
                f.write(f"  Authentication: {net.get('authentication', 'N/A')}\n")
                f.write(f"  Security Score: {net['score']}/100 ({net['grade']})\n")
                f.write(f"  Risk Level:     {net['risk']}\n")
                if net['risk'] in ['CRITICAL', 'HIGH']:
                    f.write(f"  ⚠️  INSECURE NETWORK\n")
                f.write("\n")

            # Summary
            f.write("=" * 80 + "\n")
            f.write("SECURITY SUMMARY\n")
            f.write("=" * 80 + "\n")

            counts = {'Open': 0, 'WEP': 0, 'WPA': 0, 'WPA2': 0, 'WPA3': 0}
            for net in self.networks:
                enc = net['encryption']
                if 'WPA3' in enc:
                    counts['WPA3'] += 1
                elif 'WPA2' in enc:
                    counts['WPA2'] += 1
                elif 'WPA' in enc:
                    counts['WPA'] += 1
                elif 'WEP' in enc:
                    counts['WEP'] += 1
                elif 'Open' in enc:
                    counts['Open'] += 1

            for k, v in counts.items():
                f.write(f"  {k}: {v}\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("Generated by WiFi Security Auditor — Project #15\n")
            f.write("=" * 80 + "\n")

        print(f"\n{Colors.GREEN}[✓] Report saved to: {self.output_file}{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # MAIN
    # ------------------------------------------------------------------ #
    def scan(self):
        """Main scan method"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] WiFi Security Scanner{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Started: {datetime.now():%Y-%m-%d %H:%M:%S}{Colors.RESET}\n")

        start = time.time()

        # Detect platform and scan
        platform_name = self.check_platform()

        if platform_name == 'windows':
            self.networks = self.scan_windows()
        elif platform_name == 'linux':
            self.networks = self.scan_linux()
        else:
            print(f"{Colors.RED}[!] Unsupported platform{Colors.RESET}")
            return

        if not self.networks:
            print(f"{Colors.YELLOW}[!] No networks found.{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Make sure WiFi is enabled and you have permissions.{Colors.RESET}")
            self.generate_report()
            return

        # Analyze
        self.analyze_networks()

        # Display
        self.print_networks()
        self.print_summary()
        self.print_recommendations()

        # Save report
        self.generate_report()

        print(f"\n{Colors.GREEN}[✓] Scan completed in {time.time() - start:.2f} seconds{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="WiFi Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan nearby WiFi networks
  python wifi_security_scanner.py

  # Save to custom file
  python wifi_security_scanner.py -o my_report.txt

  # Verbose output
  python wifi_security_scanner.py -v
        """
    )

    parser.add_argument('-o', '--output', default='wifi_security_report.txt',
                       help='Output file name')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')

    args = parser.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    WIFI SECURITY SCANNER")
    print("    Project #15: Wireless Network Security Scanner")
    print("=" * 70 + f"{Colors.RESET}\n")

    scanner = WiFiSecurityScanner(
        output_file=args.output,
        verbose=args.verbose
    )
    scanner.scan()

if __name__ == "__main__":
    main()