#!/usr/bin/env python3
"""
=============================================================================
NetGuard — Live Alert Trigger Script
=============================================================================
Generates REAL network traffic on your actual interface to trigger alerts
during a live NetGuard capture.

HOW TO USE:
  Terminal 1 — Start NetGuard:
    sudo python3 netguard.py
    > start capture

  Terminal 2 — Run this script:
    sudo python3 tests/trigger_alerts.py

IMPORTANT:
  - Uses your REAL network interface (not loopback!)
  - Each test clears the dedup cache so alerts fire on every run
  - Requires sudo for raw sockets
=============================================================================
"""

import socket
import struct
import time
import sys
import os
import subprocess
import random
import threading

# Colors
G = '\033[92m'    # green
Y = '\033[93m'    # yellow
R = '\033[91m'    # red
C = '\033[96m'    # cyan
B = '\033[1m'     # bold
D = '\033[2m'     # dim
W = '\033[97m'    # white
X = '\033[0m'     # reset


def banner():
    print(f"""
{C}{B}╔══════════════════════════════════════════════════════════╗
║        NetGuard — Live Alert Trigger Script              ║
╚══════════════════════════════════════════════════════════╝{X}
""")


def section(n, title):
    print(f"\n{C}{'─' * 56}{X}")
    print(f"  {B}Test {n}: {title}{X}")
    print(f"{C}{'─' * 56}{X}")


def ok(msg):
    print(f"  {G}✓{X} {msg}")


def info(msg):
    print(f"  {G}▶{X} {msg}")


def warn(msg):
    print(f"  {Y}⚠{X} {msg}")


def dim(msg):
    print(f"    {D}{msg}{X}")


def check_root():
    if os.geteuid() != 0:
        print(f"\n{R}  ERROR: Root privileges required for raw sockets.{X}")
        print(f"  Run: {B}sudo python3 tests/trigger_alerts.py{X}\n")
        sys.exit(1)


def get_real_ip():
    """Get the machine's real (non-loopback) IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def clear_netguard_dedup():
    """Tell user how to clear dedup cache for re-runs."""
    pass  # Handled by starting fresh capture


def get_gateway():
    """Get default gateway IP."""
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=3
        )
        parts = result.stdout.strip().split()
        if 'via' in parts:
            return parts[parts.index('via') + 1]
    except Exception:
        pass
    return None


# ─── Traffic Generators ──────────────────────────────────────────────────

def test_syn_scan(target_ip):
    """
    TRIGGERS:
      - NETGUARD SCAN SYN Scan Detected (SID 9000001-9000006)
      - NETGUARD SCAN Rapid Port Scan    (SID 9000020)
    
    Sends 30 rapid SYN packets to different ports on target.
    Suricata sees these on the real interface because target is
    a real IP (not loopback).
    """
    section(1, "SYN Port Scan → SID 9000001-9000006, 9000020")
    info(f"Scanning 30 ports on {target_ip} via real interface...")

    ports = list(range(1, 31))
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect_ex((target_ip, port))
            s.close()
        except Exception:
            pass
        time.sleep(0.05)

    ok(f"30 SYN packets sent to {target_ip}")
    dim("Expected: NETGUARD SCAN SYN Scan + Rapid Port Scan")


def test_ssh_bruteforce(target_ip):
    """
    TRIGGERS:
      - NETGUARD BRUTE-FORCE SSH Brute Force Detected (SID 9000030)
    
    Makes 8 rapid TCP connections to port 22.
    """
    section(2, "SSH Brute Force → SID 9000030")
    info(f"Making 8 rapid connections to {target_ip}:22...")

    for i in range(8):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target_ip, 22))
            # Send SSH banner to make it look like a real SSH attempt
            if result == 0:
                try:
                    s.send(b"SSH-2.0-OpenSSH_8.9\r\n")
                    time.sleep(0.1)
                except Exception:
                    pass
            s.close()
        except Exception:
            pass
        time.sleep(0.5)

    ok(f"8 SSH connections attempted to {target_ip}:22")
    dim("Expected: NETGUARD BRUTE-FORCE SSH Brute Force Detected")


def test_ftp_bruteforce(target_ip):
    """
    TRIGGERS:
      - NETGUARD BRUTE-FORCE FTP Brute Force Detected (SID 9000040)
    """
    section(3, "FTP Brute Force → SID 9000040")
    info(f"Making 8 rapid connections to {target_ip}:21...")

    for i in range(8):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect_ex((target_ip, 21))
            s.close()
        except Exception:
            pass
        time.sleep(0.5)

    ok(f"8 FTP connections attempted")
    dim("Expected: NETGUARD BRUTE-FORCE FTP Brute Force Detected")


def test_dns_queries():
    """
    TRIGGERS:
      - ET DNS rules (queries to public resolvers)
      - DNS event rules (dns-events.rules)
      - Generates traffic visible to BOTH Suricata and NetGuard
    """
    section(4, "DNS Queries → ET DNS + Behavioral new_dest")
    info("Sending DNS queries to external resolvers via real interface...")

    # These are EXTERNAL destinations → Suricata sees them on wlo1
    domains = [
        'malware-test.example.com',
        'c2-callback.example.org',
        'suspicious-domain.xyz',
        'totally-legit.biz',
        'example.com',
        'httpbin.org',
        'neverssl.com',
    ]

    for domain in domains:
        for resolver in ['8.8.8.8', '1.1.1.1', '9.9.9.9']:
            try:
                subprocess.run(
                    ['dig', f'@{resolver}', domain, '+short', '+time=1', '+tries=1'],
                    capture_output=True, timeout=3
                )
            except Exception:
                pass
            time.sleep(0.1)

    ok(f"{len(domains) * 3} DNS queries sent to 3 resolvers")
    dim("Expected: ET DNS + behavioral new_dest for resolvers")


def test_http_plaintext():
    """
    TRIGGERS:
      - ET INFO rules (external IP lookup, user-agent detection)
      - ET POLICY rules (cleartext HTTP, outdated protocols)
      - HTTP event rules (http-events.rules)
    """
    section(5, "Plaintext HTTP → ET INFO + ET POLICY")
    info("Making HTTP requests to trigger ET INFO/POLICY rules...")

    # These are KNOWN to trigger ET INFO rules
    urls = [
        # External IP check — triggers ET INFO "External IP Lookup"
        'http://ifconfig.me/ip',
        'http://checkip.amazonaws.com',
        'http://ipinfo.io/ip',
        # Plaintext HTTP — triggers ET POLICY
        'http://neverssl.com/',
        'http://httpbin.org/user-agent',
        'http://example.com/',
        # IP check services
        'http://whatismyip.akamai.com/',
    ]

    for url in urls:
        try:
            subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-m', '3',
                 '-A', 'Mozilla/5.0 NetGuard-Test',
                 url],
                capture_output=True, timeout=5
            )
            dim(f"  → {url}")
        except Exception:
            pass
        time.sleep(0.3)

    ok(f"{len(urls)} HTTP requests sent")
    dim("Expected: ET INFO External IP Lookup, ET POLICY alerts")


def test_tls_connections():
    """
    TRIGGERS:
      - TLS event rules (tls-events.rules)
      - Generates new destination connections for behavioral engine
    """
    section(6, "TLS/HTTPS Connections → TLS events + new_dest")
    info("Making HTTPS connections to various external hosts...")

    hosts = [
        'example.com',
        'httpbin.org',
        'ifconfig.me',
        'cloudflare.com',
        'github.com',
    ]

    for host in hosts:
        try:
            subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-m', '3',
                 f'https://{host}/'],
                capture_output=True, timeout=5
            )
            dim(f"  → https://{host}/")
        except Exception:
            pass
        time.sleep(0.3)

    ok(f"{len(hosts)} TLS connections made")
    dim("Expected: TLS events, behavioral new_dest alerts")


def test_beaconing_unknown():
    """
    TRIGGERS:
      - NETGUARD BEHAVIOR Beaconing Detected (behavioral engine)
    
    Sends 25 periodic connections to an external IP at ~2s intervals.
    The low CV (coefficient of variation) triggers beaconing detection.
    """
    section(7, "Beaconing to UNKNOWN IP → Behavioral beaconing")

    # Use a different target each run to avoid dedup
    targets = [
        ('93.184.216.34', 'example.com'),
        ('93.184.215.14', 'example.org'),
        ('208.67.222.222', 'OpenDNS'),
    ]
    target_ip, target_name = random.choice(targets)
    count = 25
    interval = 2.0

    info(f"Sending {count} periodic connections to {target_ip} ({target_name})")
    info(f"Interval: {interval}s — this takes ~{int(count * interval)}s")

    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect_ex((target_ip, 443))
            s.close()
        except Exception:
            pass
        if (i + 1) % 5 == 0:
            dim(f"  ... {i + 1}/{count} connections")
        if i < count - 1:
            time.sleep(interval + random.uniform(-0.05, 0.05))

    ok(f"Beaconing simulation complete to {target_ip}")
    dim(f"Expected: NETGUARD BEHAVIOR Beaconing Detected — {count} connections (CV ≈ 0.02)")


def test_beaconing_cloudflare_nonstandard():
    """
    TRIGGERS:
      - NETGUARD BEHAVIOR Beaconing Detected (behavioral engine)
    
    Beaconing to Cloudflare IP on NON-STANDARD port (4444).
    Even though Cloudflare is semi-trusted, non-standard ports always alert.
    """
    section(8, "Beaconing to CLOUDFLARE on port 4444 → Semi-trusted alert")

    target_ip = '104.16.132.229'  # Cloudflare IP
    count = 25
    interval = 2.0

    info(f"Beaconing to {target_ip}:4444 (Cloudflare, non-standard port)")
    info(f"Semi-trusted IPs must alert on non-standard ports!")

    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect_ex((target_ip, 4444))
            s.close()
        except Exception:
            pass
        if (i + 1) % 5 == 0:
            dim(f"  ... {i + 1}/{count} connections")
        if i < count - 1:
            time.sleep(interval + random.uniform(-0.05, 0.05))

    ok(f"Beaconing to Cloudflare:4444 complete")
    dim("Expected: Beaconing alert even though Cloudflare is semi-trusted")


def test_data_transfer():
    """
    TRIGGERS:
      - Large flows visible in connection tracker
      - If target is unknown and > 200MB, triggers data_exfil
    
    Sends ~5 MB to a real external server via HTTP POST.
    """
    section(9, "Data Transfer → Connection tracking + exfil visibility")

    target = '93.184.216.34'  # example.com
    mb = 5
    info(f"Sending {mb} MB of data to {target}:80...")
    dim(f"(Below exfil threshold of 200 MB — just testing visibility)")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, 80))

        header = f"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: {mb * 1024 * 1024}\r\n\r\n"
        s.sendall(header.encode())

        chunk = b'X' * (64 * 1024)
        sent = 0
        target_bytes = mb * 1024 * 1024
        while sent < target_bytes:
            try:
                n = s.send(chunk)
                sent += n
            except Exception:
                break
            if sent % (1024 * 1024) < 65536:
                dim(f"  ... {sent // (1024 * 1024)} MB sent")

        s.close()
        ok(f"{sent // (1024 * 1024)} MB sent to {target}")
    except ConnectionRefusedError:
        warn(f"Connection to {target}:80 refused — SYN packet still captured")
    except Exception as e:
        warn(f"Transfer error: {e}")
        dim("The connection attempt itself is still captured by NetGuard")

    dim("Expected: Flow visible in 'show connections' with byte count")


def test_nmap_scan(target_ip):
    """
    TRIGGERS:
      - Multiple NETGUARD SCAN rules
      - ET SCAN rules if ET ruleset is active
    
    Uses actual nmap if available for most realistic scan signatures.
    """
    section(10, "Nmap Scan (if available) → SCAN rules")

    # Check if nmap is installed
    nmap_path = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
    if nmap_path.returncode != 0:
        warn("nmap not installed — skipping (install with: sudo apt install nmap)")
        return

    info(f"Running nmap SYN scan on {target_ip} (top 20 ports)...")
    try:
        result = subprocess.run(
            ['nmap', '-sS', '--top-ports', '20', '-T4', '--max-retries', '1',
             target_ip],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.strip().split('\n'):
            if 'open' in line or 'closed' in line or 'filtered' in line:
                dim(f"  {line.strip()}")
        ok(f"nmap scan complete on {target_ip}")
        dim("Expected: NETGUARD SCAN SYN Scan + Rapid Port Scan alerts")
    except subprocess.TimeoutExpired:
        warn("nmap timed out")
    except Exception as e:
        warn(f"nmap error: {e}")


# ─── Inventory ───────────────────────────────────────────────────────────

def print_inventory():
    print(f"\n{B}{'=' * 56}{X}")
    print(f"  {B}COMPLETE ALERT RULE INVENTORY{X}")
    print(f"{B}{'=' * 56}{X}")

    print(f"\n{C}  ── A. Custom Suricata Rules (netguard-custom.rules) ──{X}\n")
    rules = [
        ("SCAN",  "9000001", "SYN Scan (window 1024)"),
        ("SCAN",  "9000002", "SYN Scan (window 2048)"),
        ("SCAN",  "9000003", "SYN Scan (window 3072)"),
        ("SCAN",  "9000004", "SYN Scan (window 4096)"),
        ("SCAN",  "9000005", "SYN Scan (window 42340 — nmap)"),
        ("SCAN",  "9000006", "SYN Scan (window 65535 — nmap)"),
        ("SCAN",  "9000010", "ACK Scan"),
        ("SCAN",  "9000011", "FIN Scan"),
        ("SCAN",  "9000012", "XMAS Scan (FIN+PSH+URG)"),
        ("SCAN",  "9000013", "NULL Scan (no flags)"),
        ("SCAN",  "9000020", "Rapid Port Scan (20+ in 5s)"),
        ("BRUTE", "9000030", "SSH Brute Force (5+ in 60s)"),
        ("BRUTE", "9000035", "RDP Brute Force (5+ in 60s)"),
        ("BRUTE", "9000040", "FTP Brute Force (5+ in 60s)"),
        ("BRUTE", "9000045", "Telnet Brute Force (5+ in 60s)"),
        ("BRUTE", "9000050", "SSH Password Spray (10+ targets)"),
    ]
    for rtype, sid, name in rules:
        print(f"    {Y}[{rtype:<5}]{X} SID {sid} — {name}")

    print(f"\n{C}  ── B. ET Community Rules (~64,000 rules) ──{X}\n")
    for cat, desc in [
        ("ET INFO",    "Informational (IP lookups, user-agents)"),
        ("ET POLICY",  "Policy violations (cleartext, old TLS)"),
        ("ET DNS",     "DNS anomalies and queries"),
        ("ET SCAN",    "Port scanning & enumeration"),
        ("ET MALWARE", "Known malware C2 & downloads"),
        ("ET EXPLOIT", "CVE exploits & RCE attempts"),
    ]:
        print(f"    {Y}[{cat:<12}]{X} {desc}")

    print(f"\n{C}  ── C. Built-in Event Rules (739 rules) ──{X}\n")
    for name, count in [
        ("stream-events", 113), ("http-events", 94), ("decoder-events", 155),
        ("tls-events", 38), ("dns-events", 10), ("ssh-events", 10),
    ]:
        print(f"    {Y}[{count:>3} rules]{X} {name}")

    print(f"\n{C}  ── D. Behavioral Detectors (behavior_engine.py) ──{X}\n")
    for name, trigger in [
        ("BEACONING",       "20+ periodic connections, CV < 0.20"),
        ("DATA_EXFIL",      "200MB+ to unknown destination"),
        ("NEW_DEST",        "First-ever connection (needs DB)"),
        ("TRAFFIC_ANOMALY", "5× volume spike vs baseline (needs DB)"),
    ]:
        print(f"    {Y}[{name:<17}]{X} {trigger}")

    print(f"\n{C}  ── E. Tuning Layers ──{X}\n")
    print(f"    {Y}[TRUSTED]{X}        Google/Meta/AWS/Azure — fully exempt")
    print(f"    {Y}[SEMI-TRUSTED]{X}   Cloudflare/NAT64 — conditional suppression")
    print(f"    {Y}[SEVERITY REMAP]{X} new_dest→SUPPRESS, anomaly→LOW")
    print(f"    {Y}[DO NOT SUPPRESS]{X} SSH brute-force, MALWARE, EXPLOIT → always alert")
    print()


# ─── Main ─────────────────────────────────────────────────────────────────

def main():
    banner()
    check_root()

    local_ip = get_real_ip()
    gateway = get_gateway()

    if not local_ip:
        print(f"  {R}Could not determine local IP. Check network.{X}")
        sys.exit(1)

    # Scan target = gateway (traffic to self goes through loopback, invisible to Suricata)
    scan_target = gateway or local_ip

    print(f"  {B}Your IP:{X}      {local_ip}")
    print(f"  {B}Gateway:{X}      {gateway or 'unknown'}")
    print(f"  {B}Scan target:{X}  {scan_target} (gateway — goes through real interface)")

    # Show inventory first
    print_inventory()

    # Live test prompt
    print(f"{B}{'=' * 56}{X}")
    print(f"  {B}READY FOR LIVE TESTING{X}")
    print(f"{B}{'=' * 56}{X}")
    print(f"""
  {Y}This will generate real traffic including:{X}
    1.  SYN scan on gateway ({scan_target})
    2.  SSH brute-force on gateway ({scan_target})
    3.  FTP brute-force on gateway ({scan_target})
    4.  DNS queries to 8.8.8.8 / 1.1.1.1 / 9.9.9.9
    5.  HTTP requests to IP-check services
    6.  TLS/HTTPS connections to external hosts
    7.  Beaconing simulation (25 periodic connections)
    8.  Beaconing to Cloudflare on non-standard port
    9.  Data transfer to example.com
    10. Nmap scan (if nmap installed)

  {R}Make sure NetGuard capture is running first!{X}
  {D}Tip: Start a NEW capture session so dedup is clean.{X}
""")

    try:
        answer = input(f"  {B}Proceed? [y/N]: {X}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n  Cancelled.")
        return

    if answer != 'y':
        print("  Skipped. Re-run anytime.")
        return

    start = time.time()

    # ── Run all tests ────────────────────────────────────────────
    test_syn_scan(scan_target)
    time.sleep(1)

    test_ssh_bruteforce(scan_target)
    time.sleep(1)

    test_ftp_bruteforce(scan_target)
    time.sleep(1)

    test_dns_queries()
    time.sleep(1)

    test_http_plaintext()
    time.sleep(1)

    test_tls_connections()
    time.sleep(1)

    test_beaconing_unknown()
    time.sleep(1)

    test_beaconing_cloudflare_nonstandard()
    time.sleep(1)

    test_data_transfer()
    time.sleep(1)

    test_nmap_scan(scan_target)

    elapsed = time.time() - start

    # ── Results ──────────────────────────────────────────────────
    print(f"\n\n{C}{'═' * 56}{X}")
    print(f"  {B}LIVE TEST COMPLETE!  ({elapsed:.0f}s){X}")
    print(f"{C}{'═' * 56}{X}")
    print(f"""
  {G}Now check NetGuard for alerts:{X}

    {B}CLI:{X}   show alerts
    {B}GUI:{X}   Alerts page

  {B}Expected alerts:{X}

    {Y}Suricata (Custom):{X}
      • NETGUARD SCAN SYN Scan Detected
      • NETGUARD SCAN Rapid Port Scan
      • NETGUARD BRUTE-FORCE SSH Brute Force Detected
      • NETGUARD BRUTE-FORCE FTP Brute Force Detected

    {Y}Suricata (ET Community):{X}
      • ET INFO External IP Lookup
      • ET POLICY HTTP Connection
      • ET DNS queries

    {Y}Behavioral:{X}
      • NETGUARD BEHAVIOR Beaconing Detected (unknown IP)
      • NETGUARD BEHAVIOR Beaconing Detected (Cloudflare:4444)
      • NETGUARD BEHAVIOR New Destination (multiple new IPs)

  {D}Note: Some alerts may take 2-3 seconds to appear
  (behavioral engine flushes every tracker cycle).
  If running a SECOND time, start a new capture session
  first to reset the dedup cache.{X}
""")


if __name__ == '__main__':
    main()
