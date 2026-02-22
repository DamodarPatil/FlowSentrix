# Phase 3 Testing Guide — Suricata Rules + Behavioral Tagging

## What Was Added

### Part A — Custom Suricata Rules (13 rules)

| SIDs | What it Detects | Threshold |
|------|----------------|-----------|
| 9000001–9000006 | SYN Scan (nmap -sS) | 5 SYNs in 10s per source |
| 9000010 | ACK Scan (nmap -sA) | 5 in 10s |
| 9000011 | FIN Scan (nmap -sF) | 5 in 10s |
| 9000012 | XMAS Scan (nmap -sX) | 3 in 10s |
| 9000013 | NULL Scan (nmap -sN) | 5 in 10s |
| 9000020 | Rapid Port Scan | 20 SYNs in 5s |
| 9000030 | SSH Brute Force | 5 connections to port 22 in 60s |
| 9000035 | RDP Brute Force | 5 connections to port 3389 in 60s |
| 9000040 | FTP Brute Force | 5 connections to port 21 in 60s |
| 9000045 | Telnet Brute Force | 5 connections to port 23 in 60s |
| 9000050 | SSH Password Spray | 10 SSH connections in 120s |

### Part B — Behavioral Tagging Engine (4 detectors)

| Tag | What it Detects | How |
|-----|----------------|-----|
| `beaconing` | Periodic C2 callbacks | Coefficient of variation < 0.20 on connection intervals |
| `data_exfil` | Large uploads to external IPs | >50 MB = medium, >200 MB = high |
| `new_dest` | First-ever connection to an IP | `known_destinations` DB table lookup |
| `traffic_anomaly` | Volume spike vs baseline | Current bytes > 5× rolling average |

### New CLI Commands

| Command | Description |
|---------|-------------|
| `show tags` | Display summary of all behavioral tags |
| `search tag <TAG>` | Find connections with a specific tag |

---

## How to Test Manually

### Prerequisites

```bash
# Make sure you're in the NetGuard directory
cd ~/NetGuard

# Verify Suricata rules are valid
sudo suricata -T -c /etc/suricata/suricata.yaml
# Expected: "Configuration provided was successfully loaded. Exiting."
```

---

### Test 1: SSH Brute Force Detection (Suricata Rule)

This tests SID 9000030 — SSH brute force.

**Terminal 1 — Start NetGuard capture:**
```bash
sudo python3 main.py
# In the shell:
netguard> set interface wlan0
netguard> start
```

**Terminal 2 — Simulate SSH brute force (against your own machine):**
```bash
# Option A: Using Hydra (if installed)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1 -t 4

# Option B: Using ncrack
ncrack -p 22 --user root -P /usr/share/wordlists/rockyou.txt 127.0.0.1

# Option C: Manual rapid SSH connections (simplest)
for i in $(seq 1 10); do
    ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no root@127.0.0.1 2>/dev/null &
done
```

**Verify in NetGuard:**
```
netguard> show alerts
# Should see: "NETGUARD BRUTE-FORCE SSH Brute Force Detected"

netguard> show threats
# Should show the source IP in "Top Source IPs"
```

---

### Test 2: SYN Scan Detection (Suricata Rule)

This tests SIDs 9000001–9000006.

**Terminal 1 — NetGuard capturing (same as above)**

**Terminal 2 — Run nmap SYN scan:**
```bash
# Scan your own machine
sudo nmap -sS -p 1-1000 127.0.0.1

# Or scan your gateway
sudo nmap -sS -p 1-100 192.168.1.1
```

**Verify:**
```
netguard> show alerts
# Should see: "NETGUARD SCAN SYN Scan Detected"
```

---

### Test 3: Other Scan Types

```bash
# FIN Scan
sudo nmap -sF -p 1-100 127.0.0.1

# XMAS Scan
sudo nmap -sX -p 1-100 127.0.0.1

# NULL Scan
sudo nmap -sN -p 1-100 127.0.0.1

# ACK Scan
sudo nmap -sA -p 1-100 127.0.0.1
```

---

### Test 4: Beaconing Detection (Behavioral Engine)

This simulates C2 beaconing — regular periodic connections to the same server.

**Terminal 1 — NetGuard capturing**

**Terminal 2 — Simulate beaconing (curl every 30 seconds):**
```bash
# This contacts example.com every 30 seconds — regular interval = beaconing
for i in $(seq 1 10); do
    curl -s -o /dev/null https://example.com
    echo "Beacon $i sent"
    sleep 30
done
```

**Wait ~5 minutes, then verify:**
```
netguard> show tags
# Should show: beaconing tag with HIGH severity

netguard> search tag beaconing
# Should show the connections to example.com

netguard> show connections
# The "Tags" column should show "beaconing" for those connections
```

> **Note:** The beaconing detector needs 5+ connections with regular intervals 
> (CV < 0.20). Run the curl loop for at least 5 iterations.

---

### Test 5: Data Exfiltration Detection (Behavioral Engine)

This simulates a large file upload to an external server.

**Terminal 1 — NetGuard capturing**

**Terminal 2 — Generate and upload a large file:**
```bash
# Create a 60MB test file
dd if=/dev/urandom of=/tmp/testfile bs=1M count=60

# Upload to a test server (or use netcat)
# Option A: Using a public service
curl -X POST -F "file=@/tmp/testfile" https://file.io

# Option B: Using netcat (set up receiver first on another machine)
# On receiver: nc -l -p 9999 > /dev/null
# On sender:   cat /tmp/testfile | nc <RECEIVER_IP> 9999

# Cleanup
rm /tmp/testfile
```

**Verify:**
```
netguard> show tags
# Should show: data_exfil tag with MEDIUM severity (50MB+)

netguard> search tag data_exfil
# Should show the upload connection
```

---

### Test 6: New Destination Detection (Behavioral Engine)

This is the easiest to test — any connection to a new IP gets tagged on first run.

**Terminal 1 — NetGuard capturing**

**Terminal 2 — Connect to an unusual IP:**
```bash
# Connect to servers you've never visited
curl -s -o /dev/null https://httpbin.org/get
curl -s -o /dev/null https://ifconfig.me
curl -s -o /dev/null https://api.ipify.org
```

**Verify:**
```
netguard> show tags
# Should show: new_dest tags with LOW severity

netguard> search tag new_dest
```

> **Note:** After the first capture session, these IPs get added to 
> `known_destinations`. On subsequent sessions, they won't be tagged again.

---

### Test 7: CLI Commands

Test all the new CLI features:

```bash
sudo python3 main.py
```

```
# View behavioral tag summary
netguard> show tags

# Search by specific tag
netguard> search tag beaconing
netguard> search tag data_exfil
netguard> search tag new_dest
netguard> search tag traffic_anomaly

# View connections — Tags column appears when tags exist
netguard> show connections

# Tab completion works
netguard> show t<TAB>    → shows 'tags', 'threats', 'top-talkers'
netguard> search t<TAB>  → shows 'tag', 'threat'

# Help text includes new commands
netguard> help
```

---

### Test 8: Database Verification

Verify the database schema was updated correctly:

```bash
# Check schema
sqlite3 data/netguard.db ".schema connections" | grep -E "tags|severity"
# Expected: tags TEXT DEFAULT '', severity TEXT DEFAULT ''

# Check known_destinations table exists
sqlite3 data/netguard.db ".schema known_destinations"
# Expected: CREATE TABLE known_destinations (ip TEXT PRIMARY KEY, ...)

# Check tagged connections
sqlite3 data/netguard.db "SELECT tags, severity, COUNT(*) FROM connections WHERE tags != '' GROUP BY tags, severity;"

# Export with tags
netguard> export csv /tmp/test_export.csv
# Check: head /tmp/test_export.csv — should include Tags and Severity columns
```

---

## Quick Smoke Test (All-in-One)

If you want a fast test of everything at once:

```bash
# 1. Start capture
sudo python3 main.py
netguard> start

# 2. In another terminal, run all at once:
# SYN scan (triggers Suricata rule)
sudo nmap -sS -p 1-100 127.0.0.1 &

# Rapid SSH connections (triggers brute force rule)
for i in $(seq 1 8); do ssh -o ConnectTimeout=1 root@127.0.0.1 2>/dev/null & done

# Beaconing simulation (regular intervals)
for i in $(seq 1 6); do curl -s -o /dev/null https://example.com; sleep 30; done &

# New destination
curl -s -o /dev/null https://httpbin.org/get

# 3. After ~3 minutes, check in NetGuard:
netguard> show alerts     # Suricata detections
netguard> show threats    # Threat summary
netguard> show tags       # Behavioral tags
netguard> show connections # Tags column visible
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `show alerts` is empty | Suricata may need time to start. Wait 10–15s after `start` |
| `show tags` is empty | Tags are only generated when tracker flushes (every ~10s). Wait for traffic |
| `new_dest` tags everything | Expected on first run — the `known_destinations` table is empty initially |
| Suricata rules not loading | Run `sudo suricata -T` to check for syntax errors |
| DB permission error | Run NetGuard with `sudo` — the DB was created with root |
