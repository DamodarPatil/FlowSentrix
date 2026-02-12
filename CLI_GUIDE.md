# NetGuard CLI — User Guide

## Quick Start

```bash
# Run with sudo (required for packet capture)
sudo python3 netguard.py
```

You'll see the NETGUARD banner and an interactive prompt:

```
netguard ▶
```

---

## Commands

### 🔴 Capture

```bash
capture start              # Start live packet capture (background)
capture stop               # Stop capture + show summary
capture status             # Show packets captured, rate, duration
```

> Packets display in real-time while capture runs. You can type commands anytime — capture runs in the background.

### 📊 Display

```bash
show stats                 # Protocol breakdown (from live capture or DB)
show recent                # Last 20 packets
show recent 50             # Last 50 packets
show top-talkers           # Top 10 most active IPs
show top-talkers 20        # Top 20
show interfaces            # List network interfaces (with IP + UP/DOWN)
show config                # Current settings
```

### 🔍 Search

```bash
search ip 10.19.54.96      # Find packets by IP address
search proto DNS            # Find packets by protocol (TCP, UDP, DNS, TLS, etc.)
search port 443             # Find packets by port number
```

### ⚙️ Config

```bash
set interface wlo1          # Set capture interface
set csv output.csv          # Enable CSV export during capture
set count 500               # Capture exactly 500 packets (0 = unlimited)
set display off             # Hide live packet output (still captures)
set display on              # Show live packet output
```

### 📤 Export

```bash
export csv results.csv      # Export all captured packets from DB to CSV
```

### Other

```bash
clear                       # Clear screen
help                        # Show all commands
help capture                # Help for a specific command
exit                        # Exit NetGuard
```

---

## Tab Completion

Press **Tab** to auto-complete commands:

```bash
cap<TAB>      → capture
capture st<TAB>  → start / status / stop
set int<TAB>  → interface
set interface w<TAB>  → wlo1
```

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Tab` | Auto-complete command |
| `Ctrl+C` | Stop capture (stays in shell) |
| `Ctrl+D` | Exit NetGuard |
| `↑` / `↓` | Command history |

---

## Example Session

```bash
$ sudo python3 netguard.py

netguard ▶ show interfaces
  Available Interfaces:
    • lo (127.0.0.1) UP
    • wlo1 (10.19.54.96) UP ◀ active

netguard ▶ capture start
  ▸ Starting capture on wlo1...
  ✓ Capture running in background

  #    TIME     PROTO    SOURCE              DESTINATION         LEN   INFO
  1    0.000s   DNS      10.19.54.96:53421   10.19.54.54:53       80   query A google.com
  2    0.012s   DNS      10.19.54.54:53      10.19.54.96:53421   124   response A 142.250.192.14
  3    0.015s   TCP      10.19.54.96:41822   142.250.192.14:443   74   [SYN] Seq=0
  ...

netguard ▶ capture status
  ● CAPTURING
    Interface:  wlo1
    Duration:   45s
    Packets:    1,247
    Rate:       28 pkt/s

netguard ▶ capture stop
  ✓ Capture stopped. 1,247 packets in 45s

netguard ▶ show stats
  ┌─────────────────────────────────┐
  │       Session Overview          │
  │  Total Packets:  1,247          │
  │  Total Bytes:    892.4 KB       │
  └─────────────────────────────────┘

netguard ▶ search proto DNS
  Found 42 packet(s)
  ...

netguard ▶ exit
  Goodbye! 👋
```

---

## Color Coding

| Color | Meaning |
|-------|---------|
| 🔵 Blue | TCP |
| 🟢 Green | UDP, DNS, outgoing traffic |
| 🟡 Yellow | TLS/HTTPS |
| 🔴 Red | Retransmission, Dup ACK, errors |
| ⚪ White | ARP, general |
| 🟣 Magenta | HTTP |
| 🔵 Cyan | QUIC, ICMP |
