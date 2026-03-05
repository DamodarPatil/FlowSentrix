# NetGuard — IDS Tuning Guide

> **What is this?** A plain-English explanation of every tuning change we made to NetGuard and Suricata, why it was needed, and how it all fits together.

---

## The Problem

When NetGuard is first deployed on a network, its behavioral detectors and Suricata create **hundreds of false positive alerts**. These aren't real attacks — they're normal internet traffic being flagged because the tool doesn't know your network yet.

For example:
- Uploading a 500 MB file to **Google Drive** triggers a "Data Exfiltration" alert
- Watching **YouTube** triggers a "Beaconing" alert (video buffering looks like malware check-ins)
- The Linux DNS service (`systemd-resolved` at `127.0.0.53`) fires a beaconing alert every 2 seconds — forever
- **Every single new IP** you connect to fires a "New Destination" alert (useless on day 1)
- Normal web browsing looks like a "Traffic Anomaly" because the baseline is zero

Meanwhile, a **real SSH brute-force attack** (`10.92.237.60 → 10.92.237.82:22`) was buried under all this noise.

**The goal:** Silence the noise. Keep the real threats visible.

---

## What We Changed (Overview)

```
config/
├── tuning.yaml            ← Main tuning file (thresholds + behavior)
├── ip_allowlist.txt       ← Trusted IP ranges (Google, Meta, etc.)
├── severity_remap.yaml    ← Which alerts to demote or suppress
├── do_not_suppress.yaml   ← Alerts that must NEVER be silenced
├── threshold.config       ← Suricata suppress/threshold rules
├── suricata-tuning.yaml   ← Suricata engine settings (reference)
└── __init__.py            ← Python loader for all configs above

core/
├── behavior_engine.py     ← Modified — now reads tuning.yaml
└── tshark_capture.py      ← Modified — enforces severity remap + protection
```

---

## Change 1: IP Allowlist (`config/ip_allowlist.txt`)

### What it does
A list of trusted IP ranges in CIDR format. Any IP matching this list is **exempt from behavioral alerts**.

### Why it's needed
Google, YouTube, Cloudflare, Facebook, Fastly, and Microsoft own massive IP ranges. Traffic to these services is always legitimate — flagging a Google Drive upload as "data exfiltration" is a false positive, not a security finding.

### What's in the list

| Provider | Range | Why trusted |
|----------|-------|-------------|
| Google / YouTube / GCP | `2404:6800::/32`, `142.250.0.0/15`, etc. | Video streaming, Drive sync, GCP APIs |
| Facebook / Meta | `2a03:2880::/32`, `157.240.0.0/16` | Social platforms, WhatsApp |
| Fastly CDN | `2a04:4e42::/32`, `151.101.0.0/16` | GitHub, Reddit, npm downloads |
| Cloudflare | `2606:4700::/32`, `104.16.0.0/12` | CDN / DNS (1.1.1.1) |
| Microsoft / Azure | `20.0.0.0/8`, `13.64.0.0/11` | VS Code, Windows Update, GitHub |
| NAT64 | `64:ff9b::/96` | Router translates IPv4→IPv6 here. Always safe. |
| Loopback | `127.0.0.0/8`, `::1/128` | Your own machine talking to itself |

---

## Change 2: Behavioral Tuning (`config/tuning.yaml`)

### What it does
Controls the thresholds and behavior of NetGuard's 4 detectors. Before this change, all thresholds were hardcoded in Python. Now they're configurable via YAML.

### What changed per detector

#### Beaconing Detector
| Setting | Before | After | Why |
|---------|--------|-------|-----|
| Min connections | 5 | **20** | 5 was too sensitive — browser keep-alives to CDNs fire constantly |
| CV floor for trusted IPs | _(none)_ | **0.05** | Very regular intervals to CDNs are keepalives, not C2 |
| systemd-resolved (127.0.0.53) | Alerts every 2s | **Always suppressed** | It's the OS DNS service — it will ALWAYS beacon |
| Whitelisted destinations | Alerts normally | **Suppressed** | YouTube video buffering is not a C2 callback |

#### Data Exfiltration Detector
| Setting | Before | After | Why |
|---------|--------|-------|-----|
| Medium threshold | 50 MB | **200 MB** | 50 MB catches OS updates and Docker pulls |
| High threshold | 200 MB | **500 MB** | 200 MB catches Google Drive photo backups |
| Whitelisted destinations | Alerts normally | **Fully suppressed** | 576 MB to Google Drive is a backup, not exfil |

#### New Destination Detector
| Setting | Before | After | Why |
|---------|--------|-------|-----|
| During learning (first 30 days) | Alerts on everything | **Demoted to INFO** | Every IP is "new" on a fresh install, but we still log them in case malware connects to a C2 on day 15 |
| Whitelisted IPs | Alerts | **Suppressed** | Google, Cloudflare, etc. are never suspicious |
| After learning | Alerts on everything | **Only non-HTTPS ports** | A new connection to port 443 is probably a website; port 4444 is more suspicious |

#### Traffic Anomaly Detector
| Setting | Before | After | Why |
|---------|--------|-------|-----|
| Min absolute size | 0 bytes | **10 MB** | A 34× spike on 0.001 MB = 0.034 MB total — that's nothing |
| Min baseline age | _(none)_ | **14 days** | Baseline is near-zero on new installs — every page load looks like a 100× anomaly |
| Whitelisted destinations | Alerts normally | **Suppressed** | YouTube/CDN traffic is inherently bursty |

---

## Change 3: Severity Remap (`config/severity_remap.yaml`)

### What it does
Changes how loud alerts appear in the CLI and GUI. Some alerts are demoted, some are suppressed entirely, and critical threats stay at maximum severity.

### The remap table

| Alert Type | Original Severity | New Severity | Reason |
|-----------|-------------------|--------------|--------|
| `new_dest` | LOW | **SUPPRESS** | Silently dropped — too noisy, especially during learning |
| `traffic_anomaly` | MEDIUM | **LOW** | Shown only in detailed views until baseline matures |
| `beaconing` | HIGH | **MEDIUM** | Most beaconing alerts are CDN keep-alives |
| `data_exfil` | HIGH/MEDIUM | **MEDIUM** | Reduced priority since whitelisted destinations are already filtered |
| ET INFO (Suricata) | MEDIUM | **LOW** | Informational, not actionable |
| ET POLICY (Suricata) | MEDIUM | **LOW** | Policy-level events, not threats |
| **SSH Brute-Force** | CRITICAL | **CRITICAL** | **Never changed — real attack** |

### How SUPPRESS works
When an alert's severity is remapped to `SUPPRESS`:
- It is **not shown** in the CLI or GUI
- It is **not stored** in the database
- It is silently dropped and never surfaces

---

## Change 4: Do Not Suppress List (`config/do_not_suppress.yaml`)

### What it does
A safety net. Even if a tuning rule accidentally tries to suppress or demote a critical alert, this file **overrides everything** and keeps it visible.

### What's protected

| Protection Type | What | Why |
|----------------|------|-----|
| Confirmed alert | SSH Password Spray from `10.92.237.60` | Verified real attack |
| Confirmed alert | SSH Brute Force to `10.92.237.82:22` | Same attack, different detection |
| Category | Any `BRUTE-FORCE SSH` signature | All SSH brute-force must alert |
| Category | Any `MALWARE` signature | Malware downloads must always alert |
| Category | Any `EXPLOIT` signature | Exploit attempts must always alert |
| Category | Any `C2` signature | Command-and-control traffic must alert |
| Category | Any `LATERAL` movement | Internal lateral movement must alert |
| IP pair | `10.92.237.60 → 10.92.237.82` | Confirmed attacker → victim |
| Suricata SID | 2001219 | ET SCAN SSH Brute Force Attempt |
| Suricata SID | 2003068 | ET SCAN SSH Outbound Scan |
| Suricata SID | 2019284 | ET SCAN SSH Vertical Scan |

---

## Change 5: Suricata Threshold Rules (`config/threshold.config`)

### What it does
Tells Suricata's own engine to suppress or rate-limit certain signature alerts for trusted destinations. This is separate from NetGuard's behavioral layer — it controls Suricata's native rules (the ET rules).

### Key rules

| Rule Type | What it does |
|-----------|-------------|
| **Suppress** to Google/Meta/CDN | Silence policy alerts to known-good cloud services |
| **Suppress** to loopback | Never alert on `127.0.0.0/8` (internal DNS, local services) |
| **Suppress** to NAT64 `64:ff9b::/96` | Translated IPv4 traffic — always normal |
| **Rate-limit** ET INFO rules | Max 1 alert per minute per source (was flooding) |
| **Rate-limit** QUIC/HTTP3 | Max 1 per 5 minutes per destination (YouTube/Google constant) |
| **Rate-limit** DNS queries | Max 1 per 10 minutes (queries to 1.1.1.1 / 8.8.8.8 are normal) |

---

## Change 6: Suricata Engine Tuning (`config/suricata-tuning.yaml`)

### What it does
Provides optimized settings for Suricata's internal engine to work well on our dual-stack IPv4/IPv6 network with NAT64.

### Key settings applied to `/etc/suricata/suricata.yaml`

| Setting | What changed | Why |
|---------|-------------|-----|
| `HOME_NET` | Added IPv6 ranges + NAT64 prefix | Suricata only knew about IPv4 private ranges |
| `threshold-file` | Uncommented to point to `threshold.config` | Needed for suppress rules to take effect |
| `stream.memcap` | 256 MB (reference) | Heavy TLS traffic needs more memory |
| `flow.timeouts.tcp.established` | 600s (reference) | YouTube/Drive sessions live longer than default |
| `app-layer.protocols.quic` | Enabled (reference) | Google/YouTube use QUIC heavily |

> The `suricata-tuning.yaml` file is a **reference document**. Only `HOME_NET` and `threshold-file` were actually applied to the live config. The other sections can be merged manually if needed.

---

## Change 7: Config Loader (`config/__init__.py`)

### What it does
A Python module that loads all the YAML config files and provides a function to check if an IP is in the allowlist.

### Key functions

| Function | Purpose |
|----------|---------|
| `load_tuning_config()` | Loads all YAML files and returns a single config dict |
| `is_whitelisted(ip, networks)` | Checks if an IP falls within any trusted CIDR range |
| `get_detector_config(tuning, name)` | Gets settings for a specific detector |

---

## Change 8: Behavior Engine (`core/behavior_engine.py`)

### What changed
The engine now loads `config/tuning.yaml` and `config/ip_allowlist.txt` at startup. Every detector checks the allowlist before alerting.

### Before vs After

```
BEFORE: All thresholds hardcoded → flags everything → hundreds of false positives
AFTER:  Loads config at startup → checks allowlist → only flags truly suspicious traffic
```

Each detector now:
1. Reads its thresholds from `tuning.yaml` (falls back to defaults if missing)
2. Checks if the destination IP is in the allowlist before flagging
3. Respects the learning period settings

---

## Change 9: Alert Pipeline (`core/tshark_capture.py`)

### What changed
The capture engine now enforces severity remap and do-not-suppress at the moment alerts are created — for **both** behavioral alerts and Suricata alerts.

### The alert flow (before and after)

```
BEFORE:
  Detector fires → alert created with original severity → shown in CLI/GUI → stored in DB

AFTER:
  Detector fires → alert created → is it protected? (do_not_suppress.yaml)
    YES → keep original severity, always show
    NO  → apply severity remap (severity_remap.yaml)
           → SUPPRESS? silently drop, never show or store
           → other? update severity, then show and store
```

This applies to:
- **Behavioral alerts** (beaconing, data_exfil, new_dest, traffic_anomaly) in `_flush_tracker()`
- **Suricata alerts** (ET rules) in `_read_suricata_alerts()`

---

## Change 10: System Deployment

### What was deployed to `/etc/suricata/`

| File | Action |
|------|--------|
| `threshold.config` | NetGuard rules **appended** to existing file (defaults preserved) |
| `suricata.yaml` | `HOME_NET` updated + `threshold-file` uncommented |
| Both files | **Backed up** as `.bak.20260304` before changes |

Suricata was restarted and is running with the new config.

---

## The Result

| Before Tuning | After Tuning |
|--------------|--------------|
| Hundreds of false positive alerts per capture session | Only genuine threats surface |
| Google Drive uploads flagged as "exfiltration" | Silently ignored (whitelisted) |
| YouTube flagged as "beaconing" | Silently ignored (whitelisted) |
| systemd-resolved flagged every 2 seconds | Always suppressed |
| Every new website visit flagged as "new destination" | Suppressed for known ASNs, demoted to INFO for others |
| Real SSH brute-force buried under noise | **Always visible at CRITICAL severity** |
| All thresholds hardcoded in Python | Configurable via YAML files |

---

## How to Modify These Settings

All tuning is done through the YAML files in `config/`. No Python code changes needed.

- **To add a new trusted IP range:** Add the CIDR to `config/ip_allowlist.txt`
- **To change a detector threshold:** Edit `config/tuning.yaml`
- **To change alert severity:** Edit `config/severity_remap.yaml`
- **To protect a new alert from suppression:** Add it to `config/do_not_suppress.yaml`
- **To add a Suricata suppress rule:** Add it to `config/threshold.config` AND copy to `/etc/suricata/threshold.config`

Changes to the `config/` files take effect on the next NetGuard capture start (no code restart needed — configs are loaded fresh on each `TsharkCapture` init).
