# Connection Tracking

NetGuard aggregates individual packets into **connections** (also called flows). Instead of storing one row per packet, it stores one row per connection — the same approach used by enterprise tools like Zeek, ntopng, and Arkime.

## Why Connection Tracking?

| Approach | 470K packets captured |
|----------|----------------------|
| **Per-packet** (old) | 470,000 database rows, slow queries |
| **Per-connection** (new) | ~600 rows, instant queries |

A YouTube video stream might generate 50,000 packets — but it's **one connection**. Connection tracking collapses those into a single row showing: source, destination, protocol, total bytes, duration, and state.

## What is a Connection?

A connection is identified by a **5-tuple**:

```
(Source IP, Destination IP, Source Port, Destination Port, Protocol)
```

**Example:** All packets between `192.168.1.5:54321` and `142.250.193.46:443` over `QUIC` belong to the **same connection**, regardless of direction.

Bidirectional traffic is automatically merged — a packet from A→B and a reply from B→A are part of the same flow.

## Connection Fields

| Field | Description | Example |
|-------|-------------|---------|
| `src_ip` | Initiator IP (who started the connection) | `192.168.1.5` |
| `dst_ip` | Destination IP | `142.250.193.46` |
| `src_port` | Initiator port | `54321` |
| `dst_port` | Destination port | `443` |
| `protocol` | Application/transport protocol | `QUIC`, `TLSv1.3`, `DNS` |
| `direction` | Relative to your machine | `OUTGOING` / `INCOMING` |
| `total_packets` | Number of packets in this flow | `50,234` |
| `total_bytes` | Total bytes transferred | `48.5 MB` |
| `duration` | Time from first to last packet | `2m 30s` |
| `state` | TCP connection state | `ACTIVE`, `ESTABLISHED`, `FIN`, `RST` |

### Connection States

| State | Meaning |
|-------|---------|
| `ACTIVE` | Non-TCP or ongoing UDP/QUIC flow |
| `SYN_SENT` | TCP handshake initiated (SYN sent) |
| `ESTABLISHED` | TCP handshake complete (SYN+ACK received) |
| `FIN` | Connection closing (FIN sent) |
| `RST` | Connection reset |

## CLI Commands

### Viewing Connections

```
netguard ▶ show connections        # Top 10 connections by bytes
netguard ▶ show connections 50     # Top 50 connections
```

Output:
```
┏━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ #  ┃ Source                 ┃ Destination            ┃ Protocol ┃ Dir  ┃ Packets  ┃ Bytes      ┃ Duration ┃ State       ┃
┡━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ 1  │ 192.168.1.5:54321      │ 142.250.193.46:443     │ QUIC     │ →    │  50,234  │  48.5 MB   │ 2m 30s   │ ACTIVE      │
│ 2  │ 192.168.1.5:43210      │ 104.18.32.7:443        │ TLSv1.3  │ →    │   1,200  │   2.1 MB   │ 45s      │ ESTABLISHED │
└────┴────────────────────────┴────────────────────────┴──────────┴──────┴──────────┴────────────┴──────────┴─────────────┘
```

### Searching

```
netguard ▶ search ip 142.250.193.46     # All connections involving this IP
netguard ▶ search proto QUIC            # All QUIC connections
netguard ▶ search port 443              # All connections on port 443
```

### Exporting

```
netguard ▶ export csv                   # Auto-named: netguard_export_20260217_220500.csv
netguard ▶ export csv report            # Saves as report.csv (auto-appends .csv)
netguard ▶ export csv my_export.csv     # Saves as my_export.csv
```

The CSV contains one row per connection with all fields listed above.

### Statistics

```
netguard ▶ show stats         # Protocol breakdown (packet counts)
netguard ▶ show top-talkers   # Most active IPs (connections + packets + bytes)
```

`show stats` still shows **packet counts** per protocol (for accuracy), while `show connections` and `search` show **connection-level** data.

## How It Works Internally

```
┌──────────────┐     ┌───────────────────┐     ┌──────────────┐     ┌──────────┐
│   dumpcap    │     │   tshark (live)    │     │  Connection  │     │  SQLite  │
│  (raw pcap)  │     │  dissect packets  │────▶│   Tracker    │────▶│    DB    │
│              │     │                   │     │ (in-memory)  │     │          │
└──────┬───────┘     └───────────────────┘     └──────────────┘     └──────────┘
       │                                        Aggregates by                    
       ▼                                        5-tuple, merges                  
  .pcapng file                                  bidirectional                    
  (ground truth)                                traffic                          
```

1. **dumpcap** writes every packet to the pcapng file (zero-drop ground truth)
2. **tshark** dissects packets and feeds them to the **ConnectionTracker**
3. The tracker maintains an in-memory dict keyed by 5-tuple — O(1) per packet
4. Every 2 seconds (and on capture stop), flows are flushed to SQLite
5. After capture stops, `reprocess()` rebuilds everything from the pcapng file for accuracy

## Database Schema

The `connections` table replaces the old `packets` table:

```sql
CREATE TABLE connections (
    id INTEGER PRIMARY KEY,
    src_ip TEXT,          -- Initiator IP
    dst_ip TEXT,          -- Destination IP  
    src_port INTEGER,     -- Initiator port
    dst_port INTEGER,     -- Destination port
    protocol TEXT,        -- QUIC, TLSv1.3, DNS, etc.
    transport TEXT,       -- TCP, UDP, ICMP
    direction TEXT,       -- INCOMING / OUTGOING
    start_time DATETIME,  -- First packet timestamp
    end_time DATETIME,    -- Last packet timestamp
    duration REAL,        -- Seconds between first and last packet
    total_packets INTEGER,-- Packet count in this flow
    total_bytes INTEGER,  -- Total bytes transferred
    state TEXT,           -- TCP state: ACTIVE, ESTABLISHED, FIN, RST
    session_id INTEGER    -- Links to capture session
);
```

> **Note:** The raw pcapng file remains the ground truth for individual packet data. Use Wireshark to inspect individual packets: `wireshark data/capture_XXXX.pcapng`

## Command-Line Query Tool

For scripting or quick lookups outside the shell:

```bash
python3 query_db.py --connections 50          # Top 50 connections
python3 query_db.py --stats                   # Protocol stats
python3 query_db.py --ip 192.168.1.5          # Search by IP
python3 query_db.py --protocol QUIC           # Search by protocol
python3 query_db.py --top-talkers 20          # Top 20 IPs
python3 query_db.py --export output.csv       # Export to CSV
python3 query_db.py --recalculate-stats       # Rebuild protocol stats
```
