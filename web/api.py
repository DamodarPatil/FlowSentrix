"""
NetGuard Web API — FastAPI backend serving dashboard data from SQLite.
Run: python web/api.py
"""
import sys
import os

# Add project root to path so we can import core modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from core.database import NetGuardDatabase

app = FastAPI(title="NetGuard API", version="1.0.0")

# Allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "netguard.db")


def get_db():
    return NetGuardDatabase(db_path=DB_PATH)


def fmt_bytes(b):
    """Convert bytes to human-readable string."""
    if b >= 1_000_000_000:
        return f"{b / 1_000_000_000:.1f}", "GB"
    elif b >= 1_000_000:
        return f"{b / 1_000_000:.1f}", "MB"
    elif b >= 1_000:
        return f"{b / 1_000:.1f}", "KB"
    return str(b), "B"


def fmt_count(n):
    """Convert large numbers to human-readable."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}", "M"
    elif n >= 1_000:
        return f"{n / 1_000:.1f}", "K"
    return str(n), ""


@app.get("/api/stats")
def get_stats(
    session_id: int = Query(0, ge=0, description="Filter by session ID (0 = all)"),
):
    """Get cumulative dashboard stats, optionally scoped to a session."""
    db = get_db()
    try:
        if session_id > 0:
            stats = db.get_session_stats(session_id)
            if stats is None:
                return {"error": "session_not_found", "total_packets": {"value": "0", "unit": ""}, "total_bytes": {"value": "0", "unit": "B"}, "session_count": 0, "connection_count": 0, "protocols": []}
        else:
            stats = db.get_cumulative_stats()

        # Format numbers for display
        pkt_val, pkt_unit = fmt_count(stats["total_packets"])
        bytes_val, bytes_unit = fmt_bytes(stats["total_bytes"])

        # Protocol breakdown — ALL protocols, percentage by packet count
        colors = [
            "#00f3ff", "#bc13fe", "#00ff73", "#ffaa00", "#ff6b9d",
            "#ff2a2a", "#6ec6ff", "#ffcc80", "#b39ddb", "#80deea",
            "#c5e1a5", "#ef9a9a", "#fff59d", "#f48fb1", "#90caf9",
            "#a5d6a7", "#ce93d8", "#80cbc4", "#e6ee9c", "#bcaaa4",
        ]
        total_pkts = sum(row[1] for row in stats["protocol_stats"]) or 1
        protocols = []
        for i, (proto, count, pbytes) in enumerate(stats["protocol_stats"]):
            pct = round((count / total_pkts) * 100, 1)
            protocols.append({
                "name": proto,
                "pct": pct,
                "packets": count,
                "color": colors[i % len(colors)],
            })

        return {
            "total_packets": {"value": pkt_val, "unit": pkt_unit},
            "total_bytes": {"value": bytes_val, "unit": bytes_unit},
            "session_count": stats["session_count"],
            "connection_count": stats["connection_count"],
            "protocols": protocols,
        }
    finally:
        db.close()


@app.get("/api/alerts")
def get_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=10, le=200, description="Rows per page"),
    severity: str = Query("", description="Filter by severity: high, medium, low"),
    search: str = Query("", description="Search IP or signature text"),
    proto: str = Query("", description="Filter by protocol"),
    date_from: str = Query("", description="Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM)"),
    date_to: str = Query("", description="End date (YYYY-MM-DD or YYYY-MM-DD HH:MM)"),
    group: bool = Query(False, description="Group by signature"),
    session_id: int = Query(0, ge=0, description="Filter by session ID (0 = all)"),
):
    """Get alerts with pagination, filters, and severity breakdown."""
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    where_clauses = []
    params = []

    if severity:
        sev_map = {"high": 1, "medium": 2, "low": 3}
        if severity in sev_map:
            where_clauses.append("severity_num = ?")
            params.append(sev_map[severity])

    if search:
        where_clauses.append("(src_ip LIKE ? OR dst_ip LIKE ? OR signature LIKE ? OR category LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like, like])

    if proto:
        where_clauses.append("proto = ?")
        params.append(proto)

    if date_from:
        where_clauses.append("timestamp >= ?")
        params.append(date_from)

    if date_to:
        if len(date_to) == 10:
            date_to += " 23:59:59"
        where_clauses.append("timestamp <= ?")
        params.append(date_to)

    if session_id > 0:
        where_clauses.append("session_id = ?")
        params.append(session_id)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # Unfiltered severity counts (always show totals on stat cards)
    cursor.execute("SELECT severity_num, COUNT(*) FROM alerts GROUP BY severity_num")
    total_sev = {r[0]: r[1] for r in cursor.fetchall()}
    total_high = total_sev.get(1, 0)
    total_medium = total_sev.get(2, 0)
    total_low = total_sev.get(3, 0)

    # Filtered count (for pagination)
    cursor.execute(f"SELECT COUNT(*) FROM alerts {where_sql}", list(params))
    total_count = cursor.fetchone()[0]

    # Distinct protocols for filter dropdown
    cursor.execute("SELECT DISTINCT proto FROM alerts WHERE proto IS NOT NULL AND proto != '' ORDER BY proto")
    all_protos = [r[0] for r in cursor.fetchall()]

    total_pages = max(1, (total_count + per_page - 1) // per_page)
    offset = (page - 1) * per_page

    if group:
        # Grouped mode: collapse by signature, show count
        # Recount for grouped mode (must be done before the data query
        # since both share the same cursor)
        cursor.execute(f"SELECT COUNT(DISTINCT signature || severity_num) FROM alerts {where_sql}", list(params))
        total_count = cursor.fetchone()[0]
        total_pages = max(1, (total_count + per_page - 1) // per_page)

        cursor.execute(f"""
            SELECT signature, severity_num, category, proto, COUNT(*) as cnt,
                   MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
                   GROUP_CONCAT(DISTINCT src_ip) as src_ips,
                   GROUP_CONCAT(DISTINCT dst_ip) as dst_ips
            FROM alerts {where_sql}
            GROUP BY signature, severity_num
            ORDER BY MAX(id) DESC
            LIMIT ? OFFSET ?
        """, list(params) + [per_page, offset])

        alerts = []
        for (sig, sev_num, cat, p, cnt, first, last, srcs, dsts) in cursor.fetchall():
            sev_label = "high" if sev_num == 1 else ("medium" if sev_num == 2 else "low")
            alerts.append({
                "signature": sig or "Unknown Alert",
                "severity": sev_label,
                "category": cat or "",
                "proto": p or "",
                "count": cnt,
                "first_seen": first or "",
                "last_seen": last or "",
                "src_ips": (srcs or "").split(",")[:5],
                "dst_ips": (dsts or "").split(",")[:5],
                "grouped": True,
            })
    else:
        # Flat mode: individual alert rows
        cursor.execute(f"""
            SELECT id, timestamp, severity_num, signature, category,
                   src_ip, dst_ip, src_port, dst_port, proto, action
            FROM alerts {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, list(params) + [per_page, offset])

        alerts = []
        for (id_, ts, sev_num, sig, cat, src, dst, sport, dport, p, act) in cursor.fetchall():
            sev_label = "high" if sev_num == 1 else ("medium" if sev_num == 2 else "low")
            alerts.append({
                "id": id_,
                "timestamp": ts or "",
                "severity": sev_label,
                "signature": sig or "Unknown Alert",
                "category": cat or "",
                "src_ip": src or "",
                "dst_ip": dst or "",
                "src_port": sport,
                "dst_port": dport,
                "proto": p or "",
                "action": act or "allowed",
                "meta": f"{src} → {dst}:{dport}" if dport else f"{src} → {dst}",
            })

    conn.close()
    return {
        "alerts": alerts,
        "page": page,
        "per_page": per_page,
        "total_count": total_count,
        "total_pages": total_pages,
        "high_count": total_high,
        "medium_count": total_medium,
        "low_count": total_low,
        "protocols": all_protos,
    }


@app.get("/api/connections")
def get_connections(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=10, le=200, description="Rows per page"),
    search: str = Query("", description="Search src/dst IP or protocol"),
    protocol: str = Query("", description="Filter by protocol"),
    tag: str = Query("", description="Filter by tag"),
    date_from: str = Query("", description="Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM)"),
    date_to: str = Query("", description="End date (YYYY-MM-DD or YYYY-MM-DD HH:MM)"),
    session_id: int = Query(0, ge=0, description="Filter by session ID (0 = all)"),
):
    """Get connections with pagination and filters."""
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    where_clauses = []
    params = []

    if search:
        where_clauses.append("(src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])

    if protocol:
        where_clauses.append("protocol = ?")
        params.append(protocol)

    if tag:
        where_clauses.append("tags LIKE ?")
        params.append(f"%{tag}%")

    if date_from:
        where_clauses.append("start_time >= ?")
        params.append(date_from)

    if date_to:
        # If only date given (no time), extend to end of day
        if len(date_to) == 10:
            date_to += " 23:59:59"
        where_clauses.append("start_time <= ?")
        params.append(date_to)

    if session_id > 0:
        where_clauses.append("session_id = ?")
        params.append(session_id)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # Get total count for pagination
    count_params = list(params)
    cursor.execute(f"SELECT COUNT(*) FROM connections {where_sql}", count_params)
    total_count = cursor.fetchone()[0]

    # Paginated query
    offset = (page - 1) * per_page
    query_params = list(params) + [per_page, offset]

    cursor.execute(f"""
        SELECT id, src_ip, src_port, dst_ip, dst_port, protocol,
               direction, total_packets, total_bytes, state, tags, start_time
        FROM connections
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """, query_params)

    rows = cursor.fetchall()

    # Get distinct protocols for filter dropdown
    cursor.execute("SELECT DISTINCT protocol FROM connections ORDER BY protocol")
    all_protos = [r[0] for r in cursor.fetchall()]

    # Get distinct tags for filter dropdown
    cursor.execute("SELECT DISTINCT tags FROM connections WHERE tags != '' AND tags IS NOT NULL ORDER BY tags")
    all_tags = [r[0] for r in cursor.fetchall()]

    conn.close()

    total_pages = max(1, (total_count + per_page - 1) // per_page)

    connections = []
    for (id_, src_ip, src_port, dst_ip, dst_port, proto,
         direction, packets, nbytes, state, tags, start_time) in rows:
        bv, bu = fmt_bytes(nbytes or 0)
        connections.append({
            "id": id_,
            "src": f"{src_ip}:{src_port}" if src_port else src_ip,
            "dst": f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "direction": direction or "—",
            "packets": packets or 0,
            "bytes": f"{bv} {bu}",
            "tags": tags or "",
            "time": start_time or "",
        })

    return {
        "connections": connections,
        "page": page,
        "per_page": per_page,
        "total_count": total_count,
        "total_pages": total_pages,
        "protocols": all_protos,
        "tags": all_tags,
    }


@app.get("/api/alerts/latest")
def get_latest_alert():
    """Returns the most recent alert's id and timestamp — used by frontend for new-alert detection."""
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, severity, signature, src_ip, dst_ip FROM alerts ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    if not row:
        return {"id": 0, "timestamp": "", "severity": "", "title": "", "meta": ""}
    id_, ts, sev, sig, src, dst = row
    sev_label = "high" if sev == 1 else ("medium" if sev == 2 else "low")
    return {
        "id": id_,
        "timestamp": ts,
        "severity": sev_label,
        "title": sig or "Unknown Alert",
        "meta": f"{src} → {dst}",
    }

import threading
import time as _time
from datetime import datetime


# ── Capture Manager (singleton) ──────────────────────────────────

class CaptureManager:
    """Manages a single TsharkCapture instance for the GUI."""

    def __init__(self):
        self.sniffer = None
        self._thread = None
        self._lock = threading.Lock()
        self.state = "idle"           # idle | capturing | stopping | analyzing
        self.start_time = None
        self.interface = None
        self.error = None
        self.last_stats = None        # Final stats after capture
        self._pps_samples = []        # For packets/sec calculation
        self._packet_buffer = []      # Ring buffer of last 200 packets
        self._packet_lock = threading.Lock()
        self._packet_id_counter = 0

    @property
    def is_running(self):
        return self.state in ("capturing", "stopping", "analyzing")

    def start(self, interface: str) -> dict:
        with self._lock:
            if self.is_running:
                return {"ok": False, "error": "Capture already running"}

            # Check prerequisites
            from core.tshark_capture import TsharkCapture
            if not TsharkCapture.is_available():
                return {"ok": False, "error": "tshark/dumpcap not installed. Run: sudo apt install tshark"}

            # Check root
            if os.geteuid() != 0:
                return {"ok": False, "error": "Root privileges required. Start API with: sudo"}

            self.error = None
            self.last_stats = None
            self.interface = interface
            self.state = "capturing"
            self.start_time = _time.time()
            self._pps_samples = []

            self._packet_buffer = []
            self._packet_id_counter = 0

            try:
                self.sniffer = TsharkCapture(
                    interface=interface,
                    db_path=DB_PATH,
                    on_packet=self._packet_callback,
                )
            except Exception as e:
                self.state = "idle"
                self.error = str(e)
                return {"ok": False, "error": str(e)}

            # Run capture in background thread
            self._thread = threading.Thread(
                target=self._run_capture,
                name="NetGuard-WebCapture",
                daemon=True,
            )
            self._thread.start()
            return {"ok": True, "interface": interface}

    def _packet_callback(self, data):
        """Called for each packet — buffers recent packets for the GUI."""
        # Skip self-traffic: GUI API (8000) and Vite dev server (5173)
        # These are the GUI's own polling requests — showing them creates a feedback loop
        src_port = data.get('src_port', '')
        dst_port = data.get('dst_port', '')
        skip_ports = {'8000', '5173'}
        if str(src_port) in skip_ports or str(dst_port) in skip_ports:
            return

        proto = data.get('application_protocol', data.get('transport_protocol', '?'))
        src = data.get('display_src', data.get('src', '?'))
        dst = data.get('display_dst', data.get('dst', '?'))

        src_display = f"{src}:{src_port}" if src_port else src
        dst_display = f"{dst}:{dst_port}" if dst_port else dst

        # Truncate long addresses
        if len(src_display) > 28:
            src_display = src_display[:25] + "..."
        if len(dst_display) > 28:
            dst_display = dst_display[:25] + "..."

        info = data.get('info', '')
        if len(info) > 80:
            info = info[:77] + "..."

        with self._packet_lock:
            self._packet_id_counter += 1
            pkt = {
                "id": self._packet_id_counter,
                "num": data.get('packet_id', '?'),
                "time": round(data.get('relative_time', 0), 3),
                "proto": proto,
                "src": src_display,
                "dst": dst_display,
                "length": data.get('packet_length', 0),
                "direction": data.get('direction', ''),
                "info": info,
            }
            self._packet_buffer.append(pkt)
            # Keep last 500 packets
            if len(self._packet_buffer) > 500:
                self._packet_buffer = self._packet_buffer[-500:]

    def _run_capture(self):
        try:
            self.sniffer.start(count=0)
        except Exception as e:
            self.error = str(e)
        finally:
            if self.state == "stopping":
                # Reprocess for accurate stats
                self.state = "analyzing"
                try:
                    if self.sniffer and self.sniffer.pcap_file:
                        self.sniffer.reprocess()
                except Exception:
                    pass

            # Save final stats
            if self.sniffer:
                self.last_stats = {
                    "packets": self.sniffer.packets_captured,
                    "bytes": self.sniffer.total_bytes,
                    "pcap_file": self.sniffer.pcap_file,
                    "session_id": self.sniffer.session_id,
                    "duration": _time.time() - self.start_time if self.start_time else 0,
                }

            self.state = "idle"

    def stop(self) -> dict:
        with self._lock:
            if self.state != "capturing":
                return {"ok": False, "error": f"Not capturing (state: {self.state})"}

            self.state = "stopping"

            if self.sniffer:
                self.sniffer.stop_sniffing.set()
                # Kill subprocesses
                if self.sniffer._tshark:
                    try:
                        self.sniffer._tshark.terminate()
                    except Exception:
                        pass
                if self.sniffer._dumpcap:
                    try:
                        self.sniffer._dumpcap.terminate()
                    except Exception:
                        pass

            return {"ok": True, "message": "Stopping capture..."}

    def get_status(self) -> dict:
        elapsed = 0
        if self.start_time and self.state != "idle":
            elapsed = _time.time() - self.start_time

        packets = 0
        total_bytes = 0
        pcap_packets = 0
        pcap_bytes = 0
        pps = 0

        if self.sniffer and self.state != "idle":
            packets = self.sniffer.packets_captured
            total_bytes = self.sniffer.total_bytes
            pcap_packets = self.sniffer.pcap_packets_captured
            pcap_bytes = self.sniffer.pcap_total_bytes

            # Calculate PPS from recent samples
            now = _time.time()
            self._pps_samples.append((now, pcap_packets))
            # Keep only last 5 seconds of samples
            self._pps_samples = [(t, p) for t, p in self._pps_samples if now - t <= 5]
            if len(self._pps_samples) >= 2:
                dt = self._pps_samples[-1][0] - self._pps_samples[0][0]
                dp = self._pps_samples[-1][1] - self._pps_samples[0][1]
                if dt > 0:
                    pps = int(dp / dt)

        # Format bytes
        bv, bu = fmt_bytes(total_bytes)
        pcap_bv, pcap_bu = fmt_bytes(pcap_bytes)

        # Format duration
        secs = int(elapsed)
        if secs >= 3600:
            duration_str = f"{secs // 3600}h {(secs % 3600) // 60}m {secs % 60}s"
        elif secs >= 60:
            duration_str = f"{secs // 60}m {secs % 60}s"
        else:
            duration_str = f"{secs}s"

        result = {
            "state": self.state,
            "interface": self.interface,
            "packets": packets,
            "pcap_packets": pcap_packets,
            "bytes": total_bytes,
            "bytes_display": f"{bv} {bu}",
            "pcap_bytes_display": f"{pcap_bv} {pcap_bu}",
            "duration": round(elapsed, 1),
            "duration_display": duration_str,
            "pps": pps,
            "pcap_file": self.sniffer.pcap_file if self.sniffer else None,
            "error": self.error,
        }

        # Include last stats if capture just finished
        if self.state == "idle" and self.last_stats:
            result["last_capture"] = self.last_stats
            lbv, lbu = fmt_bytes(self.last_stats["bytes"])
            result["last_capture"]["bytes_display"] = f"{lbv} {lbu}"
            ld = int(self.last_stats["duration"])
            if ld >= 3600:
                result["last_capture"]["duration_display"] = f"{ld // 3600}h {(ld % 3600) // 60}m {ld % 60}s"
            elif ld >= 60:
                result["last_capture"]["duration_display"] = f"{ld // 60}m {ld % 60}s"
            else:
                result["last_capture"]["duration_display"] = f"{ld}s"

        return result


# Global capture manager
capture_mgr = CaptureManager()


# ── Capture API Endpoints ────────────────────────────────────────

@app.get("/api/interfaces")
def get_interfaces():
    """List available network interfaces."""
    interfaces = []
    try:
        net_dir = '/sys/class/net'
        if os.path.isdir(net_dir):
            for name in sorted(os.listdir(net_dir)):
                if not os.path.isdir(os.path.join(net_dir, name)):
                    continue
                iface = {"name": name, "ip": "", "state": "unknown"}

                # Get state
                try:
                    with open(f'{net_dir}/{name}/operstate', 'r') as f:
                        iface["state"] = f.read().strip()
                except Exception:
                    pass

                # Get IP address
                try:
                    import socket, fcntl, struct
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    ip = socket.inet_ntoa(fcntl.ioctl(
                        sock.fileno(), 0x8915,
                        struct.pack('256s', name.encode())
                    )[20:24])
                    iface["ip"] = ip
                    sock.close()
                except Exception:
                    pass

                interfaces.append(iface)
    except Exception:
        pass

    return {"interfaces": interfaces}


@app.post("/api/capture/start")
def start_capture(interface: str = Query("any", description="Network interface")):
    """Start packet capture."""
    return capture_mgr.start(interface)


@app.post("/api/capture/stop")
def stop_capture():
    """Stop current capture."""
    return capture_mgr.stop()


@app.get("/api/capture/status")
def capture_status():
    """Get current capture status and live stats."""
    return capture_mgr.get_status()


@app.get("/api/capture/packets")
def capture_packets(after_id: int = Query(0, description="Only return packets with id > after_id")):
    """Get buffered live packets for the feed."""
    with capture_mgr._packet_lock:
        if after_id > 0:
            packets = [p for p in capture_mgr._packet_buffer if p["id"] > after_id]
        else:
            # Return last 50 for initial load
            packets = capture_mgr._packet_buffer[-50:]
    return {"packets": packets}

# ── Settings API Endpoints ───────────────────────────────────────

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


@app.get("/api/settings/system")
def get_system_status():
    """Get system dependency status and versions."""
    import subprocess as sp
    import platform

    def get_version(cmd):
        try:
            r = sp.run(cmd, capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                # Extract version from first line
                out = r.stdout.strip().split('\n')[0]
                return out
            return None
        except Exception:
            return None

    # tshark
    tshark_ver = get_version(['tshark', '--version'])
    tshark_ok = tshark_ver is not None
    if tshark_ver and 'TShark' in tshark_ver:
        # "TShark (Wireshark) 4.2.2 ..."  →  "4.2.2"
        parts = tshark_ver.split()
        for i, p in enumerate(parts):
            if p.startswith('('):
                continue
            if any(c.isdigit() for c in p) and '.' in p:
                tshark_ver = p.rstrip('.')
                break

    # dumpcap
    dumpcap_ver = get_version(['dumpcap', '--version'])
    dumpcap_ok = dumpcap_ver is not None
    if dumpcap_ver and 'Dumpcap' in dumpcap_ver:
        parts = dumpcap_ver.split()
        for p in parts:
            if any(c.isdigit() for c in p) and '.' in p:
                dumpcap_ver = p.rstrip('.')
                break

    # suricata
    suricata_ver = get_version(['suricata', '--build-info'])
    suricata_ok = suricata_ver is not None
    if suricata_ver:
        for line in suricata_ver.split('\n'):
            if 'version' in line.lower():
                suricata_ver = line.strip()
                break

    # suricata rules
    rules_path = '/var/lib/suricata/rules/suricata.rules'
    rules_ok = os.path.exists(rules_path) and os.path.getsize(rules_path) > 0
    rules_count = 0
    if rules_ok:
        try:
            with open(rules_path, 'r') as f:
                rules_count = sum(1 for line in f if line.strip() and not line.strip().startswith('#'))
        except Exception:
            pass

    # root
    is_root = os.geteuid() == 0

    return {
        "tshark": {"installed": tshark_ok, "version": tshark_ver or ""},
        "dumpcap": {"installed": dumpcap_ok, "version": dumpcap_ver or ""},
        "suricata": {"installed": suricata_ok, "version": suricata_ver or ""},
        "suricata_rules": {"loaded": rules_ok, "count": rules_count},
        "root": is_root,
        "python_version": platform.python_version(),
        "os": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
    }


@app.get("/api/settings/data")
def get_data_stats():
    """Get database and capture file statistics."""
    import sqlite3
    import glob

    # Database stats
    db_exists = os.path.exists(DB_PATH)
    db_size_bytes = os.path.getsize(DB_PATH) if db_exists else 0
    db_size_display = fmt_bytes(db_size_bytes)

    # Pcap files
    pcap_files = []
    total_pcap_bytes = 0
    if os.path.isdir(DATA_DIR):
        for f in sorted(glob.glob(os.path.join(DATA_DIR, "*.pcapng")), reverse=True):
            sz = os.path.getsize(f) if os.path.exists(f) else 0
            total_pcap_bytes += sz
            pcap_files.append({
                "name": os.path.basename(f),
                "size": sz,
                "size_display": f"{fmt_bytes(sz)[0]} {fmt_bytes(sz)[1]}",
            })

    pcap_display = fmt_bytes(total_pcap_bytes)

    # Session list
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT s.id, s.start_time, s.end_time, s.total_packets,
                   s.total_bytes, s.interface, s.pcap_file, s.status,
                   COALESCE(a.cnt, 0) as alert_count,
                   COALESCE(c.cnt, 0) as connection_count
            FROM sessions s
            LEFT JOIN (SELECT session_id, COUNT(*) as cnt FROM alerts GROUP BY session_id) a ON s.id = a.session_id
            LEFT JOIN (SELECT session_id, COUNT(*) as cnt FROM connections GROUP BY session_id) c ON s.id = c.session_id
            ORDER BY s.id DESC
        """)
        rows = cursor.fetchall()
    except Exception:
        rows = []
    conn.close()

    sessions = []
    for (id_, start, end, pkts, nbytes, iface, pcap, status, alerts, conns) in rows:
        bv, bu = fmt_bytes(nbytes or 0)
        # Check if pcap file exists
        pcap_exists = False
        pcap_size = ""
        if pcap:
            full_path = pcap if os.path.isabs(pcap) else os.path.join(DATA_DIR, os.path.basename(pcap))
            if os.path.exists(full_path):
                pcap_exists = True
                psz = os.path.getsize(full_path)
                pv, pu = fmt_bytes(psz)
                pcap_size = f"{pv} {pu}"

        sessions.append({
            "id": id_,
            "start_time": start or "",
            "end_time": end or "",
            "packets": pkts or 0,
            "bytes_display": f"{bv} {bu}",
            "interface": iface or "—",
            "pcap_file": os.path.basename(pcap) if pcap else "",
            "pcap_exists": pcap_exists,
            "pcap_size": pcap_size,
            "status": status or "completed",
            "alerts": alerts,
            "connections": conns,
        })

    return {
        "db_path": DB_PATH,
        "db_size": db_size_bytes,
        "db_size_display": f"{db_size_display[0]} {db_size_display[1]}",
        "pcap_count": len(pcap_files),
        "pcap_total_size": total_pcap_bytes,
        "pcap_total_display": f"{pcap_display[0]} {pcap_display[1]}",
        "sessions": sessions,
    }


@app.post("/api/settings/clear")
def clear_all_data():
    """Wipe all sessions, connections, and alerts from the database."""
    db = get_db()
    try:
        count = db.clear_all_sessions()
        if count < 0:
            return {"ok": False, "error": "Failed to clear data"}
        return {"ok": True, "deleted_sessions": count}
    finally:
        db.close()


@app.delete("/api/settings/sessions/{session_id}")
def delete_session(session_id: int):
    """Delete a single session and optionally its pcap file."""
    import sqlite3

    # Get pcap file path before deleting
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT pcap_file FROM sessions WHERE id = ?", (session_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {"ok": False, "error": f"Session {session_id} not found"}

    pcap_path = row[0]

    db = get_db()
    try:
        ok = db.delete_session(session_id)
        if not ok:
            return {"ok": False, "error": "Failed to delete session"}
    finally:
        db.close()

    # Delete pcap file if it exists
    pcap_deleted = False
    if pcap_path:
        full_path = pcap_path if os.path.isabs(pcap_path) else os.path.join(DATA_DIR, os.path.basename(pcap_path))
        if os.path.exists(full_path):
            try:
                os.remove(full_path)
                pcap_deleted = True
            except Exception:
                pass

    return {"ok": True, "session_id": session_id, "pcap_deleted": pcap_deleted}


@app.get("/api/sessions/{session_id}/check")
def check_session(session_id: int):
    """Lightweight check if a session still exists."""
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, interface, start_time FROM sessions WHERE id = ?", (session_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"exists": True, "id": row[0], "interface": row[1], "start_time": row[2]}
    return {"exists": False}


if __name__ == "__main__":
    print(f"📡 NetGuard API starting on http://localhost:8000")
    print(f"📂 Database: {DB_PATH}")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

