"""
NetGuard Database Module
SQLite-based storage for connection/flow-level network analysis.

Architecture:
  - connections table: One row per flow (5-tuple), not per packet
  - protocol_stats table: Aggregate protocol counters
  - sessions table: Capture session metadata
  - alerts table: Suricata IDS alerts
  - ip_reputation table: AbuseIPDB cache

The raw pcapng file is the ground truth for individual packets.
This DB stores aggregated summaries for fast querying.
"""
import sqlite3
import os
import threading
from datetime import datetime
from typing import Dict, Optional, List


class NetGuardDatabase:
    """
    Manages SQLite database for connection-level network analysis.
    Stores flow summaries instead of individual packets.
    """
    
    def __init__(self, db_path="data/netguard.db"):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        
        # Thread safety lock for database operations
        self._lock = threading.Lock()
        
        # Ensure data directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        
        # Create persistent connection
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Initialize database schema
        self._init_database()
    
    def _init_database(self):
        """Create tables and indexes if they don't exist."""
        # Connection/flow table — one row per 5-tuple flow
        # This is how real enterprise monitors (Zeek, ntopng) store data
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                transport TEXT NOT NULL,
                direction TEXT,
                start_time DATETIME NOT NULL,
                end_time DATETIME,
                duration REAL DEFAULT 0,
                total_packets INTEGER DEFAULT 1,
                total_bytes INTEGER DEFAULT 0,
                state TEXT DEFAULT 'ACTIVE',
                session_id INTEGER,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        
        # Protocol statistics table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS protocol_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT UNIQUE NOT NULL,
                packet_count INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                last_seen DATETIME
            )
        """)
        
        # Session information table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time DATETIME NOT NULL,
                end_time DATETIME,
                total_packets INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                interface TEXT,
                status TEXT DEFAULT 'active'
            )
        """)
        
        # Suricata IDS alerts table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                severity TEXT NOT NULL,
                severity_num INTEGER NOT NULL,
                signature TEXT NOT NULL,
                signature_id INTEGER,
                category TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                action TEXT DEFAULT 'allowed',
                session_id INTEGER
            )
        """)

        # IP reputation cache (AbuseIPDB)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                abuse_score INTEGER DEFAULT 0,
                country TEXT,
                isp TEXT,
                is_malicious BOOLEAN DEFAULT 0,
                last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for connections table
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_src_ip 
            ON connections(src_ip)
        """)
        
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_dst_ip 
            ON connections(dst_ip)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_protocol 
            ON connections(protocol)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_start_time 
            ON connections(start_time)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_bytes 
            ON connections(total_bytes)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_direction 
            ON connections(direction)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp 
            ON alerts(timestamp)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity 
            ON alerts(severity_num)
        """)
        
        # Drop legacy packets table if it exists (data lives in pcapng now)
        self.cursor.execute("DROP TABLE IF EXISTS packets")

        # Drop legacy packet indexes
        for idx in ['idx_packets_timestamp', 'idx_packets_transport_protocol',
                     'idx_packets_application_protocol', 'idx_packets_src_ip',
                     'idx_packets_dst_ip', 'idx_packets_direction']:
            self.cursor.execute(f"DROP INDEX IF EXISTS {idx}")
        
        self.conn.commit()

    # ── Session management ──────────────────────────────────────

    def start_session(self, interface: Optional[str] = None) -> int:
        """
        Start a new capture session.
        
        Args:
            interface: Network interface name
            
        Returns:
            Session ID
        """
        with self._lock:
            self.cursor.execute("""
                INSERT INTO sessions (start_time, interface)
                VALUES (?, ?)
            """, (datetime.now(), interface))
            
            session_id = self.cursor.lastrowid
            self.conn.commit()
            
            return session_id
    
    def end_session(self, session_id: int, total_packets: int, total_bytes: int):
        """
        Mark a session as completed.
        
        Args:
            session_id: ID of the session to end
            total_packets: Total packets captured
            total_bytes: Total bytes transferred
        """
        with self._lock:
            self.cursor.execute("""
                UPDATE sessions 
                SET end_time = ?, 
                    total_packets = ?, 
                    total_bytes = ?,
                    status = 'completed'
                WHERE id = ?
            """, (datetime.now(), total_packets, total_bytes, session_id))
            
            self.conn.commit()

    # ── Connection/flow storage ─────────────────────────────────

    def flush_connections(self, flows: list, session_id: int = None):
        """Bulk insert connection/flow summaries from the tracker.
        
        Args:
            flows: List of flow dicts from ConnectionTracker.get_flows()
            session_id: Current capture session ID
        """
        with self._lock:
            try:
                for flow in flows:
                    self.cursor.execute("""
                        INSERT INTO connections (
                            src_ip, dst_ip, src_port, dst_port,
                            protocol, transport, direction,
                            start_time, end_time, duration,
                            total_packets, total_bytes, state, session_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        flow['src_ip'], flow['dst_ip'],
                        flow.get('src_port'), flow.get('dst_port'),
                        flow['protocol'], flow['transport'],
                        flow.get('direction', ''),
                        flow['start_time'], flow['end_time'],
                        flow.get('duration', 0),
                        flow['total_packets'], flow['total_bytes'],
                        flow.get('state', 'ACTIVE'),
                        session_id,
                    ))
                self.conn.commit()
            except Exception:
                pass  # Don't crash capture on DB errors

    def clear_connections(self):
        """Clear all connections (called before reprocessing)."""
        with self._lock:
            self.cursor.execute("DELETE FROM connections")
            self.cursor.execute("DELETE FROM protocol_stats")
            self.conn.commit()

    # ── Query methods ───────────────────────────────────────────

    def close(self):
        """Close the database connection."""
        with self._lock:
            if self.conn:
                self.conn.close()
                self.conn = None

    def get_packet_count(self) -> int:
        """Get total packet count (sum across all connections)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COALESCE(SUM(total_packets), 0) FROM connections")
        count = cursor.fetchone()[0]
        
        conn.close()
        return count
    
    def get_connection_count(self) -> int:
        """Get total number of connections/flows."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM connections")
        count = cursor.fetchone()[0]
        
        conn.close()
        return count

    def get_protocol_stats(self) -> List[tuple]:
        """
        Get protocol statistics.
        
        Returns:
            List of tuples: (protocol, packet_count, total_bytes)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT protocol, packet_count, total_bytes 
            FROM protocol_stats
            ORDER BY packet_count DESC
        """)
        
        stats = cursor.fetchall()
        conn.close()
        
        return stats

    def get_cumulative_stats(self) -> Dict:
        """Get cumulative stats from all connections."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Protocol breakdown from connections
        cursor.execute("""
            SELECT protocol, SUM(total_packets) as cnt, SUM(total_bytes) as bytes
            FROM connections
            GROUP BY protocol ORDER BY cnt DESC
        """)
        protocol_stats = cursor.fetchall()

        # Direction counts
        cursor.execute("""
            SELECT direction, SUM(total_packets) FROM connections
            WHERE direction IS NOT NULL AND direction != ''
            GROUP BY direction
        """)
        direction_counts = dict(cursor.fetchall())

        # Totals
        cursor.execute("""
            SELECT COALESCE(SUM(total_packets), 0), COALESCE(SUM(total_bytes), 0)
            FROM connections
        """)
        total_pkts, total_bytes = cursor.fetchone()

        # Session count
        cursor.execute("SELECT COUNT(*) FROM sessions")
        session_count = cursor.fetchone()[0]

        # Connection count
        cursor.execute("SELECT COUNT(*) FROM connections")
        connection_count = cursor.fetchone()[0]

        conn.close()
        return {
            'protocol_stats': protocol_stats,  # [(proto, count, bytes), ...]
            'direction_counts': direction_counts,
            'total_packets': total_pkts,
            'total_bytes': total_bytes,
            'session_count': session_count,
            'connection_count': connection_count,
        }

    def get_connections(self, limit: int = 50, order_by: str = 'total_bytes') -> List[tuple]:
        """
        Get connections ordered by the specified column.
        
        Args:
            limit: Maximum number of connections to return
            order_by: Column to sort by (total_bytes, total_packets, duration, start_time)
            
        Returns:
            List of tuples with connection data
        """
        # Whitelist allowed order columns
        allowed = {'total_bytes', 'total_packets', 'duration', 'start_time'}
        if order_by not in allowed:
            order_by = 'total_bytes'
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(f"""
            SELECT src_ip, dst_ip, src_port, dst_port,
                   protocol, direction, start_time, end_time,
                   duration, total_packets, total_bytes, state
            FROM connections
            ORDER BY {order_by} DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return rows

    def search_by_ip(self, ip_address: str) -> List[tuple]:
        """
        Search connections involving an IP address.
        
        Args:
            ip_address: IP address to search for
            
        Returns:
            List of matching connections
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT src_ip, dst_ip, src_port, dst_port,
                   protocol, direction, start_time, end_time,
                   duration, total_packets, total_bytes, state
            FROM connections
            WHERE src_ip = ? OR dst_ip = ?
            ORDER BY total_bytes DESC
            LIMIT 100
        """, (ip_address, ip_address))
        
        rows = cursor.fetchall()
        conn.close()
        
        return rows
    
    def search_by_protocol(self, protocol: str) -> List[tuple]:
        """
        Search connections by protocol.
        
        Args:
            protocol: Protocol name (TCP, QUIC, DNS, TLSv1.3, etc.)
            
        Returns:
            List of matching connections
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT src_ip, dst_ip, src_port, dst_port,
                   protocol, direction, start_time, end_time,
                   duration, total_packets, total_bytes, state
            FROM connections
            WHERE UPPER(protocol) = UPPER(?) OR UPPER(transport) = UPPER(?)
            ORDER BY total_bytes DESC
            LIMIT 100
        """, (protocol, protocol))
        
        rows = cursor.fetchall()
        conn.close()
        
        return rows

    def search_by_port(self, port: int) -> List[tuple]:
        """
        Search connections by port number.
        
        Args:
            port: Port number to search for
            
        Returns:
            List of matching connections
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT src_ip, dst_ip, src_port, dst_port,
                   protocol, direction, start_time, end_time,
                   duration, total_packets, total_bytes, state
            FROM connections
            WHERE src_port = ? OR dst_port = ?
            ORDER BY total_bytes DESC
            LIMIT 100
        """, (port, port))
        
        rows = cursor.fetchall()
        conn.close()
        
        return rows
    
    def get_top_talkers(self, limit: int = 10) -> List[tuple]:
        """
        Get most active IP addresses by total bytes transferred.
        
        Args:
            limit: Number of top IPs to return
            
        Returns:
            List of tuples: (ip, total_connections, total_packets, total_bytes)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Combine src and dst IPs, aggregate
        cursor.execute("""
            SELECT ip, COUNT(*) as connections, 
                   SUM(packets) as total_packets,
                   SUM(bytes) as total_bytes
            FROM (
                SELECT src_ip as ip, total_packets as packets, total_bytes as bytes FROM connections
                UNION ALL
                SELECT dst_ip as ip, total_packets as packets, total_bytes as bytes FROM connections
            )
            GROUP BY ip
            ORDER BY total_bytes DESC
            LIMIT ?
        """, (limit,))
        
        talkers = cursor.fetchall()
        conn.close()
        
        return talkers
    
    def get_database_size(self) -> str:
        """Get human-readable database size."""
        if not os.path.exists(self.db_path):
            return "0 B"
        
        size_bytes = os.path.getsize(self.db_path)
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        
        return f"{size_bytes:.2f} TB"
    
    def clear_old_data(self, days: int = 30):
        """
        Delete connections older than specified days.
        
        Args:
            days: Delete connections older than this many days
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM connections
            WHERE start_time < datetime('now', '-' || ? || ' days')
        """, (days,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted
    
    def delete_connections_by_date(self, date_str: str) -> int:
        """
        Delete connections for a specific date.

        Args:
            date_str: Date string in YYYY-MM-DD format
            
        Returns:
            Number of deleted connections
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM connections
            WHERE date(start_time) = ?
        """, (date_str,))
        
        deleted = cursor.rowcount
        
        # Recalculate protocol_stats from remaining connections
        if deleted > 0:
            cursor.execute("DELETE FROM protocol_stats")
            cursor.execute("""
                INSERT INTO protocol_stats (protocol, packet_count, total_bytes, last_seen)
                SELECT 
                    protocol,
                    SUM(total_packets) as packet_count,
                    SUM(total_bytes) as total_bytes,
                    MAX(end_time) as last_seen
                FROM connections
                GROUP BY protocol
            """)
        
        conn.commit()
        conn.close()
        
        return deleted

    def export_to_csv(self, output_file: str, limit: Optional[int] = None):
        """
        Export connections to CSV file.
        
        Args:
            output_file: Path to output CSV file
            limit: Maximum number of records to export (None = all)
        """
        import csv
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = """
            SELECT id, src_ip, dst_ip, src_port, dst_port,
                   protocol, transport, direction,
                   start_time, end_time, duration,
                   total_packets, total_bytes, state
            FROM connections 
            ORDER BY total_bytes DESC
        """
        if limit:
            query += f" LIMIT {limit}"
        
        cursor.execute(query)
        rows = cursor.fetchall()
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Connection_ID', 'Source_IP', 'Destination_IP',
                'Source_Port', 'Destination_Port',
                'Protocol', 'Transport', 'Direction',
                'Start_Time', 'End_Time', 'Duration_Seconds',
                'Total_Packets', 'Total_Bytes', 'State'
            ])
            writer.writerows(rows)
        
        conn.close()
        
        return len(rows)

    # ── Alert methods (Suricata IDS) ──────────────────────────

    def insert_alert(self, alert: Dict, session_id: int = None):
        """Insert a Suricata alert into the database."""
        with self._lock:
            try:
                self.cursor.execute("""
                    INSERT INTO alerts (timestamp, severity, severity_num, signature,
                        signature_id, category, src_ip, dst_ip, src_port, dst_port,
                        proto, action, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.get('timestamp', ''),
                    alert.get('severity', 'LOW'),
                    alert.get('severity_num', 3),
                    alert.get('signature', ''),
                    alert.get('signature_id', 0),
                    alert.get('category', ''),
                    alert.get('src_ip', ''),
                    alert.get('dst_ip', ''),
                    alert.get('src_port'),
                    alert.get('dst_port'),
                    alert.get('proto', ''),
                    alert.get('action', 'allowed'),
                    session_id,
                ))
                self.conn.commit()
            except Exception:
                pass

    def get_alerts(self, limit: int = 100) -> List[tuple]:
        """Get recent alerts ordered by timestamp descending."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT timestamp, severity, signature, category,
                   src_ip, dst_ip, dst_port, proto
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_threat_summary(self) -> Dict:
        """Get a summary of threats: severity counts, top attackers, top signatures."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Severity counts
        cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
        severity_counts = dict(cursor.fetchall())

        # Top source IPs (attackers)
        cursor.execute("""
            SELECT src_ip, COUNT(*) as cnt FROM alerts
            GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
        """)
        top_attackers = cursor.fetchall()

        # Top signatures
        cursor.execute("""
            SELECT signature, COUNT(*) as cnt FROM alerts
            GROUP BY signature ORDER BY cnt DESC LIMIT 10
        """)
        top_signatures = cursor.fetchall()

        # Total
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total = cursor.fetchone()[0]

        conn.close()
        return {
            'total': total,
            'severity_counts': severity_counts,
            'top_attackers': top_attackers,
            'top_signatures': top_signatures,
        }

    def get_alert_count(self) -> int:
        """Get total alert count."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def cache_ip_reputation(self, ip: str, abuse_score: int, country: str = '',
                            isp: str = ''):
        """Cache an IP reputation result from AbuseIPDB."""
        with self._lock:
            try:
                self.cursor.execute("""
                    INSERT OR REPLACE INTO ip_reputation
                        (ip, abuse_score, country, isp, is_malicious, last_checked)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (ip, abuse_score, country, isp, abuse_score > 50))
                self.conn.commit()
            except Exception:
                pass

    def get_ip_reputation(self, ip: str) -> Optional[Dict]:
        """Get cached IP reputation, or None if not cached."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT abuse_score, country, isp, is_malicious, last_checked
            FROM ip_reputation WHERE ip = ?
        """, (ip,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {
                'abuse_score': row[0], 'country': row[1], 'isp': row[2],
                'is_malicious': bool(row[3]), 'last_checked': row[4],
            }
        return None
