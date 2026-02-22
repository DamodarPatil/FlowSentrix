"""
Behavioral Tagging Engine for NetGuard.

Provides 4 statistical/volume-based detectors that complement Suricata's
signature-based detection. These detect patterns Suricata CANNOT:

1. Beaconing     — periodic C2 callbacks (timing analysis)
2. Data Exfil    — large outbound transfers to external IPs
3. New Dest      — first-ever connection to unknown IP
4. Traffic Anomaly — deviation from per-IP rolling baseline

Usage:
    engine = BehaviorEngine(db)
    tags = engine.analyze(flows)   # {flow_key: [(tag, severity, reason), ...]}
"""

import statistics
from typing import Dict, List, Tuple, Optional
from datetime import datetime


# Tag severity levels
SEVERITY_LOW = 'low'
SEVERITY_MEDIUM = 'medium'
SEVERITY_HIGH = 'high'
SEVERITY_CRITICAL = 'critical'

# Thresholds (tunable)
BEACON_MIN_CONNECTIONS = 5       # Min connections to same dst to check beaconing
BEACON_CV_THRESHOLD = 0.20       # Coefficient of variation < 0.20 = periodic

EXFIL_MEDIUM_BYTES = 50 * 1024 * 1024    # 50 MB
EXFIL_HIGH_BYTES = 200 * 1024 * 1024     # 200 MB

ANOMALY_MULTIPLIER = 5.0         # Flag if > 5× rolling average

# Private/local IP prefixes (skip for exfil detection)
_PRIVATE_PREFIXES = (
    '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
    '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
    '127.', '169.254.', '0.0.0.0',
    '::', 'fe80:', 'fc', 'fd', 'ff',
)


def _is_private(ip: str) -> bool:
    """Check if an IP is private/local/multicast."""
    if not ip:
        return True
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


class BehaviorEngine:
    """Statistical behavioral analysis engine.

    Analyzes connection flows to detect patterns that signature-based
    engines like Suricata cannot: beaconing, data exfiltration,
    new destinations, and traffic anomalies.
    """

    def __init__(self, db=None):
        """Initialize the engine.

        Args:
            db: NetGuardDatabase instance (for known_destinations lookups)
        """
        self._db = db

    def analyze(self, flows: List[dict], ip_to_domain: Dict[str, str] = None) -> Dict[str, List[Tuple[str, str, str]]]:
        """Run all detectors on a batch of flows.

        Args:
            flows: List of flow dicts from ConnectionTracker.get_flows()
            ip_to_domain: Optional IP→domain mapping from DNS responses
                          (enables CDN-aware beaconing detection)

        Returns:
            Dict mapping flow index → [(tag, severity, reason), ...]
            Only flows with detected behaviors are included.
        """
        if not flows:
            return {}

        all_tags: Dict[int, List[Tuple[str, str, str]]] = {}

        # Run each detector
        detectors = [
            lambda f: self._detect_beaconing(f, ip_to_domain or {}),
            self._detect_data_exfil,
            self._detect_new_destination,
            self._detect_traffic_anomaly,
        ]
        for detector in detectors:
            results = detector(flows)
            for idx, tag, severity, reason in results:
                if idx not in all_tags:
                    all_tags[idx] = []
                all_tags[idx].append((tag, severity, reason))

        return all_tags

    def _detect_beaconing(self, flows: List[dict], ip_to_domain: Dict[str, str] = None) -> List[Tuple[int, str, str, str]]:
        """Detect periodic C2-style beaconing.

        Groups flows by (src_ip, destination) pair. The destination is resolved
        to a domain name via DNS lookups when available, so that CDN-rotated IPs
        (e.g., Cloudflare serving example.com from multiple IPs) are grouped
        together. Falls back to raw dst_ip when no DNS mapping exists.

        Also deduplicates flows that start within 1 second of each other to
        the same destination (handles TCP + TLS being tracked as separate flows).

        Returns:
            List of (flow_index, 'beaconing', severity, reason)
        """
        results = []
        if ip_to_domain is None:
            ip_to_domain = {}

        # Group flows by src → destination (domain or IP)
        pairs: Dict[tuple, List[Tuple[int, dict]]] = {}
        for i, flow in enumerate(flows):
            src = flow.get('src_ip', '')
            dst_ip = flow.get('dst_ip', '')
            # Resolve dst_ip to domain if known (CDN-aware grouping)
            dst_key = ip_to_domain.get(dst_ip, dst_ip)
            key = (src, dst_key)
            if key not in pairs:
                pairs[key] = []
            pairs[key].append((i, flow))

        for (src, dst), group in pairs.items():
            if len(group) < BEACON_MIN_CONNECTIONS:
                continue

            # Skip multicast/broadcast
            if dst.startswith('ff') or dst.startswith('224.') or dst.startswith('239.'):
                continue

            # Extract start times and sort
            times = []
            for idx, flow in group:
                try:
                    t = datetime.fromisoformat(flow.get('start_time', ''))
                    times.append((t, idx))
                except (ValueError, TypeError):
                    continue

            if len(times) < BEACON_MIN_CONNECTIONS:
                continue

            times.sort(key=lambda x: x[0])

            # Deduplicate flows starting within 1 second of each other
            # (handles TCP handshake + TLS data being separate flows)
            deduped = [times[0]]
            for j in range(1, len(times)):
                if (times[j][0] - deduped[-1][0]).total_seconds() > 1.0:
                    deduped.append(times[j])

            if len(deduped) < BEACON_MIN_CONNECTIONS:
                continue

            # Compute inter-connection intervals (seconds)
            intervals = []
            for j in range(1, len(deduped)):
                delta = (deduped[j][0] - deduped[j - 1][0]).total_seconds()
                if delta > 0:
                    intervals.append(delta)

            if len(intervals) < BEACON_MIN_CONNECTIONS - 1:
                continue

            # Coefficient of variation = stdev / mean
            mean = statistics.mean(intervals)
            if mean < 1.0:  # Too fast — likely just burst traffic, not beaconing
                continue

            stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
            cv = stdev / mean if mean > 0 else float('inf')

            if cv < BEACON_CV_THRESHOLD:
                # Use domain name in reason if available
                display_dst = dst
                reason = (
                    f"{len(deduped)} connections to {display_dst}, "
                    f"interval ~{mean:.1f}s (CV={cv:.3f})"
                )
                # Tag all flows in this group
                for idx, _ in group:
                    results.append((idx, 'beaconing', SEVERITY_HIGH, reason))

        return results

    def _detect_data_exfil(self, flows: List[dict]) -> List[Tuple[int, str, str, str]]:
        """Detect large outbound data transfers.

        Aggregates outbound bytes per destination IP across all flows,
        then flags if the total exceeds the threshold. This catches
        split uploads (e.g., 60 MB across 30 × 2 MB connections).

        Returns:
            List of (flow_index, 'data_exfil', severity, reason)
        """
        results = []

        # Aggregate outbound bytes per destination
        dst_bytes: Dict[str, int] = {}
        dst_flows: Dict[str, List[int]] = {}

        for i, flow in enumerate(flows):
            if flow.get('direction', '') != 'OUTGOING':
                continue

            dst_ip = flow.get('dst_ip', '')
            if _is_private(dst_ip):
                continue

            dst_bytes[dst_ip] = dst_bytes.get(dst_ip, 0) + flow.get('total_bytes', 0)
            if dst_ip not in dst_flows:
                dst_flows[dst_ip] = []
            dst_flows[dst_ip].append(i)

        # Check aggregated totals
        for dst_ip, total_bytes in dst_bytes.items():
            if total_bytes >= EXFIL_HIGH_BYTES:
                mb = total_bytes / (1024 * 1024)
                reason = f"{mb:.1f} MB uploaded to {dst_ip}"
                for idx in dst_flows[dst_ip]:
                    results.append((idx, 'data_exfil', SEVERITY_HIGH, reason))
            elif total_bytes >= EXFIL_MEDIUM_BYTES:
                mb = total_bytes / (1024 * 1024)
                reason = f"{mb:.1f} MB uploaded to {dst_ip}"
                for idx in dst_flows[dst_ip]:
                    results.append((idx, 'data_exfil', SEVERITY_MEDIUM, reason))

        return results

    def _detect_new_destination(self, flows: List[dict]) -> List[Tuple[int, str, str, str]]:
        """Detect connections to never-before-seen IPs.

        Queries the known_destinations table. IPs not in the table
        are tagged as 'new_dest'.

        Returns:
            List of (flow_index, 'new_dest', severity, reason)
        """
        results = []

        if not self._db:
            return results

        # Collect unique destination IPs from flows
        dst_ips = set()
        for flow in flows:
            dst = flow.get('dst_ip', '')
            if dst and not _is_private(dst):
                dst_ips.add(dst)

        if not dst_ips:
            return results

        # Check which are known
        known = self._db.get_known_destinations(dst_ips)

        for i, flow in enumerate(flows):
            dst = flow.get('dst_ip', '')
            if dst and not _is_private(dst) and dst not in known:
                results.append((
                    i, 'new_dest', SEVERITY_LOW,
                    f"First connection to {dst}"
                ))

        return results

    def _detect_traffic_anomaly(self, flows: List[dict]) -> List[Tuple[int, str, str, str]]:
        """Detect traffic volume anomalies per destination IP.

        Compares current session bytes to the rolling average for each
        destination. Flags if current > N× average.

        Returns:
            List of (flow_index, 'traffic_anomaly', severity, reason)
        """
        results = []

        if not self._db:
            return results

        # Aggregate bytes per destination in this batch
        dst_bytes: Dict[str, int] = {}
        dst_flows: Dict[str, List[int]] = {}
        for i, flow in enumerate(flows):
            dst = flow.get('dst_ip', '')
            if not dst or _is_private(dst):
                continue
            dst_bytes[dst] = dst_bytes.get(dst, 0) + flow.get('total_bytes', 0)
            if dst not in dst_flows:
                dst_flows[dst] = []
            dst_flows[dst].append(i)

        if not dst_bytes:
            return results

        # Get rolling averages from DB
        averages = self._db.get_destination_averages(set(dst_bytes.keys()))

        for dst_ip, current_bytes in dst_bytes.items():
            avg = averages.get(dst_ip)
            if avg is None or avg < 1024:  # Skip if no baseline or too small
                continue

            ratio = current_bytes / avg
            if ratio >= ANOMALY_MULTIPLIER:
                mb_current = current_bytes / (1024 * 1024)
                mb_avg = avg / (1024 * 1024)
                reason = (
                    f"{dst_ip}: {mb_current:.1f} MB this session "
                    f"vs {mb_avg:.1f} MB average ({ratio:.1f}×)"
                )
                for idx in dst_flows.get(dst_ip, []):
                    results.append((idx, 'traffic_anomaly', SEVERITY_MEDIUM, reason))

        return results
