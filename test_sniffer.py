#!/usr/bin/env python3
"""
NetGuard - Wireshark-Inspired Packet Sniffer Test
Run with: sudo python3 test_sniffer.py [--csv output.csv]
"""
from core.sniffer import PacketSniffer
import sys


def main():
    print("=" * 80)
    print("NetGuard - Wireshark-Inspired Network Traffic Analyzer (Phase 3)")
    print("=" * 80)
    print("\n🎯 NEW FEATURES:")
    print("   ✓ Sequential packet IDs for tracking")
    print("   ✓ High-precision timestamps (microseconds) + relative time")
    print("   ✓ Two-tier protocol classification (Transport + Application)")
    print("   ✓ Separate port columns for analysis")
    print("   ✓ Dynamic TCP Info with connection state (SYN, ACK, FIN, RST)")
    print("   ✓ TCP flag extraction and visualization")
    print("   ✓ TLS handshake detection (0x16 byte check)")
    print("   ✓ Traffic direction detection (INCOMING/OUTGOING)")
    print("   ✓ Comprehensive runtime statistics")
    print("   ✓ Enhanced CSV export with all fields")
    print()
    print("💾 Storage:")
    print("   Database: data/netguard.db (SQLite with enhanced schema)")
    if "--csv" in sys.argv:
        csv_idx = sys.argv.index("--csv")
        if csv_idx + 1 < len(sys.argv):
            csv_file = sys.argv[csv_idx + 1]
            print(f"   CSV Export: {csv_file} (real-time logging)")
    print()
    print("💡 Generate diverse traffic to see intelligent detection:")
    print("   ping 8.8.8.8                    # ICMP Echo Request/Reply")
    print("   curl http://example.com         # HTTP with TCP handshake")
    print("   curl https://google.com         # HTTPS with TLS detection")
    print("   ssh user@host                   # SSH connection lifecycle")
    print()
    print("🔍 After capture, query your enhanced data:")
    print("   python3 query_db.py --stats          # Protocol breakdown")
    print("   python3 query_db.py --recent 100     # Last 100 packets")
    print("   python3 query_db.py --export full.csv # Export all enhanced fields")
    print()
    print("📚 See DATABASE_GUIDE.md and PROTOCOL_DETECTION.md for details")
    print("\n⚠️  Press Ctrl+C to stop and see comprehensive session summary\n")
    
    # Check for CSV export option
    csv_file = None
    if "--csv" in sys.argv:
        csv_idx = sys.argv.index("--csv")
        if csv_idx + 1 < len(sys.argv):
            csv_file = sys.argv[csv_idx + 1]
            print(f"📝 CSV logging enabled: {csv_file}\n")
    
    # Initialize sniffer with Wireshark-inspired features
    sniffer = PacketSniffer(
        interface=None,
        db_path="data/netguard.db",
        csv_file=csv_file
    )
    
    # Capture packets (use 0 for infinite, or specify count)
    sniffer.start(count=0)


if __name__ == "__main__":
    main()
