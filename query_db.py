#!/usr/bin/env python3
"""
NetGuard Database Query Tool
Query and analyze captured network traffic from SQLite database.
"""
import sys
import argparse
from core.database import NetGuardDatabase
from datetime import datetime


def format_connection_row(conn):
    """Format connection data for display."""
    src_ip, dst_ip, src_port, dst_port, protocol, direction, \
        start_time, end_time, duration, total_packets, total_bytes, state = conn

    src = f"{src_ip}:{src_port}" if src_port else src_ip
    dst = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
    src = src[:22] if len(src) <= 22 else src[:19] + "..."
    dst = dst[:22] if len(dst) <= 22 else dst[:19] + "..."
    dur = f"{duration:.1f}s" if duration else "-"

    return f"{protocol:<8} | {src:<22} → {dst:<22} | {total_packets:>6} pkts | {format_bytes(total_bytes):>10} | {dur:>8} | {state}"


def show_connections(db, limit=50):
    """Show top connections by bytes."""
    print(f"\n📊 Top {limit} Connections (by bytes)")
    print("=" * 120)

    connections = db.get_connections(limit)

    if not connections:
        print("No connections found in database.")
        return

    for conn in connections:
        print(format_connection_row(conn))

    print(f"\nShowing {len(connections)} of {db.get_connection_count()} total connections")
    print(f"({db.get_packet_count():,} total packets)")


def show_stats(db):
    """Show protocol statistics."""
    print("\n📈 Protocol Statistics")
    print("=" * 70)

    stats = db.get_protocol_stats()

    if not stats:
        print("No statistics available.")
        return

    total_packets = sum(s[1] for s in stats)
    total_bytes = sum(s[2] for s in stats)

    print(f"Total Packets: {total_packets:,}")
    print(f"Total Bytes: {format_bytes(total_bytes)}")
    print(f"Connections: {db.get_connection_count():,}")
    print(f"Database Size: {db.get_database_size()}")
    print("\nProtocol Breakdown:")
    print("-" * 70)

    for protocol, count, bytes_val in stats:
        percentage = (count / total_packets * 100) if total_packets > 0 else 0
        bar_length = int(percentage / 2)
        bar = "█" * bar_length + "░" * (50 - bar_length)
        print(f"  {protocol:<10} : {count:>8,} packets ({percentage:>5.1f}%) | {format_bytes(bytes_val):>10} {bar}")


def format_bytes(bytes_value):
    """Convert bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} TB"


def search_ip(db, ip_address):
    """Search for connections by IP address."""
    print(f"\n🔍 Searching for IP: {ip_address}")
    print("=" * 120)

    connections = db.search_by_ip(ip_address)

    if not connections:
        print(f"No connections found for IP: {ip_address}")
        return

    print(f"Found {len(connections)} connection(s):\n")

    for conn in connections:
        print(format_connection_row(conn))


def search_protocol(db, protocol):
    """Search for connections by protocol."""
    print(f"\n🔍 Searching for Protocol: {protocol}")
    print("=" * 120)

    connections = db.search_by_protocol(protocol.upper())

    if not connections:
        print(f"No connections found for protocol: {protocol}")
        return

    print(f"Found {len(connections)} connection(s):\n")

    for conn in connections[:100]:
        print(format_connection_row(conn))

    if len(connections) > 100:
        print(f"\n... and {len(connections) - 100} more. Use --export to see all.")


def show_top_talkers(db, limit=10):
    """Show most active IP addresses."""
    print(f"\n🗣️  Top {limit} Most Active IPs")
    print("=" * 60)

    talkers = db.get_top_talkers(limit)

    if not talkers:
        print("No data available.")
        return

    for i, talker in enumerate(talkers, 1):
        if len(talker) == 4:
            ip, connections, packets, total_bytes = talker
            print(f"  {i:2}. {ip:<22} : {connections:>4} connections, {packets:>8,} pkts, {format_bytes(total_bytes):>10}")
        else:
            ip, count = talker
            print(f"  {i:2}. {ip:<22} : {count:>8,} packets")


def export_csv(db, output_file, limit=None):
    """Export database to CSV."""
    print(f"\n📤 Exporting to CSV: {output_file}")

    count = db.export_to_csv(output_file, limit)

    print(f"✅ Exported {count} connections to {output_file}")


def delete_date(db, date_str, force=False):
    """Delete connections for a specific date."""
    print(f"\n🗑️  Deleting connections for date: {date_str}")

    if not force:
        try:
            response = input(f"Are you sure you want to delete all connections from {date_str}? [y/N] ")
            if response.lower() != 'y':
                print("Operation cancelled.")
                return
        except EOFError:
            print("Error: Input stream closed. Use --force to skip confirmation.")
            return

    count = db.delete_connections_by_date(date_str)
    print(f"✅ Deleted {count} connections.")


def recalculate_stats(db):
    """Recalculate protocol statistics from connections table."""
    import sqlite3
    print("\n🔄 Recalculating protocol statistics...")

    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM protocol_stats')
    cursor.execute('''
        INSERT INTO protocol_stats (protocol, packet_count, total_bytes, last_seen)
        SELECT protocol, SUM(total_packets), SUM(total_bytes), MAX(end_time)
        FROM connections GROUP BY protocol
    ''')
    conn.commit()
    conn.close()

    print("✅ Stats recalculated!")


def main():
    parser = argparse.ArgumentParser(
        description="NetGuard Database Query Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --connections 100                Show top 100 connections
  %(prog)s --stats                          Show protocol statistics
  %(prog)s --ip 192.168.1.100               Search by IP address
  %(prog)s --protocol TCP                   Search by protocol
  %(prog)s --top-talkers 20                 Show top 20 active IPs
  %(prog)s --export output.csv              Export all to CSV
  %(prog)s --export output.csv --limit 1000 Export last 1000 to CSV
  %(prog)s --delete-date 2026-02-04         Delete connections for date
  %(prog)s --recalculate-stats              Rebuild protocol statistics
        """
    )

    parser.add_argument('--db', default='data/netguard.db',
                       help='Database path (default: data/netguard.db)')
    parser.add_argument('--connections', type=int, metavar='N', nargs='?', const=50,
                       help='Show top N connections by bytes (default: 50)')
    parser.add_argument('--stats', action='store_true',
                       help='Show protocol statistics')
    parser.add_argument('--ip', metavar='IP_ADDRESS',
                       help='Search connections by IP address')
    parser.add_argument('--protocol', metavar='PROTOCOL',
                       help='Search connections by protocol (TCP, UDP, DNS, etc.)')
    parser.add_argument('--top-talkers', type=int, metavar='N',
                       help='Show top N most active IP addresses')
    parser.add_argument('--export', metavar='CSV_FILE',
                       help='Export connections to CSV file')
    parser.add_argument('--limit', type=int, metavar='N',
                       help='Limit export to N connections (used with --export)')
    parser.add_argument('--delete-date', metavar='YYYY-MM-DD',
                       help='Delete connections for a specific date')
    parser.add_argument('--force', action='store_true',
                       help='Force deletion without confirmation')
    parser.add_argument('--recalculate-stats', action='store_true',
                       help='Recalculate protocol statistics from connections')

    args = parser.parse_args()

    # Initialize database
    db = NetGuardDatabase(args.db)

    # If no arguments, show stats by default
    if len(sys.argv) == 1:
        show_stats(db)
        print()
        show_connections(db, 20)
        return

    # Execute requested operations
    if args.stats:
        show_stats(db)

    if args.connections is not None:
        if args.connections <= 0:
            print("[!] Error: --connections must be a positive number.")
            sys.exit(1)
        show_connections(db, args.connections)

    if args.ip:
        search_ip(db, args.ip)

    if args.protocol:
        search_protocol(db, args.protocol)

    if args.top_talkers is not None:
        if args.top_talkers <= 0:
            print("[!] Error: --top-talkers must be a positive number.")
            sys.exit(1)
        show_top_talkers(db, args.top_talkers)

    if args.export:
        if args.limit is not None and args.limit <= 0:
            print("[!] Error: --limit must be a positive number.")
            sys.exit(1)
        export_csv(db, args.export, args.limit)
    elif args.limit is not None:
        print("[!] Warning: --limit has no effect without --export.")

    if args.delete_date:
        delete_date(db, args.delete_date, args.force)

    if args.recalculate_stats:
        recalculate_stats(db)

    print()  # Final newline


if __name__ == "__main__":
    main()
