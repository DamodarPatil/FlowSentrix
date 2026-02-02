"""
NetGuard Packet Sniffer Module
Refined for Phase 1: Monitoring & Data Extraction
"""
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw
from datetime import datetime
import threading

class PacketSniffer:
    """Core engine to capture and parse network traffic."""
    
    def __init__(self, interface=None):
        self.interface = interface
        self.stop_sniffing = threading.Event() # To stop thread gracefully later
        self.packets_captured = 0

    def get_protocol_name(self, protocol_num):
        """Helper to convert numbers to names (if needed)"""
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protocol_map.get(protocol_num, str(protocol_num))

    def analyze_packet(self, packet):
        """
        Extracts ONLY the data we need for the Dashboard.
        Returns: Dictionary (Clean Data) or None
        """
        packet_data = {}
        
        # 1. Basic Info
        packet_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packet_data["size"] = len(packet) # Vital for bandwidth monitoring!
        
        # 2. Extract IP Layer
        if IP in packet:
            packet_data["src"] = packet[IP].src
            packet_data["dst"] = packet[IP].dst
            packet_data["protocol"] = self.get_protocol_name(packet[IP].proto)
        elif IPv6 in packet:
            packet_data["src"] = packet[IPv6].src
            packet_data["dst"] = packet[IPv6].dst
            packet_data["protocol"] = "IPv6"
        elif ARP in packet:
            packet_data["src"] = packet[ARP].psrc
            packet_data["dst"] = packet[ARP].pdst
            packet_data["protocol"] = "ARP"
            packet_data["info"] = "Who has " + packet[ARP].pdst + "?"
            return packet_data # ARP stops here
        else:
            return None # Ignore non-IP/ARP traffic for now

        # 3. specific Protocol Detail & "Human Readable Info"
        packet_data["info"] = "" # Default empty info
        
        if TCP in packet:
            packet_data["protocol"] = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Smart Tagging (The "NetGuard" Feature)
            if dst_port == 80 or src_port == 80:
                packet_data["info"] = f"HTTP Web Traffic ({dst_port})"
            elif dst_port == 443 or src_port == 443:
                packet_data["info"] = f"HTTPS Secure Web ({dst_port})"
            elif dst_port == 22 or src_port == 22:
                packet_data["info"] = f"SSH Remote Access ({dst_port})"
            else:
                packet_data["info"] = f"TCP Connection : {dst_port}"

        elif UDP in packet:
            packet_data["protocol"] = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            if dst_port == 53 or src_port == 53:
                packet_data["protocol"] = "DNS"
                packet_data["info"] = "Domain Name Resolution"
            else:
                packet_data["info"] = f"UDP Data : {dst_port}"

        elif ICMP in packet:
            packet_data["protocol"] = "ICMP"
            packet_data["info"] = "Ping Request/Reply"

        return packet_data

    def packet_callback(self, packet):
        """Callback that runs on every single packet"""
        self.packets_captured += 1
        
        # Process the raw packet into clean data
        data = self.analyze_packet(packet)
        
        if data:
            # === DEMO MODE: Print nicely formatted table row ===
            # Later, we will send 'data' to the Database/GUI instead of printing
            print(f"[{data['timestamp']}] {data['protocol']:<6} | {data['src']:<15} -> {data['dst']:<15} | Size: {data['size']:<5} | {data['info']}")

    def start(self, count=0):
        """Start capturing."""
        print(f"[*] NetGuard Monitoring Started on {self.interface or 'Default Interface'}...")
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=count,
                store=False
            )
        except PermissionError:
            print("[!] Error: You need to run this as root (sudo).")
        except Exception as e:
            print(f"[!] Sniffer Error: {e}")

if __name__ == "__main__":
    # Test Run
    tool = PacketSniffer()
    tool.start(count=1000)