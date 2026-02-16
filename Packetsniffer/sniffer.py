from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
from collections import defaultdict
import argparse

# Dictionary to count packets by protocol
packet_counts = defaultdict(int)

# Packet log
packet_log = []

# Counter for display
packet_counter = 0

def analyze_packet(packet):
    """
    Analyze each captured packet, log details, and perform analysis.
    """
    global packet_log, packet_counter

    packet_counter += 1

    # Basic info
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"\n[Packet #{packet_counter}]")
        
        if protocol == 6:  # TCP
            packet_counts['TCP'] += 1
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                print(f"  Protocol: TCP")
                print(f"  Source: {src_ip}:{src_port}")
                print(f"  Destination: {dst_ip}:{dst_port}")
                print(f"  Flags: {flags}")
        elif protocol == 17:  # UDP
            packet_counts['UDP'] += 1
            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"  Protocol: UDP")
                print(f"  Source: {src_ip}:{src_port}")
                print(f"  Destination: {dst_ip}:{dst_port}")
        elif protocol == 1:  # ICMP
            packet_counts['ICMP'] += 1
            print(f"  Protocol: ICMP")
            print(f"  Source: {src_ip}")
            print(f"  Destination: {dst_ip}")
        else:
            packet_counts['Other'] += 1
            print(f"  Protocol: Other ({protocol})")
            print(f"  Source: {src_ip}")
            print(f"  Destination: {dst_ip}")

        print(f"  Packet Length: {len(packet)} bytes")

        # Log packet details
        packet_log.append(packet)

        # Detect suspicious activity
        detect_suspicious_activity(packet)
    else:
        print(f"\n[Packet #{packet_counter}] Non-IP packet detected")

def detect_suspicious_activity(packet):
    """
    Perform basic anomaly detection for suspicious activity.
    """
    if TCP in packet and packet[TCP].flags == "S":  # SYN flag
        print(f"  [!] ALERT: Potential SYN Scan Detected")
    if UDP in packet and len(packet[UDP].payload) > 500:  # Large UDP packet
        print(f"  [!] ALERT: Large UDP Packet ({len(packet[UDP].payload)} bytes)")
    if IP in packet and packet[IP].len > 1500:  # Unusually large IP packet
        print(f"  [!] ALERT: Large IP Packet ({packet[IP].len} bytes)")

def save_to_pcap(file_name):
    """
    Save captured packets to a .pcap file.
    """
    if packet_log:
        wrpcap(file_name, packet_log)
        print(f"\n[+] {len(packet_log)} packets saved to {file_name}")
    else:
        print("\n[-] No packets captured to save.")

def print_statistics():
    """
    Print packet statistics.
    """
    print("\n" + "="*50)
    print("[Packet Statistics]")
    print("="*50)
    total = sum(packet_counts.values())
    for protocol, count in packet_counts.items():
        percentage = (count / total * 100) if total > 0 else 0
        print(f"  {protocol}: {count} ({percentage:.1f}%)")
    print(f"\n  Total Packets: {total}")
    print("="*50)

def main():
    """
    Main function to handle packet sniffing with user-defined options.
    """
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer with Scapy")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff on (default: default interface)")
    parser.add_argument("-c", "--count", type=int, default=10, help="Number of packets to capture (default: 10, 0 for unlimited)")
    parser.add_argument("-f", "--filter", type=str, default="", help="BPF filter string (e.g., 'tcp', 'udp', 'port 80')")
    parser.add_argument("-o", "--output", type=str, default="packets.pcap", help="Output file to save packets")

    args = parser.parse_args()

    try:
        print("="*50)
        print("     PACKET SNIFFER STARTED")
        print("="*50)
        if args.interface:
            print(f"[+] Interface: {args.interface}")
        else:
            print(f"[+] Interface: Default")
        print(f"[+] Packet Count: {'Unlimited' if args.count == 0 else args.count}")
        print(f"[+] Filter: {args.filter if args.filter else 'None (all packets)'}")
        print(f"[+] Output File: {args.output}")
        print("="*50)
        print("\nPress Ctrl+C to stop capturing...\n")
        
        if args.interface:
            sniff(iface=args.interface, filter=args.filter, count=args.count, prn=analyze_packet)
        else:
            sniff(filter=args.filter, count=args.count, prn=analyze_packet)
            
    except KeyboardInterrupt:
        print("\n\n[!] Sniffing interrupted by user")
    except PermissionError:
        print("\n[-] Error: Administrator/root privileges required for packet sniffing")
    except Exception as e:
        print(f"\n[-] Error: {e}")
    finally:
        save_to_pcap(args.output)
        print_statistics()

if __name__ == "__main__":
    main()