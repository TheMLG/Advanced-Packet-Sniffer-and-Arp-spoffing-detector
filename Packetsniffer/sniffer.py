from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, ARP
from collections import defaultdict
import argparse
import time

# Packet statistics
packet_counts = defaultdict(int)
arp_stats = defaultdict(int)

# Logs
packet_log = []
alert_log = []
arp_table = {}

# Counters
packet_counter = 0
arp_counter = 0

def analyze_packet(packet):
    """
    Analyze all types of packets (IP, ARP, etc).
    """
    global packet_counter
    
    # Check if it's an ARP packet
    if ARP in packet:
        analyze_arp_packet(packet)
    elif IP in packet:
        analyze_ip_packet(packet)
    else:
        packet_counter += 1
        print(f"\n[Packet #{packet_counter}] Non-IP/ARP packet detected")

def analyze_ip_packet(packet):
    """
    Analyze IP packets (TCP, UDP, ICMP, etc).
    """
    global packet_log, packet_counter

    packet_counter += 1
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
            
            # Detect SYN scan
            if flags == "S":
                print(f"  [!] ALERT: Potential SYN Scan Detected")
                
    elif protocol == 17:  # UDP
        packet_counts['UDP'] += 1
        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  Protocol: UDP")
            print(f"  Source: {src_ip}:{src_port}")
            print(f"  Destination: {dst_ip}:{dst_port}")
            
            # Detect large UDP packets
            if len(packet[UDP].payload) > 500:
                print(f"  [!] ALERT: Large UDP Packet ({len(packet[UDP].payload)} bytes)")
                
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
    packet_log.append(packet)

def analyze_arp_packet(packet):
    """
    Analyze ARP packets and detect spoofing.
    """
    global arp_table, arp_counter, arp_stats
    
    if packet[ARP].op in (1, 2):  # ARP request or reply
        arp_counter += 1
        
        src_mac = packet[ARP].hwsrc
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        
        packet_type = "REQUEST" if packet[ARP].op == 1 else "REPLY"
        arp_stats[packet_type] += 1
        
        print(f"\n[ARP Packet #{arp_counter}]")
        print(f"  Type: {packet_type}")
        print(f"  Source IP: {src_ip}")
        print(f"  Source MAC: {src_mac}")
        print(f"  Destination IP: {dst_ip}")
        
        # Detect gratuitous ARP
        if packet[ARP].op == 2 and src_ip == dst_ip:
            print(f"  [!] ALERT: Gratuitous ARP detected")
            arp_stats['Gratuitous'] += 1
        
        # Check for ARP spoofing
        if src_ip in arp_table:
            stored_mac = arp_table[src_ip]
            
            if stored_mac != src_mac:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                
                print(f"  [!] ARP SPOOFING DETECTED!")
                print(f"      IP {src_ip}: MAC changed from {stored_mac} to {src_mac}")
                print(f"      Timestamp: {timestamp}")
                
                alert_log.append({
                    'timestamp': timestamp,
                    'ip': src_ip,
                    'old_mac': stored_mac,
                    'new_mac': src_mac,
                    'packet_number': arp_counter
                })
                
                arp_stats['Spoofing'] += 1
            else:
                print(f"  Status: Valid")
        else:
            arp_table[src_ip] = src_mac
            print(f"  Status: New ARP entry")
            arp_stats['New Entries'] += 1
        
        packet_log.append(packet)

def save_to_pcap(file_name):
    """
    Save captured packets to a .pcap file.
    """
    if packet_log:
        wrpcap(file_name, packet_log)
        print(f"\n[+] {len(packet_log)} packets saved to {file_name}")
    else:
        print("\n[-] No packets captured to save.")

def save_alerts(filename):
    """
    Save ARP spoofing alerts to file.
    """
    if alert_log:
        with open(filename, 'w') as f:
            f.write("ARP SPOOFING DETECTION LOG\n")
            f.write("="*60 + "\n\n")
            for alert in alert_log:
                f.write(f"[{alert['timestamp']}] Packet #{alert['packet_number']}\n")
                f.write(f"IP: {alert['ip']}\n")
                f.write(f"Old MAC: {alert['old_mac']}\n")
                f.write(f"New MAC: {alert['new_mac']}\n")
                f.write("-"*60 + "\n")
        print(f"[+] ARP alerts saved to {filename}")

def print_statistics():
    """
    Print comprehensive statistics.
    """
    print("\n" + "="*60)
    print("[PACKET STATISTICS]")
    print("="*60)
    total_ip = sum(packet_counts.values())
    if total_ip > 0:
        for protocol, count in packet_counts.items():
            percentage = (count / total_ip * 100)
            print(f"  {protocol}: {count} ({percentage:.1f}%)")
        print(f"\n  Total IP Packets: {total_ip}")
    
    print("\n" + "-"*60)
    print("[ARP STATISTICS]")
    print("-"*60)
    for stat_type, count in arp_stats.items():
        print(f"  {stat_type}: {count}")
    print(f"\n  Total ARP Packets: {arp_counter}")
    print(f"  Total Packets: {packet_counter}")
    print("="*60)
    
    if alert_log:
        print("\n" + "="*60)
        print("[ARP SPOOFING ALERTS]")
        print("="*60)
        for alert in alert_log:
            print(f"\n  [{alert['timestamp']}]")
            print(f"  IP: {alert['ip']}")
            print(f"  Old MAC: {alert['old_mac']}")
            print(f"  New MAC: {alert['new_mac']}")
        print("\n" + "="*60)
        print(f"[!] Total Spoofing Attempts: {len(alert_log)}")
    else:
        print("\n[+] No ARP spoofing detected")
    
    # Print ARP table
    if arp_table:
        print("\n" + "="*60)
        print("[ARP TABLE]")
        print("="*60)
        print(f"{'IP Address':<20} {'MAC Address':<20}")
        print("-"*60)
        for ip, mac in arp_table.items():
            print(f"{ip:<20} {mac:<20}")
        print("="*60)

def main():
    """
    Main function for integrated packet sniffer and ARP detector.
    """
    parser = argparse.ArgumentParser(description="Integrated Packet Sniffer & ARP Spoofing Detector")
    parser.add_argument("-i", "--interface", type=str, help="Network interface")
    parser.add_argument("-c", "--count", type=int, default=50, help="Number of packets (default: 50, 0=unlimited)")
    parser.add_argument("-f", "--filter", type=str, default="", help="BPF filter (e.g., 'tcp', 'arp')")
    parser.add_argument("-o", "--output", type=str, default="captured_packets.pcap", help="Output PCAP file")
    parser.add_argument("-a", "--alerts", type=str, default="arp_alerts.txt", help="ARP alerts file")

    args = parser.parse_args()

    try:
        print("="*60)
        print("  INTEGRATED PACKET SNIFFER & ARP DETECTOR")
        print("="*60)
        print(f"[+] Interface: {args.interface if args.interface else 'Default'}")
        print(f"[+] Packet Count: {'Unlimited' if args.count == 0 else args.count}")
        print(f"[+] Filter: {args.filter if args.filter else 'None (all)'}")
        print(f"[+] PCAP Output: {args.output}")
        print(f"[+] Alerts Output: {args.alerts}")
        print("="*60)
        print("\nPress Ctrl+C to stop...\n")
        
        if args.interface:
            sniff(iface=args.interface, filter=args.filter, count=args.count, prn=analyze_packet, store=0)
        else:
            sniff(filter=args.filter, count=args.count, prn=analyze_packet, store=0)
            
    except KeyboardInterrupt:
        print("\n\n[!] Stopped by user")
    except PermissionError:
        print("\n[-] Error: Administrator/root privileges required")
    except Exception as e:
        print(f"\n[-] Error: {e}")
    finally:
        save_to_pcap(args.output)
        save_alerts(args.alerts)
        print_statistics()

if __name__ == "__main__":
    main()