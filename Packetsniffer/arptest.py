from scapy.all import ARP, send
import time

# Send multiple ARP packets with same IP but different MACs
ip = "10.137.66.105"
mac1 = "aa:bb:cc:dd:ee:01"
mac2 = "aa:bb:cc:dd:ee:02"

arp1 = ARP(op=2, psrc=ip, hwsrc=mac1, pdst=ip)
arp2 = ARP(op=2, psrc=ip, hwsrc=mac2, pdst=ip)

send(arp1)
time.sleep(1)
send(arp2)  # This should trigger spoofing alert