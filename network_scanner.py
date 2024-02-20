# Network Scanner Algorithm
# Goal - Discover clients on network

# Steps
# 1. Create arp request directed to broadcast MAC asking for IP.
#   Two main parts:
#       -> Use ARP to ask who has target IP.
#       -> Set destination MAC to broadcast MAC.
# 2. Send packet and receive response.
# 3. Parse the response
# 4. Print result

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("IP\t\t\t\t\tMAC Address\n-------------------------------------")

    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)

scan("192.168.159.2/24")