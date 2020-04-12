#!usr/bin/env python

# INSTALL THE FOLLOWING PYTHON MODULES:
# - pip3 install scapy
# - pip3 install scapy_http
import sys

import scapy.all as scapy

# Given an IP address, return the MAC address of the machine:
def get_mac(ip):
    # Create an object representing an ARP packet asking the MAC of the specific IP:
    arp_request = scapy.ARP(pdst=ip)
    # Create an Ethernet frame to the broadcast MAC address:
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # combination of the Ethernet frame and the ARP packet
    arp_request_broadcast = broadcast / arp_request
    # Send the request. It sends a packet with custom header.
    # Return 2 lists: list of answered packets and list of unanswered packets
    # answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout = 1)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # get only answered packets
    return answered_list[0][1].hwsrc


def sniff(interface):
    # iface: specify the interface used to sniff on.
    # store: I tell scapy to not store packets in memory.
    # prn: allows to specify a callback function (a function that is call every time that the sniff() function sniff
    #      a packet.
    # OPTIONAL FILTERS: uses to specifies filters packets using "BPF syntax"
    #         SOME FILTER EXAMPLES:
    #           - udp: filter UDP packets
    #           - arp: filter ARP packets
    #           - tcp: filter TCP packets
    #           - port 21: filter packets on a specific port
    # DOCUMENTATION LINK: https://scapy.readthedocs.io/en/latest/extending.html
    #scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter=80)
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    try:
        # Check if the packet have an ARP layer and if this ARP layer is a response of type "IS AT":
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            # Retrieve the real MAC address of the IP:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            # Retrieve the MAC in the response:
            response_mac = get_mac(packet[scapy.ARP].hwsrc)

            # Check if the real MAC address is the different from the MAC address retrieved from the response:
            if real_mac != response_mac:
                print("[+] You are under attack !!!")
    except IndexError:
        pass



sniff("eth0")