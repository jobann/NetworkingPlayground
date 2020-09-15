#!/usr/bin/env python

import scapy.all as scapy
import netfilterqueue


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if ".exe" in scapy_packet[scapy.Raw].load:
            if scapy_packet[scapy.TCP].dport == 80:
                print("HTTP Request")
                print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                print("HTTP Response")
                print(scapy_packet.show())

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
