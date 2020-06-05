#!/usr/bin/env python

import netfilterqueue


def process_packets(packet):
    packet.drop()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packets)
queue.run()
