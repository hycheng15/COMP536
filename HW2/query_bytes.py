#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Reason-GPL: import-scapy
import random
import socket
import sys

from scapy.all import *

QUERY_ETYPE = 0x1235

class Query(Packet):
    name = "Query"
    fields_desc = [
        LongField("port_2_bytes", 0),
        LongField("port_3_bytes", 0)
    ]

bind_layers(Ether, Query, type=QUERY_ETYPE)

def get_if():
    ifs = get_if_list()
    iface = None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    iface = get_if()
    my_mac = get_if_hwaddr(iface)

    # Set up a QUERTY packet (broadcast)
    print(f"Sending querying on iface {iface} to S1")
    req = Ether(src=my_mac, dst='ff:ff:ff:ff:ff:ff', type=QUERY_ETYPE)
    req = req / Query(port_2_bytes=0, port_3_bytes=0)
    req.show2()

    # Send the packet and wait for a response
    # srp1 sends at L2 and waits for exactly one response
    res = srp1(req, iface=iface, timeout=2, verbose=False)

    if res and Query in res:
        print("===== Received response from S1 =====")
        print(f"* Port 2 has sent {res[Query].port_2_bytes} bytes")
        print(f"* Port 3 has sent {res[Query].port_3_bytes} bytes")
    else:
        print("No response received")        

if __name__ == '__main__':
    main()