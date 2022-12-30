#!/usr/bin/env python

#
# Copyright (c) 2018 Sarah Tollman, 2021 Theo Jepsen
# All rights reserved.
#
# This software was developed by Stanford University and the University of Cambridge Computer Laboratory
# under National Science Foundation under Grant No. CNS-0855268,
# the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
# by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"),
# as part of the DARPA MRC research programme.
#

from collections import namedtuple
from datetime import datetime, timedelta
from scapy.all import *
from threading import Thread, Lock

from control_plane.utils.consts import *

NUM_ARP_ATTEMPTS = 5

"""
The ARP cache is responsible for managing ARP requests, populating the arp cache
table, and timing out expired cache entries
"""
class ARP_cache():

    """
    Initializes the ARP cache

    @param config a Config object
    """
    def __init__(self, config):
        self.tables_api = config.tables_api
        self.ifaces = config.ifaces
        self.sendp = config.sendp
        self.rtable = config.rtable
        self.arp_pending_reply = {}
        self.seen_arp_request = []
        # TODO: initialize ARP handling thread(s)?
        # TODO: define additional helper methods
        # One possible approach for handling the ARP cache is to define two
        # additional threads:
        # 1. To send multiple arp requests per destination ip address before
        #    sending and ICMP host unreachable if none of the requests receive
        #    a response
        # 2. To remove stale cache entries

    def handle_arp_miss(self, pkt):
        self.arp_pending_reply[pkt] = 0
        if pkt in self.seen_arp_request:
            return
        self.seen_arp_request.append(pkt)
        t = Ether()/ARP()
        if IP in pkt:
            t[Ether].dst = ETH_BROADCAST
            t[Ether].src = pkt[Ether].src

            t[ARP].hwdst = ETH_BROADCAST
            t[ARP].pdst = pkt[IP].dst

            t[ARP].hwsrc = pkt[Ether].src
            t[ARP].psrc = pkt[IP].src
            
        else if ARP in pkt:
            t[Ether].dst = ETH_BROADCAST
            t[Ether].src = pkt[Ether].src

            t[ARP].hwdst = ETH_BROADCAST
            t[ARP].pdst = pkt[ARP].pdst

            t[ARP].hwsrc = pkt[Ether].src
            t[ARP].psrc = pkt[IP].src
            

        for i in self.ifaces:
            if IP in pkt:
                if i.ip != pkt[IP].dst:
                    sendp(t, iface=i, verbose=False)
            else if ARP in pkt:
                sendp(t, iface=i, verbose=False)


