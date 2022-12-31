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
        self.dma_iface = config.dma_iface
        self.arp_pending_reply = []
        
        # TODO: initialize ARP handling thread(s)?
        # TODO: define additional helper methods
        # One possible approach for handling the ARP cache is to define two
        # additional threads:
        # 1. To send multiple arp requests per destination ip address before
        #    sending and ICMP host unreachable if none of the requests receive
        #    a response
        # 2. To remove stale cache entries

    def handle_arp_miss(self, pkt):
        t = Ether()/ARP()
        if IP in pkt:
            self.arp_pending_reply.append(pkt) # Counter to determine if it is stale
            t[Ether].dst = ETH_BROADCAST
            t[Ether].src = pkt[Ether].src

            t[ARP].hwdst = ETH_BROADCAST
            t[ARP].pdst = pkt[IP].dst
            t[ARP].hwsrc = pkt[Ether].src
            t[ARP].psrc = pkt[IP].src

        elif ARP in pkt:
            t = pkt
        
        self.tables_api.table_cam_add_entry(ARP_CACHE_TABLE_NAME, match_fields={"next_hop_ipv4":  t[ARP].psrc},\
             action_name='MyIngress.arp_respond', action_params={"result": t[ARP].hwsrc})

        for i in self.ifaces:
            if IP in pkt:
                if (i.ip != pkt[IP].dst) and (i.ip != pkt[IP].src):
                    sendp(t, iface=i, verbose=False)

            if ARP in pkt:
                if (i.ip != pkt[ARP].psrc) and (i.ip != pkt[ARP].pdst):
                    sendp(t, iface=i, verbose=False)

    def handle_arp_reply(self, pkt):
        t = None
        for s in self.arp_pending_reply:
            if s[IP].dst == pkt[ARP].psrc:
                s[Ether].src = s[Ether].dst
                s[Ether].dst = pkt[ARP].hwsrc
                t = s
                self.tables_api.table_cam_add_entry(ARP_CACHE_TABLE_NAME, match_fields={"next_hop_ipv4":  s[ARP].psrc},\
                action_name='MyIngress.arp_respond', action_params={"result": s[ARP].hwsrc})
                self.arp_pending_reply.remove(s)
                sendp(t, iface=self.dma_iface, verbose=False)
                return
        sendp(pkt, iface=self.dma_iface, verbose=False)

