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
        self.ifaces = config.ifaces
        self.arp_list = []
        # TODO: initialize ARP handling thread(s)?
        # TODO: define additional helper methods
        # One possible approach for handling the ARP cache is to define two
        # additional threads:
        # 1. To send multiple arp requests per destination ip address before
        #    sending and ICMP host unreachable if none of the requests receive
        #    a response
        # 2. To remove stale cache entries

    def handle_arp_miss(self, pkt):

        sendp(pkt, iface=self.dma_iface, verbose=False)

    # def handleArpReply(self, pkt):
    #     # add replies from hosts to cache
    #     self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
    #     self.addIPAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
    #     self.send(pkt)

    # def handleArpRequest(self, pkt):
    #     # add requests from hosts to cache
    #     self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
    #     self.addIPAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)

    #     # respond to requests addressed to any router interface
    #     if pkt[ARP].pdst in self.intf_ips:
    #         dstIP = pkt[ARP].pdst
    #         pkt[Ether].dst = pkt[Ether].src
    #         pkt[Ether].src = self.MAC
    #         pkt[ARP].op = 2 # reply
    #         pkt[ARP].hwdst = pkt[ARP].hwsrc
    #         pkt[ARP].pdst = pkt[ARP].psrc
    #         pkt[ARP].hwsrc = self.MAC
    #         pkt[ARP].psrc = dstIP

    #     self.send(pkt)

