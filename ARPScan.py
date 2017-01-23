#!/usr/bin/env python

import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


class ARPScan(object):

    def __init__(self):
        self.ip_range = "192.168.0.1/24"
        self.connect_devices = []

    def scan(self):
        alive, dead = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.ip_range), timeout=2, verbose=0)

        try:
            for i in range(0, len(alive)):
                self.connect_devices.append(alive[i][1].psrc)
        except:
            return None

        return self.connect_devices

scan = ARPScan()
