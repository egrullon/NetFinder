#!/usr/bin/python3
# -*- coding: utf-8 -*-

# NetFinder v1.0 (GNU/Linux x86_64).
# Copyright (C) 2021 egrullon <Amix>.
# License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/gpl-3.0.html>.
# This program comes with ABSOLUTELY NO WARRANTY.
# This is free software and you are free to change and redistribute it.

# Author: egrullon <Amix>
# Date: 2021-03-03
# egrullon@cystrong.com
# www.cystrong.com
# Description: is an active reconnaissance tool for detect online hosts.

"""
 ██████   █████           █████    ███████████  ███                 █████                   
░░██████ ░░███           ░░███    ░░███░░░░░░█ ░░░                 ░░███                    
 ░███░███ ░███   ██████  ███████   ░███   █ ░  ████  ████████    ███████   ██████  ████████ 
 ░███░░███░███  ███░░███░░░███░    ░███████   ░░███ ░░███░░███  ███░░███  ███░░███░░███░░███
 ░███ ░░██████ ░███████   ░███     ░███░░░█    ░███  ░███ ░███ ░███ ░███ ░███████  ░███ ░░░ 
 ░███  ░░█████ ░███░░░    ░███ ███ ░███  ░     ░███  ░███ ░███ ░███ ░███ ░███░░░   ░███     
 █████  ░░█████░░██████   ░░█████  █████       █████ ████ █████░░████████░░██████  █████    
░░░░░    ░░░░░  ░░░░░░     ░░░░░  ░░░░░       ░░░░░ ░░░░ ░░░░░  ░░░░░░░░  ░░░░░░  ░░░░░     
                                                                                            
"""

import time
import sys
import socket
from scapy.all import ARP, Ether, srp

try:
    t1 = time.time()
    net = str(input("Enter IP Address: "))

    detail_arp = ARP(pdst=net)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    pack = ether / detail_arp

    result = srp(pack, timeout=4)[0]
    devices = []

    for device_send, device_received in result:
        devices.append({'IP': device_received.psrc, 'MAC': device_received.hwsrc})

    print("\n===================================")
    print("      ** Detected Devices **")
    print("===================================")

    print("\nIP" + " \t\t " + "MAC Address")

    if __name__ == '__main__':
        for device in devices:
            print("{:16} {}".format(device['IP'], device['MAC']))

except KeyboardInterrupt:
    print("\nBye")
    sys.exit()

except socket.gaierror:
    print('Connection error')
    sys.exit()

print("\nHosts scanned in", time.time() - t1, "seconds")
