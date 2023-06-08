from scapy.all import *
import time
import threading

from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether, ARP

# icmp to capture
global icmp_packet_global

# class that houses the code to automatically get attacker ip and mac
class GetIpMac:
    # initializes the interface to send packages to
    def __init__(self, interface):
        global icmp_packet_global

        icmp_packet_global = None
        self.interface = interface

    # method dedicated to sniffing the icmp package
    def sniff_icmp(self):
        global icmp_packet_global

        pkts = sniff(count=1, filter="arp", iface=self.interface)
        results = [packet for packet in pkts if packet[Ether].dst == "ff:ff:ff:ff:ff:ff"]
        if len(results) > 0:
            icmp_packet_global = results[0]
        else:
            self.sniff_icmp()

    # sends ping to random address
    def send_ping(self):
        global icmp_packet_global

        icmp_packet = IP() / ICMP()
        icmp_packet[IP].dst = "192.168.56.107"

        while icmp_packet_global is None:
            send(icmp_packet, iface=self.interface)

    # find the mac and ip of the current device
    def find_mac_ip(self, packet):
        if packet.haslayer(ARP):
            macc = packet[Ether].src
            ipp = packet[ARP].psrc

            return [macc, ipp]

    # gets the mac and ip of the current device
    def get_mac_ip(self):
        # create + start thread for sniffing
        thread_sniff = threading.Thread(target=self.sniff_icmp)
        thread_sniff.start()

        # send packet to be sniffed, get the mac of the attacker
        self.send_ping()
        return self.find_mac_ip(icmp_packet_global)

