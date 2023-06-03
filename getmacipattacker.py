from scapy.all import *
import time
import threading

from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether, ARP

# icmp to capture
global icmp_packet_global


class GetIpMac:
    # method dedicated to sniffing the icmp package
    def sniff_icmp(self):
        global icmp_packet_global
        pkt = sniff(count=1, filter="arp")

        if len(pkt) > 0:
            icmp_packet_global = pkt[0]

    # sends ping to random address, the destination does not matter
    def send_ping(self):
        icmp_packet = IP() / ICMP()
        icmp_packet[IP].dst = "192.168.56.102"

        send(icmp_packet)

    # find the mac and ip of the current device
    def find_mac_ip(self, packet):

        if packet[0].haslayer(Ether):
            macc = packet[Ether].src
            ipp = packet[ARP].psrc

            return [macc, ipp]

    def get_mac_ip(self):
        # create + start thread for sniffing
        thread_sniff = threading.Thread(target=self.sniff_icmp)
        thread_sniff.start()

        # send packet to be sniffed, get the mac of the attacker
        self.send_ping()
        time.sleep(2)
        the_ar = self.find_mac_ip(icmp_packet_global)

        return the_ar
