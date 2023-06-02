# from scapy.all import *
# import time
# import threading
#
# from scapy.layers.dns import DNS
# from scapy.layers.inet import ICMP, IP, UDP
# from scapy.layers.l2 import Ether, ARP
#
# global transaction_id
#
# class DnsStripping:
# #intercept http request
#     def __init__(self, intercepted_transaction_id, ip_victim):
#         self.intercepted_transaction_id = intercepted_transaction_id
#         self.ip_victim = ip_victim
# #redirect to my server instead
#
#     def send_spoof_dns_response(self, packet):
#         send(packet)
#
#     def create_dns_packet(self):
#         dns_packet = IP(src="192.168.1.10", dst=self.ip_victim) / UDP(sport=12345, dport=53) / DNS()
#         dns_packet[DNS]
#
#     def intercept_dns_packet(self):
#
#
#
#
#

