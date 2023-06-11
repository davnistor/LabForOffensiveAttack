# ComputerNetworksAttack
This is a project that is only for educational purposes.

User can choose two ips of the victims, the code executes an arp poisoning fixing the attacker as the man in the middle, followed by either a DNS spoof, that redirects the user to a website of the attacker's choosing, or a SSL strip that redirects the user to a website of the attacker's choosing.

## Features
* The program automatically finds out the mac and ip address of the current machine.

## Requirements
1. Linux machine
2. Weberver that supports SSL or TLS, but does not support HSTS
3. Webserver to host the attacker's website
4. A dns server
5. Python 3
6. Scapy library
7. Netfilter library

# Running the program / User manual
* When running main.py with Python 3 you must include the following arguments: the two victims' IPs, the interface connected to the network where the victims are, the type of attack to execute between DNS spoof and SSL strip, the website to redirect the victim to during the DNS spoof and the SSL strip and the name of the website that you want to immitate. Example: python3 main.py 192.168.56.103 192.168.56.3 enp0s8 dns 192.168.56.104 fakebook.com. Only if the victim accesses fakebook.com will the victim be redirected to the attacker's website at 192.168.56.104. If anything other than dns is inputed, a SSL strip will be executed. Please stop the program with ctrl-C so that the netfilter queue object is unbinded from the Linux kernel packet queue. The attack only works if the attacker is in the same LAN as the victim. To intercept the conversation with an outside webserver or DNS, it is recommended that the second inputed IP is the IP of the gateway of the LAN.
