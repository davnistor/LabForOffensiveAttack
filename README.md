# ComputerNetworksAttack
Project still in progress. 
User can choose two ips of the victims, the code executes an arp poisoning fixing the attacker as the man in the middle, followed by either a DNS spoof, that redirects the user to a website of the attacker's choosing, or a SSL strip that redirects the user to a website of the attacker's choosing, while the attacker establishes a secure channel with the server (secure channel still to be implemented). More to come in the following days including a video demonstration using virtual machines a bind9 dns server and an apache2 webserver that will suport SSL.

## Features
* The program automatically finds out the mac and ip address of the current machine.

## Requirements
1. Linux machine
2. Weberver that supports SSL
3. Another webserver that hosts a website
4. A dns server
5. Python 3
6. Scapy library
7. Netfilter library
8. Enable ipv4 packet forwarding in sysctl.conf of the linux machine found in /etc.

# Running the program
* When running main.py with Python 3 you must include four arguments: the two victims' IPs, the interface connected to the network where the victims are, the type of attack to execute between DNS spoof and SSL strip and the website to redirect the victim to during the DNS spoof and the SSL strip. Example: python3 main.py 192.168.56.103 192.168.56.3 enp0s8 dns 192.168.56.102. If anything other than dns is inputed, a SSL strip will be executed. Please stop the program with ctrl-C so that the netfilter queue object is unbinded from the Linux kernel packet queue.
