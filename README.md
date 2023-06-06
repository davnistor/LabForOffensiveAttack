# LabForOffensiveAttack
## current situation
Arp poisoning should work, automatically initiates the attackers mac and ip address. The victims are manually entered, still no automation in that part.

dnsspoof works, my fully own version dnspoisoning is yet to work
ssl strip - attacker can steal the redirect to https message and input his own website to redirect to

## next steps 
* ssl strip module second part attacker - webserver
* decide how the user or the program chooses victims
* refactor code after implemented previous steps (to work for multiple pairs of victims for example)

## main idea, arp poisoning places us in the middle, thus dns spoofing and ssl stripping becomes possible. Strategy design pattern maybe?

