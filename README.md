# arp-spoof
Tool for spoofing ARP replies on a local access network. Instead of flooding networks with ARP packets
like I've seen many other ARP spoofing tools to, this script will wait for and reply to ARP requests 
sent out by a target machine in an attempt to beat timing-based ARP storm detection.

usage: aspoof.py [-h] -t TARGET [-r ROUTER] [-m MAC] [-fw]
