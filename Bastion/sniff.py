from scapy.all import *

def pkt_callback(pkt):
    pkt.show() # debug statement
    #print pkt[TCP].op

sniff(iface="eth0", prn=pkt_callback, filter="tcp", store=0, count=20)
