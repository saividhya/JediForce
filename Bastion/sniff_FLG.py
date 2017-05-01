from scapy.all import *

def pkt_callback(pkt):
    if pkt[IP].src == '172.31.129.12' and pkt[IP].dst != '35.167.152.77' and pkt.haslayer(Raw) and 'FLG' in pkt[Raw].load:
        pkt.show() # debug statement
    #print pkt[TCP].op

sniff(iface="eth0", prn=pkt_callback, filter="tcp", store=0)
