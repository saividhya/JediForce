from netfilterqueue import NetfilterQueue
from scapy.all import *

counter = 1

TCP_FLAGS = {
	'FIN' : 0x01,
	'SYN' : 0x02,
	'RST' : 0x04,
	'PSH' : 0x08,
	'ACK' : 0x10,
	'URG' : 0x20,
	'ECE' : 0x40,
	'CWR' : 0x80,
	'FINACK' : 0x11,
	'RSTACK' : 0x14,
	}

def packet_analyzer(pkt):
	global counter
	counter += 1
	scapy_packet = IP(pkt.get_payload())
	scapy_packet.show()
	#scapy_packet[TCP].flags = TCP_FLAGS['RSTACK']
	#del scapy_packet[IP].chksum
	#del scapy_packet[TCP].chksum
	#scapy_packet.show()
	#pkt.set_payload(str(scapy_packet))
	pkt.accept()
	print counter

nfqueue = NetfilterQueue()
nfqueue.bind(1, packet_analyzer, 3)

try:
	nfqueue.run()
except KeyboardInterrupt:
	logging.error("I died!")

nfqueue.unbind()