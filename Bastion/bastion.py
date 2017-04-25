# configuration
################################################
# set ip for your computer and target computer
my_ip = '192.168.0.47'
target_ip = '192.168.0.48'
#target_ip = '216.58.219.14'
################################################


from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import logging
import sys

FORMAT = "[%(levelname)s:%(asctime)s:%(funcName)1s()] %(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)

# Map for tcp flags to test against the packet's flag
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
	}

# Every request has multiple tcp packets but the packets must have
# same source port in case of packet coming from target or
# same destination port in case of packet to target

# conversations is a map that has key as this per request port
# and value as another dict which has target_fininsh flag, me_finish flag,
# list of packets for that request.

# Delete the key value entry after the request is fininshed
# If there is a flag going to target then print the whole list for the key port
# TODO : need to delete key value entries after certain time as
#        we should not be attacked by slow machines
conversations = {}

def packet_analyzer(pkt):
	# netfilterqueue pkt to scapy packet
	scapy_packet = IP(pkt.get_payload())
	scapy_packet.show()
	print(scapy_packet[TCP].flags)

#####

	# packet is from target
	if scapy_packet[IP].src == target_ip:

		# packet has syn flag, starting new conversation
		if scapy_packet[TCP].flags == TCP_FLAGS['SYN']:
			record = {  'target_finish': False,
						'me_finish': False,
						'packets': []
					 }
			record['packets'].append(pkt)
			conversations[scapy_packet[TCP].dport] = record

		# packet has fin flag from target, set the target_finish
		elif scapy_packet[TCP].flags == TCP_FLAGS['FIN'] or scapy_packet[TCP].flags == TCP_FLAGS['FINACK']:
			conversations[scapy_packet[TCP].dport]['target_finish'] = True
			conversations[scapy_packet[TCP].dport]['packets'].append(pkt)

		# packet has ack flag from target
		elif scapy_packet[TCP].flags == TCP_FLAGS['ACK']:

			# if the target_finish is True and me_finish is True then append to packets
			# TODO : del the conversation or print
			if conversations[scapy_packet[TCP].dport]['target_finish'] == True and conversations[scapy_packet[TCP].dport]['me_finish'] == True:
				conversations[scapy_packet[TCP].dport]['packets'].append(pkt)
				print "qwert"
				print conversations[scapy_packet[TCP].dport]

			# if the target_finish is False or me_finish is False then just add the packets in conversation
			else:
				conversations[scapy_packet[TCP].dport]['packets'].append(pkt)

		# packet has reset flag from target
		# TODO : del the conversation or print
		elif scapy_packet[TCP].flags == TCP_FLAGS['RST']:
			conversations[scapy_packet[TCP].dport]['packets'].append(pkt)
			print conversations[scapy_packet[TCP].dport]

		else:
			conversations[scapy_packet[TCP].dport]['packets'].append(pkt)
			
#####

#####

	# packet is from me
	elif scapy_packet[IP].src == my_ip:

		# packet has syn flag, starting new conversation
		if scapy_packet[TCP].flags == TCP_FLAGS['SYN']:
			record = {  'target_finish': False,
						'me_finish': False,
						'packets': []
					 }
			record['packets'].append(pkt)
			conversations[scapy_packet[TCP].sport] = record

		# packet has fin flag from target, set the target_finish
		elif scapy_packet[TCP].flags == TCP_FLAGS['FIN'] or scapy_packet[TCP].flags == TCP_FLAGS['FINACK']:
			conversations[scapy_packet[TCP].sport]['me_finish'] = True
			conversations[scapy_packet[TCP].sport]['packets'].append(pkt)

		# packet has ack flag from target
		elif scapy_packet[TCP].flags == TCP_FLAGS['ACK']:

			# if the target_finish is True and me_fininsh is True then append to packets
			# TODO : del the conversation or print
			if conversations[scapy_packet[TCP].sport]['target_finish'] == True and conversations[scapy_packet[TCP].sport]['me_finish'] == True:
				conversations[scapy_packet[TCP].sport]['packets'].append(pkt)
				print "asdf"
				print conversations[scapy_packet[TCP].sport]

			# if the target_finish is False or me_fininsh is False then just add the packets in conversation
			else:
				conversations[scapy_packet[TCP].sport]['packets'].append(pkt)

		# packet has reset flag from target, del the conversation or print
		elif scapy_packet[TCP].flags == TCP_FLAGS['RST']:
			conversations[scapy_packet[TCP].sport]['packets'].append(pkt)
			print conversations[scapy_packet[TCP].sport]

		else:
			conversations[scapy_packet[TCP].sport]['packets'].append(pkt)

#####
	print conversations
	#print("out"+str(scapy_packet.command()))
	pkt.accept()
	#pkt.drop()

def bastion():
	logging.info("Starting to fortify !")

	logging.info("I am protecting you '" + my_ip + "' from '" + target_ip + "'")

	# ip table rules
	in_to_me_ip_table_rule = 'iptables -I INPUT -s ' + target_ip + ' -d ' + my_ip + '  -j NFQUEUE --queue-num 1'
	out_from_me_ip_table_rule = 'iptables -I OUTPUT -d ' + target_ip + ' -s ' + my_ip + '  -j NFQUEUE --queue-num 1'

	# execute iptable add command
	logging.info("IP rule : " + in_to_me_ip_table_rule)
	logging.info("IP rule : " + out_from_me_ip_table_rule)
	os.system(in_to_me_ip_table_rule)
	os.system(out_from_me_ip_table_rule)


	# nfq init for input queue 1, 3 denotes the amount of packet to expose for packet_analyzer
	nfqueue = NetfilterQueue()
	nfqueue.bind(1, packet_analyzer, 3)
	logging.info("Bind functions done! Almost done!")

	try:
		nfqueue.run()
	except KeyboardInterrupt:
		os.system('iptables -F')
		logging.error("I died!")

	nfqueue.unbind()

if __name__ == "__main__":
	bastion()