'''
__author__ = saipranav
'''

# configuration
################################################
# set ip for your computer and target computer
MY_IP = '172.31.129.12'
TARGET_IP = '172.31.129.24'
TRAIL_FOLDER = 'trails'
TRAIL_FILE = 'trail.txt'
BLACKLIST_REGEX_FILE = 'blacklist.txt'
################################################


from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import logging
import sys
import shutil
import names

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

#####

	# packet is from target
	if scapy_packet[IP].src == TARGET_IP:

		# packet has syn flag, starting new conversation
		if scapy_packet[TCP].flags == TCP_FLAGS['SYN']:
			record = {  'target_finish': False,
						'me_finish': False,
						'interesting': False,
						'packets': []
					 }
			record['packets'].append(scapy_packet)
			conversations[scapy_packet[TCP].dport] = record

		# packet has fin flag from target, set the target_finish
		elif scapy_packet[TCP].flags == TCP_FLAGS['FIN'] or scapy_packet[TCP].flags == TCP_FLAGS['FINACK']:
			conversations[scapy_packet[TCP].dport]['target_finish'] = True
			conversations[scapy_packet[TCP].dport]['packets'].append(scapy_packet)

		# packet has ack flag from target
		elif scapy_packet[TCP].flags == TCP_FLAGS['ACK']:

			# if the target_finish is True and me_finish is True then append to packets
			if conversations[scapy_packet[TCP].dport]['target_finish'] == True and conversations[scapy_packet[TCP].dport]['me_finish'] == True:
				conversations[scapy_packet[TCP].dport]['packets'].append(scapy_packet)
				print "qwert"
				#print conversations[scapy_packet[TCP].dport]
				if conversations[scapy_packet[TCP].dport]['interesting'] == True:
					pcap_file_name = names.get_first_name()
					print_packet(pcap_file_name, scapy_packet[TCP].sport, scapy_packet[TCP].dport)
					write_pcap_file(pcap_file_name, scapy_packet[TCP].sport, scapy_packet[TCP].dport)
				# TODO : no need to print
				else:
					print conversations[scapy_packet[TCP].dport]

				del conversations[scapy_packet[TCP].dport]

			# if the target_finish is False or me_finish is False then just add the packets in conversation
			else:
				conversations[scapy_packet[TCP].dport]['packets'].append(scapy_packet)

		# packet has reset flag from target
		elif scapy_packet[TCP].flags == TCP_FLAGS['RST']:
			conversations[scapy_packet[TCP].dport]['packets'].append(scapy_packet)
			# TODO : no need print
			print conversations[scapy_packet[TCP].dport]

			del conversations[scapy_packet[TCP].dport]

		else:
			conversations[scapy_packet[TCP].dport]['packets'].append(scapy_packet)

			if 'FLG' in scapy_packet[Raw].load:
				conversations[scapy_packet[TCP].dport]['interesting'] = True
			
#####

#####

	# packet is from me
	elif scapy_packet[IP].src == MY_IP:

		# packet has syn flag, starting new conversation
		if scapy_packet[TCP].flags == TCP_FLAGS['SYN']:
			record = {  'target_finish': False,
						'me_finish': False,
						'interesting': False,
						'packets': []
					 }
			record['packets'].append(scapy_packet)
			conversations[scapy_packet[TCP].sport] = record

		# packet has fin flag from target, set the target_finish
		elif scapy_packet[TCP].flags == TCP_FLAGS['FIN'] or scapy_packet[TCP].flags == TCP_FLAGS['FINACK']:
			conversations[scapy_packet[TCP].sport]['me_finish'] = True
			conversations[scapy_packet[TCP].sport]['packets'].append(scapy_packet)

		# packet has ack flag from target
		elif scapy_packet[TCP].flags == TCP_FLAGS['ACK']:

			# if the target_finish is True and me_fininsh is True then append to packets
			# TODO : del the conversation or print
			if conversations[scapy_packet[TCP].sport]['target_finish'] == True and conversations[scapy_packet[TCP].sport]['me_finish'] == True:
				conversations[scapy_packet[TCP].sport]['packets'].append(scapy_packet)
				print "asdf"
				#print conversations[scapy_packet[TCP].sport]
				if conversations[scapy_packet[TCP].sport]['interesting'] == True:
					pcap_file_name = names.get_first_name()
					print_packet(pcap_file_name, scapy_packet[TCP].dport, scapy_packet[TCP].sport)
					write_pcap_file(pcap_file_name, scapy_packet[TCP].dport, scapy_packet[TCP].sport)
				# no need to print
				else:
					print conversations[scapy_packet[TCP].sport]

				del conversations[scapy_packet[TCP].sport]

			# if the target_finish is False or me_fininsh is False then just add the packets in conversation
			else:
				conversations[scapy_packet[TCP].sport]['packets'].append(scapy_packet)

		# packet has reset flag from target, del the conversation or print
		elif scapy_packet[TCP].flags == TCP_FLAGS['RST']:
			conversations[scapy_packet[TCP].sport]['packets'].append(scapy_packet)
			# no need to print
			print conversations[scapy_packet[TCP].sport]

			del conversations[scapy_packet[TCP].sport]

		else:
			conversations[scapy_packet[TCP].sport]['packets'].append(scapy_packet)

			if 'FLG' in scapy_packet[Raw].load:
				conversations[scapy_packet[TCP].sport]['interesting'] = True

#####
	print conversations
	#print("out"+str(scapy_packet.command()))
	pkt.accept()
	#pkt.drop()

# writes the pcap file so that we can replay our attacker packets later
def write_pcap_file(pcap_file_name, service_port, conversation_port):
	file_path = os.path.join(TRAIL_FOLDER, str(service_port), pcap_file_name)
	wrpcap(file_path, conversations[conversation_port]['packets'])

# prints the packet for analysis purpose
def print_packet(pcap_file_name, service_port, conversation_port):
	file_path = os.path.join(TRAIL_FOLDER, str(service_port), TRAIL_FILE)
	with open(file_path, 'a') as f:
		packets_to_write = '\n##########################################################################################\n'
		packets_to_write += '\n' + os.path.join(TRAIL_FOLDER, str(service_port), pcap_file_name) + '\n'
		for scapy_packet in conversations[conversation_port]['packets']:
			if scapy_packet.haslayer(Ethernet):
				packets_to_write += '     --------------------------------------------------------------------------------     \n'
				packets_to_write += '     |    Source Ethernet Addr     |   Ethernet Type |   Destination Ethernet Addr  |     \n'
				packets_to_write += '     |                             |                 |                              |     \n'
			#	packets_to_write += '     |      06:6f:08:89:ae:33      |      0x800      |      06:f5:47:bb:bb:6f       |     \n'
				packets_to_write += '     |      ' + scapy_packet[Ethernet].src + '      |      ' + scapy_packet[Ethernet].type + '      |      ' + scapy_packet[Ethernet].dst + '       |     \n'
				packets_to_write += '     |                             |                 |                              |     \n'
				packets_to_write += '     --------------------------------------------------------------------------------     \n'

			if scapy_packet.haslayer(ARP):
				packets_to_write += '     --------------------------------------------------------------------------------     \n'
				packets_to_write += '     |  Src Arp Ether  |  Src Arp Ip  |  Arp op  |  Dst Arp Ether  |   Dst Arp Ip   |     \n'
				packets_to_write += '     |                 |              |          |                 |                |     \n'
			#	packets_to_write += '     |06:6f:08:89:ae:33| 172.31.129.12|    2     |06:f5:47:bb:bb:6f|  172.31.129.12 |     \n'
				packets_to_write += '     |' + scapy_packet[ARP].hwsrc + '| ' + scapy_packet[ARP].psrc + '|    ' + scapy_packet[ARP].op + '     |' + scapy_packet[ARP].hwdst + '|  ' + scapy_packet[ARP].pdst + ' |     \n'
				packets_to_write += '     |                 |              |          |                 |                |     \n'
				packets_to_write += '     --------------------------------------------------------------------------------     \n'

			if scapy_packet.haslayer(ICMP):
				packets_to_write += '     --------------------------------------------------------------------------------     \n'
				packets_to_write += '     |         Icmp Type        |         Icmp Id         |        Icmp seq         |     \n'
				packets_to_write += '     |                          |                         |                         |     \n'
			#	packets_to_write += '     |              5           |            12           |           124           |     \n'
				packets_to_write += '     |              ' + scapy_packet[ICMP].type + '           |            ' + scapy_packet[ICMP].id + '           |           ' + scapy_packet[ICMP].seq + '           |     \n'
				packets_to_write += '     |                          |                         |                         |     \n'
				packets_to_write += '     --------------------------------------------------------------------------------     \n'

			if scapy_packet.haslayer(IP):
				packets_to_write += '     --------------------------------------------------------------------------------     \n'
				packets_to_write += '     |  Source Ip Addr |   id    |   len   |   ttl   | proto | Destination Ip Addr  |     \n'
				packets_to_write += '     |                 |         |         |         |       |                      |     \n'
			#	packets_to_write += '     |   172.31.172.1  |  39503  |    60   |    63   |  tcp  |    172.31.129.12     |     \n'
				packets_to_write += '     |   ' + scapy_packet[IP].src + '  |  ' + scapy_packet[IP].id + '  |    ' + scapy_packet[IP].len + '   |    ' + scapy_packet[IP].ttl + '   |  ' + scapy_packet[IP].proto + '  |    ' + scapy_packet[IP].dst + '     |     \n'
				packets_to_write += '     |                 |         |         |         |       |                      |     \n'
				packets_to_write += '     --------------------------------------------------------------------------------     \n'

			if scapy_packet.haslayer(TCP):
				packets_to_write += '     --------------------------------------------------------------------------------     \n'
				packets_to_write += '     |    Source Tcp Port    |     seq     |    ack    |    Destination Tcp Port    |     \n'
				packets_to_write += '     |                       |             |           |                            |     \n'
			#	packets_to_write += '     |         41153         |  177436954  |     60    |           20001            |     \n'
				packets_to_write += '     |         ' + scapy_packet[TCP].sport + '         |  ' + scapy_packet[TCP].seq + '  |     ' + scapy_packet[TCP].ack + '    |           ' + scapy_packet[TCP].dport + '            |     \n'
				packets_to_write += '     |                       |             |           |                            |     \n'
				packets_to_write += '     --------------------------------------------------------------------------------     \n'

			if scapy_packet.haslayer(UDP):
				packets_to_write += '     --------------------------------------------------------------------------------     \n'
				packets_to_write += '     |          Source Udp Port             |           Destination Udp Port        |     \n'
				packets_to_write += '     |                                      |                                       |     \n'
			#	packets_to_write += '     |                41153                 |                  20001                |     \n'
				packets_to_write += '     |                ' + scapy_packet[UDP].sport + '                 |                  ' + scapy_packet[UDP].dport + '                |     \n'
				packets_to_write += '     |                       |             |           |                            |     \n'
				packets_to_write += '     --------------------------------------------------------------------------------     \n'

			if scapy_packet.haslayer(Raw):
				packets_to_write += '     --------------------------------------------------------------------------------     \n'
				packets_to_write += '     |                                     Raw load                                 |     \n'
				packets_to_write += '     |                                                                              |     \n'
				packets_to_write += '     | ' + scapy_packet[Raw].load + ' |     \n'
				packets_to_write += '     |                                                                              |     \n'
				packets_to_write += '     --------------------------------------------------------------------------------     \n'

			packets_to_write += '\n'

		packets_to_write = '##########################################################################################\n'
		f.write(packets_to_write)

def bastion():
	logging.info("Starting to fortify !")

	logging.info("I am protecting you '" + MY_IP + "' from '" + TARGET_IP + "'")

	# setup the folder structure
	logging.info("Creating folder structure with help of service ports")
	if os.path.exists('./' + TRAIL_FOLDER):
		shutil.rmtree('./' + TRAIL_FOLDER)
	os.mkdir(TRAIL_FOLDER + "/",0766)
	os.system("/usr/bin/python ../Setup_Script/setup.py ./" + TRAIL_FOLDER)

	# ip table rules NOTE : don't remove the target because it can cause to stop ssh packets too from incoming
	in_to_me_ip_table_rule = 'iptables -I INPUT -s ' + TARGET_IP + ' -d ' + MY_IP + '  -j NFQUEUE --queue-num 1'
	out_from_me_ip_table_rule = 'iptables -I OUTPUT -d ' + TARGET_IP + ' -s ' + MY_IP + '  -j NFQUEUE --queue-num 1'

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