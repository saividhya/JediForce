'''
__author__ = saipranav
'''

# configuration
################################################
# set ip for your computer and target computer
MY_IP = '172.31.129.12'
TARGET_IP = '172.31.172.1'
TRAIL_FOLDER = 'trails'
BLACKLIST_REGEX_FILE = 'blacklist_packets_regex.txt'
MAX_CONVERSATIONS_PER_TRAIL_FILE = 20
################################################


from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import logging
import sys
import shutil
import names
import re

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
	'RSTACK' : 0x14,
	}

# global variable so that we can unbind in exit_handler()
nfqueue = NetfilterQueue()

# global count for number of conversation to be written
number_of_conversation_written = 1
trail_file_name = 1


# Every request has multiple tcp packets but the packets must have
# same source port in case of packet coming from target or
# same destination port in case of packet to target

# conversations is a map that has key as this per request port
# and value as another dict which has target_fininsh flag, me_finish flag, flag_theft flag (for FLG in content)
# list of packets for that request.

# Delete the key value entry after the request is fininshed
# If there is a flag going to target then print the whole list for the key port
# TODO : need to delete key value entries after certain time as
#        we should not be attacked by slow machines
conversations = {}

def packet_analyzer(pkt):

	try:
		global conversations
		# netfilterqueue pkt to scapy packet
		scapy_packet = IP(pkt.get_payload())
		#scapy_packet.show()
		blacklist_regex_list = read_and_check_blacklist_regexs_from_file()

	#####

		# packet is from target so conversation port is source port because destination port is going to be serivce port
		# TODO : whole working is for TCP needs to be compatible with udp too
		if scapy_packet[IP].src == TARGET_IP:

			# check for the regex from blacklist regexs against content in Raw layer load
			if scapy_packet[TCP].sport in conversations and scapy_packet.haslayer('Raw'):
				for blacklist_regex in blacklist_regex_list:
					# if bastion found attacker, write conversation till now and send RST to him
					if blacklist_regex.search(scapy_packet[Raw].load):
						conversations[scapy_packet[TCP].sport]['found_attacker'] = True
						logging.warn('Attaker found with ' + str(blacklist_regex.pattern) )
						conversations[scapy_packet[TCP].sport]['packets'].append(scapy_packet)
						break



			# packet has syn flag, starting new conversation
			if scapy_packet[TCP].flags & TCP_FLAGS['SYN']:
				record = {  'target_finish': False,
							'me_finish': False,
							'flag_theft': False,
							'found_attacker': False,
							'packets': []
						 }
				record['packets'].append(scapy_packet)
				conversations[scapy_packet[TCP].sport] = record
			# for all other packets with any flags
			elif scapy_packet[TCP].sport in conversations:
				conversations[scapy_packet[TCP].sport]['packets'].append(scapy_packet)
			#else:
				#logging.warn('Packet from target not stored due to most recent ack which cleared the conversation')


			# packet has fin flag from target, set the target_finish
			if scapy_packet[TCP].sport in conversations and scapy_packet[TCP].flags & TCP_FLAGS['FIN']:
				conversations[scapy_packet[TCP].sport]['target_finish'] = True


			# packet has ack flag from target
			if scapy_packet[TCP].sport in conversations and scapy_packet[TCP].flags == TCP_FLAGS['ACK']:

				# if the target_finish is True and me_finish is True then append to packets
				if conversations[scapy_packet[TCP].sport]['target_finish'] == True and conversations[scapy_packet[TCP].sport]['me_finish'] == True:
					#print conversations[scapy_packet[TCP].sport]
					if conversations[scapy_packet[TCP].sport]['flag_theft'] == True:
						pcap_file_name = names.get_first_name()
						print_packet(pcap_file_name, scapy_packet[TCP].dport, scapy_packet[TCP].sport, attacker=False)
						write_pcap_file(pcap_file_name, scapy_packet[TCP].dport, scapy_packet[TCP].sport)

					del conversations[scapy_packet[TCP].sport]


			# packet has reset flag from target
			if scapy_packet[TCP].sport in conversations and scapy_packet[TCP].flags & TCP_FLAGS['RST']:
				logging.warn('Converstation ended in RST')
				#logging.warn(conversations[scapy_packet[TCP].sport])
				del conversations[scapy_packet[TCP].sport]

	#####

	#####

		# packet is from me so conversation port is destination port because source port is service port
		# TODO : whole working is for TCP needs to be compatible with udp too
		elif scapy_packet[IP].src == MY_IP:

			# check for the FLG content in Raw layer load
			if scapy_packet[TCP].dport in conversations and scapy_packet.haslayer('Raw') and 'FLG' in scapy_packet[Raw].load:
				conversations[scapy_packet[TCP].dport]['flag_theft'] = True

				# if attacker found then this is our turn to respond
				if scapy_packet[TCP].dport in conversations and conversations[scapy_packet[TCP].dport]['found_attacker'] == True:
					new_flag = 'FLG8txk3x8ILxPIu'
					scapy_packet[TCP].payload[Raw].load = re.sub(r'FLG.{13}', new_flag, str(scapy_packet[TCP].payload))
					del scapy_packet[IP].chksum
					del scapy_packet[TCP].chksum
					pkt.set_payload(str(scapy_packet))

					# append the resent change to conversation as we are going to write that too
					conversations[scapy_packet[TCP].dport]['packets'].append(scapy_packet)
					# write to file and del conversation
					pcap_file_name = names.get_first_name()
					print_packet(pcap_file_name, scapy_packet[TCP].sport, scapy_packet[TCP].dport, attacker=True)
					write_pcap_file(pcap_file_name, scapy_packet[TCP].sport, scapy_packet[TCP].dport)
					del conversations[scapy_packet[TCP].dport]


			# packet has syn flag, starting new conversation
			if scapy_packet[TCP].flags & TCP_FLAGS['SYN']:
				record = {  'target_finish': False,
							'me_finish': False,
							'flag_theft': False,
							'found_attacker': False,
							'packets': []
						 }
				record['packets'].append(scapy_packet)
				conversations[scapy_packet[TCP].dport] = record
			# for all other packets with any flags
			elif scapy_packet[TCP].dport in conversations:
				conversations[scapy_packet[TCP].dport]['packets'].append(scapy_packet)
			#else:
				#logging.warn('Packet from me not stored due to most recent ack which cleared the conversation')


			# packet has fin flag from target, set the target_finish
			if scapy_packet[TCP].dport in conversations and scapy_packet[TCP].flags & TCP_FLAGS['FIN']:
				conversations[scapy_packet[TCP].dport]['me_finish'] = True


			# packet has ack flag from target
			if scapy_packet[TCP].dport in conversations and scapy_packet[TCP].flags == TCP_FLAGS['ACK']:

				# if the target_finish is True and me_fininsh is True then append to packets then deletes conversation
				if conversations[scapy_packet[TCP].dport]['target_finish'] == True and conversations[scapy_packet[TCP].dport]['me_finish'] == True:
					#print conversations[scapy_packet[TCP].dport]
					if conversations[scapy_packet[TCP].dport]['flag_theft'] == True:
						pcap_file_name = names.get_first_name()
						print_packet(pcap_file_name, scapy_packet[TCP].sport, scapy_packet[TCP].dport, attacker=False)
						write_pcap_file(pcap_file_name, scapy_packet[TCP].sport, scapy_packet[TCP].dport)
					del conversations[scapy_packet[TCP].dport]


			# packet has reset flag from target then deletes the conversation or print
			if scapy_packet[TCP].dport in conversations and scapy_packet[TCP].flags & TCP_FLAGS['RST']:
				logging.warn('Converstation ended in RST')
				#logging.warn(conversations[scapy_packet[TCP].dport])
				del conversations[scapy_packet[TCP].dport]

	#####
		#print conversations
		#print("out"+str(scapy_packet.command()))
		pkt.accept()
		#pkt.drop()
	except Exception as detail:
		logging.error(detail)
		exit_handler()

# writes the pcap file so that we can replay our attacker packets later
def write_pcap_file(pcap_file_name, service_port, conversation_port):
	try:
		file_path = os.path.join(TRAIL_FOLDER, str(service_port), pcap_file_name)
		wrpcap(file_path, conversations[conversation_port]['packets'])
	except IOError as io_error:
		logging.error("Unable to open and write to file")
		logging.error(io_error)
		exit_handler()

# prints the packet for analysis purpose
def print_packet(pcap_file_name, service_port, conversation_port, attacker=False):
	try:
		global number_of_conversation_written
		global trail_file_name
		global conversations

		file_path = os.path.join(TRAIL_FOLDER, str(service_port), str(trail_file_name) )
		with open(file_path, 'a') as f:
			packets_to_write = '\n####################################################################################################\n'
			if attacker:
				packets_to_write += '\nBastion sent a wrong flag for attacker ;) \n'
			packets_to_write += '\n' + os.path.join(TRAIL_FOLDER, str(service_port), pcap_file_name) + '\n'

			for scapy_packet in conversations[conversation_port]['packets']:
				if scapy_packet.haslayer('Ethernet'):
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'
					packets_to_write += '     |      Source Ethernet Addr       |    Ethernet Type     |    Destination Ethernet Addr    |     \n'
					packets_to_write += '     |                                 |                      |                                 |     \n'
				#	packets_to_write += '     |        06:6f:08:89:ae:33        |         0x800        |        06:f5:47:bb:bb:6f        |     \n'
					packets_to_write += '     |{:^33}|{:^22}|{:^33}|     \n'.format( str(scapy_packet[Ethernet].src), str(scapy_packet[Ethernet].type), str(scapy_packet[Ethernet].dst) )
					packets_to_write += '     |                                 |                      |                                 |     \n'
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'

				if scapy_packet.haslayer('ARP'):
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'
					packets_to_write += '     |    Src Arp Ether   |    Src Arp Ip    |  Arp op  |    Dst Arp Ether   |    Dst Arp Ip    |     \n'
					packets_to_write += '     |                    |                  |          |                    |                  |     \n'
				#	packets_to_write += '     | 06:6f:08:89:ae:33  |   172.31.129.12  |     2    | 06:f5:47:bb:bb:6f  |   172.31.129.12  |     \n'
					packets_to_write += '     |{:^20}|{:^18}|{:^10}|{:^20}|{:^18}|     \n'.format( str(scapy_packet[ARP].hwsrc), str(scapy_packet[ARP].psrc), str(scapy_packet[ARP].op), str(scapy_packet[ARP].hwdst), str(scapy_packet[ARP].pdst) )
					packets_to_write += '     |                    |                  |          |                    |                  |     \n'
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'

				if scapy_packet.haslayer('ICMP'):
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'
					packets_to_write += '     |           Icmp Type          |           Icmp Id           |           Icmp seq          |     \n'
					packets_to_write += '     |                              |                             |                             |     \n'
					packets_to_write += '     |{:^30}|{:^29}|{:^29}|     \n'.format( str(scapy_packet[ICMP].type), str(scapy_packet[ICMP].id),  str(scapy_packet[ICMP].seq) )
				#	packets_to_write += '     |                5             |              12             |             124             |     \n'
					packets_to_write += '     |                              |                             |                             |     \n'
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'

				if scapy_packet.haslayer('IP'):
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'
					packets_to_write += '     |      Source Ip Addr    |    id    |   len  |   ttl  |   proto  |   Destination Ip Addr   |     \n'
					packets_to_write += '     |                        |          |        |        |          |                         |     \n'
				#	packets_to_write += '     |       172.31.172.1     |   39503  |   60   |   63   |    tcp   |      172.31.129.12      |     \n'
					packets_to_write += '     |{:^24}|{:^10}|{:^8}|{:^8}|{:^10}|{:^25}|     \n'.format( str(scapy_packet[IP].src), str(scapy_packet[IP].id), str(scapy_packet[IP].len), str(scapy_packet[IP].ttl), str(scapy_packet[IP].proto), str(scapy_packet[IP].dst) )
					packets_to_write += '     |                        |          |        |        |          |                         |     \n'
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'

				if scapy_packet.haslayer('TCP'):
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'
					packets_to_write += '     |   Source Tcp Port   |   flags   |       seq      |       ack      | Destination Tcp Port |     \n'
					packets_to_write += '     |                     |           |                |                |                      |     \n'
					packets_to_write += '     |{:^21}|{:^11}|{:^16}|{:^16}|{:^22}|     \n'.format( str(scapy_packet[TCP].sport), str(scapy_packet[TCP].flags), str(scapy_packet[TCP].seq), str(scapy_packet[TCP].ack), str(scapy_packet[TCP].dport) )
				#	packets_to_write += '     |         41153         |  177436954  |     60    |           20001            |     \n'
					packets_to_write += '     |                     |           |                |                |                      |     \n'
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'

				if scapy_packet.haslayer('UDP'):
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'
					packets_to_write += '     |             Source Udp Port                |             Destination Udp Port            |     \n'
					packets_to_write += '     |                                            |                                             |     \n'
					packets_to_write += '     |{:^44}|{:45}|     \n'.format( str(scapy_packet[UDP].sport), str(scapy_packet[UDP].dport) )
				#	packets_to_write += '     |                   41153                    |                     20001                   |     \n'
					packets_to_write += '     |                                            |                                             |     \n'
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'

				if scapy_packet.haslayer('Raw'):
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'
					packets_to_write += '     |                                           Raw load                                       |     \n'
					packets_to_write += '     |                                                                                          |     \n'
					packets_to_write += '' + scapy_packet[Raw].load + '\n'
					packets_to_write += '     |                                                                                          |     \n'
					packets_to_write += '     --------------------------------------------------------------------------------------------     \n'

				packets_to_write += '\n\n'

			packets_to_write += '####################################################################################################\n'
			f.write(packets_to_write)
			number_of_conversation_written += 1

			# if we reach the limit then increment trail filename and reset number_of_conversations_written
			if number_of_conversation_written == MAX_CONVERSATIONS_PER_TRAIL_FILE:
				trail_file_name += 1
				number_of_conversation_written = 1

	except IOError as io_error:
		logging.error("Unable to open and write to file")
		logging.error(io_error)
		exit_handler()
	except ValueError as value_error:
		logging.error("Unable to handle other datatype to string convertion")
		logging.error(value_error)
		exit_handler()
	except Exception as detail:
		logging.error(detail)
		exit_handler()

# flushes the iptables , unbinds nfqueue and exits all packet_analyser threads
def exit_handler():
	global nfqueue
	os.system('iptables -F')
	nfqueue.unbind()
	logging.error("After flushing iptables Bastion DIED!")
	os._exit(1)

def read_and_check_blacklist_regexs_from_file():
	try:
		lines = [line.rstrip('\n') for line in open(BLACKLIST_REGEX_FILE)]
		regexps = []
		for line in lines:
			regex = re.compile(line)
			regexps.append(regex)
		return regexps
	except IOError as io_error:
		logging.error(io_error)
		return []
	except re.error as re_error:
		logging.error(re_error)
		return []

# main controller to setup the bastion
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

	#in_to_me_ip_table_rule = 'iptables -I INPUT -d ' + MY_IP + '  -j NFQUEUE --queue-num 1'
	#out_from_me_ip_table_rule = 'iptables -I OUTPUT -s ' + MY_IP + '  -j NFQUEUE --queue-num 1'

	# execute iptable add command
	logging.info("IP rule : " + in_to_me_ip_table_rule)
	logging.info("IP rule : " + out_from_me_ip_table_rule)
	os.system(in_to_me_ip_table_rule)
	os.system(out_from_me_ip_table_rule)

	# nfq init for input queue 1, 3 denotes the amount of packet to expose for packet_analyzer
	#nfqueue = NetfilterQueue()
	global nfqueue
	nfqueue.bind(1, packet_analyzer, 3)
	logging.info("Bind functions done! Almost done!")

	try:
		nfqueue.run()
	except KeyboardInterrupt:
		logging.error("User interrupt from keyboard")
		exit_handler()
	except Exception as detail:
		logging.error(detail)
		exit_handler()

if __name__ == "__main__":
	bastion()
