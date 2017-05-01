#!/bin/sh
apt-get install -y build-essential python-dev libnetfilter-queue-dev python-pip
pip install scapy
pip install NetfilterQueue
pip install names
pip install iCTF
#sudo iptables -I OUTPUT -d 192.168.0.6 -j NFQUEUE --queue-num 1
#sudo iptables -I INPUT -d 192.168.0.51 -j NFQUEUE --queue-num 1