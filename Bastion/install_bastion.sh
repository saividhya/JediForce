#!/bin/sh
sudo apt-get install build-essential python-dev libnetfilter-queue-dev
sudo pip install NetfilterQueue
#sudo iptables -I OUTPUT -d 192.168.0.6 -j NFQUEUE --queue-num 1
#sudo iptables -I INPUT -d 192.168.0.51 -j NFQUEUE --queue-num 1