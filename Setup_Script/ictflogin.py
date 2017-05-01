from ictf import iCTF
import sys
import os
#Update IP
ip = "35.160.215.67"
#Update Team name
team = "kselladu@asu.edu"
i = iCTF("http://%s/" % ip)
#Update Password
t = i.login(team,"3VXEHUbdM4FG")
serviceList = t.get_service_list()
key_info = t.get_ssh_keys()
with open("ctf_key", 'wb') as f:
	f.write(key_info['ctf_key'])
with open("root_key", 'wb') as f:
	f.write(key_info['root_key'])
print key_info['ip']
print key_info['port']
