from ictf import iCTF
import os
ip = "52.34.158.221"
team = "team1@example.com"
i = iCTF("http://%s/" % ip)
t = i.login(team,"password")
serviceList = t.get_service_list()
key_info = t.get_ssh_keys()
with open("ctf_key", 'wb') as f:
	f.write(key_info['ctf_key'])
with open("root_key", 'wb') as f:
	f.write(key_info['root_key'])
print key_info['ip']
print key_info['port']
