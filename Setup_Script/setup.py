from ictf import iCTF
import sys
import os
ip = "52.34.158.221"
team = "team1@example.com"
i = iCTF("http://%s/" % ip)
t = i.login(team,"password")
serviceList = t.get_service_list()
exploitPath = sys.argv[1]
for i in range(0,len(serviceList)):
	os.mkdir(exploitPath+"/"+str(serviceList[i]['port']),0777)

