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
exploitPath = sys.argv[1]
print "Creating folders...."
for i in range(0,len(serviceList)):
	os.mkdir(exploitPath+"/"+str(serviceList[i]['port']),0777)
print "Done."
