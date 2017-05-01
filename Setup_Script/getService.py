from ictf import iCTF
import sys
import os
#Update IP
ip = "35.167.152.77"
#Update Team name
team = "kselladu@asu.edu"
i = iCTF("http://%s/" % ip)
#Update Password
t = i.login(team,"3VXEHUbdM4FG")
serviceList = t.get_service_list()
print serviceList
for i in range(0,len(serviceList)):
	service = serviceList[i]['service_id']				
	hosts = t.get_targets(service)								
	print hosts
						
