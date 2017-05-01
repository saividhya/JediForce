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
print "Service List:"
print "------------------------------------------------------------------------------------------------------------------------"
print "Service ID\t\tPort\t\tService Name\t\tService Description\t\t"
print "------------------------------------------------------------------------------------------------------------------------"
for i in range(0,len(serviceList)):
	print str(serviceList[i]['service_id'])+ "\t\t\t"+str(serviceList[i]['port']) + "\t\t" + serviceList[i]['service_name'] + "\t\t" + serviceList[i]['description']
print "------------------------------------------------------------------------------------------------------------------------"
print "\n\nTargets:"
print "------------------------------------------------------------------------------------------------------------------------"					
for i in range(0,len(serviceList)):
	service = serviceList[i]['service_id']	
	print "\n"
	print str(service) + ":"		
	hosts = t.get_targets(service)								
	print "------------------------------------------------------------------------------------------------------------------------"
	print "Team Name\t\tTeam Host\t\tFlag ID\t\tport\t\t"
	print "------------------------------------------------------------------------------------------------------------------------"
	for j in range(0,len(hosts['targets'])):
		print str(hosts['targets'][j]['team_name'])+ "\t\t\t"+str(hosts['targets'][j]['hostname']) + "\t\t" + str(hosts['targets'][j]['flag_id']) + "\t\t" + str(hosts['targets'][j]['port'])
	print "------------------------------------------------------------------------------------------------------------------------"					
