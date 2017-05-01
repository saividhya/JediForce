from ictf import iCTF
import os
import stat
from multiprocessing import Process
import sys
from subprocess import Popen, PIPE
def runExploit(path,t):
	executable = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
	serviceList = t.get_service_list()
	while True:
		for root, dirs, files in os.walk(path, topdown=False):
			port = os.path.basename(path)
			for name in files:
				exploitFile = (os.path.join(root, name))
				for i in range(0,len(serviceList)):
					if(str(serviceList[i]['port']) == str(port)):
						service = serviceList[i]['service_id']				
						hosts = t.get_targets(service)		
						st = os.stat(exploitFile)
						if st.st_mode & executable:
							for i in range(0,len(hosts['targets'])):
								print "Running Script "+ exploitFile,hosts['targets'][i]['hostname'],port
								pipe = Popen([exploitFile,hosts['targets'][i]['hostname'],port,hosts['targets'][i]['flag_id']], stdout=PIPE)
								text = pipe.communicate()[0]	
								response = text.split()	
								flags = [r for r in response if r.startswith("FLG")]
								if len(flags) <> 0:
									print flags
									print t.submit_flag(flags)						
if __name__ == '__main__':
	ip = "35.167.152.77"
	team = "kselladu@asu.edu"
	i = iCTF("http://%s/" % ip)
	t = i.login(team,"3VXEHUbdM4FG")
	i = 0
	processes = []
	exploitPath = sys.argv[1]
	for x in os.walk(exploitPath):
		if i <> 0:
			process = Process(target=runExploit, args=(x[0],t))
			processes.append(process)		
		i = i+1
	for p in processes:
		p.start()
	for p in processes:
		p.join()
