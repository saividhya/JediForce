import os
import subprocess
def overflow(filePath):
	bufValue = 'JEDI'
	c = 0
	while True:
		command = 'echo \'y\' | gdb '+ filePath +' -ex \'run '+ bufValue + '\' -ex \'info reg\' -ex quit'
		print command
		p = subprocess.Popen( command, shell=True, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
		b = p.communicate()
		if str(b).find('Segmentation fault') != -1 :
			print 'EIP overriding'
			break
		else:			
			bufValue = 'BBBB%s' % bufValue
		c = c+1
	bufValue = 'BBBB%s' % bufValue
	i = 0
	while i < 8:
		command = 'echo \'y\' | gdb '+ filePath +' -ex \'run '+ bufValue + '\' -ex \'info reg\' -ex quit'
		print command
		p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr = subprocess.PIPE)		
		b = p.communicate()
		if str(b).find('0x4944454a in ?? ()') != -1:			
			print 'EIP overwrritten for input : %s ' % bufValue 
			break
		else:
			bufValue = bufValue[1:]
		i = i +1

overflow(raw_input(" Enter Path "))
