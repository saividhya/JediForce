Project CTF Readme
----------------------------
Team : Jedi Force
Members : 
Kasirajan Selladurai Selvakumari - 1210916236 - kselladu@asu.edu
Sai Pranav Ravichandran - 1210987190 - sravic12@asu.edu
Saividhya Saibaba - 1211191602 - ssaibab1@asu.edu
Archana Ramanathan Seshakrishnan - 121112666 - aseshakr@asu.edu
Priyadharshini Gunaraj - 1211075356 - pgunaraj@asu.edu



Setup Scripts
-----------------
A list of setup scripts which will help us to login to the CTF server, list the services and targets currently running in the server. And a setup script for flag submission tool to create exploit folders.

Execution Instructions
Login Script 
Update IP, team name and Password to login into CTF server
Run sshiCTF.sh
      2.    Exploit Folder Script
Update IP, team name and Password
Create exploit folder
Run setup.py



Flag Submission tool
----------------------------
An automated tool that will help us submit the flag at regular intervals. The input to the vulnerable program is given as separate script which will be invoked and the flags will be submitted to the gamebot.

Execution Instructions:
Run Setup script
python setup.py <<exploit folder>>
Run Flag submission tool as background process
		nohup python flgSubmit.py <<exploit folder>> &
Place exploit scripts in the exploit folders that have been created in step 1. Make the exploit script as executable using chmod u+x




Bastion - Sniffer & Defender ( with possibility of being Attacker )
------------------------------------------------------------------------------------
The Bastion is a tool which can be used to sniff the packets from game router and it leaves trails for those conversations (set of packets) which were used to steal our flag and given a regular expression it can find the attacker and return wrong flags.

Execution Instructions:
Add a cron job:
*/5 * * * * /root/jedi-force/Bastion/iptables_flusher.sh
sudo bash install_bastion.sh
sudo python bastion.py



Source Auditing
---------------------
An automated tool that we will find the vulnerable lines in source code which will help us analyze and debug the code quickly and efficiently.

Execution Instructions:
Run source_audit.py
python3 source_audit.py


Sql Injection Exploit tool
--------------------------------
A tool to automate SQL injection basically for blind sql injection

Execution Instructions:
Run python inject.py <vulnerable url>
	If it is run like above, the URL is exploited against the dataset from [1]
Run python injection.py <vulnerable url> <table dataset filename><column dataset filename>
	User specified filename is accepted and the findtable and findcolumn is ran against the dataset specified


Buffer Overflow tool
---------------------------
A tool to exploit buffer overflow vulnerability 

Execution Instructions:
Execute overflow.py
python overflow.py
Enter the absolute path for executable which is vulnerable to buffer overflow
Enter the option as 1 if the buffer input is accepted as command line arguments and 2 if the buffer input is accepted from user


Check File Permission file
------------------------------------
Program to check the file permission.

Execution Instructions:
To check this for a specific user, we can use sudo in command-line.
sudo -u <username> ./check-permissions.sh /long/path/to/file.txt
Else
./check-permissions.sh /long/path/to/file.txt

Setting Chroot
--------------------
Program to move the user to chroot environment
Execution Instructions:
Gcc -o <object_file_name> <.c filename>
<exefilecall>

Close-on-exec flag
-------------------------
Snippet to set the close-on-exec flag
Execution Instructions:
Gcc <filename.c>
<exefilecall>

String function patch
----------------------------
Patch files to prevent buffer overflows through strcpy, strncpy, gets
Execution Instructions:
gcc -fno-builtin -o strcpy strcpy.c
./strcpy
Input Sanitization
-----------------------
Snippet for sanitizing input from user.
Execution Instructions:
Gcc -o <objfilename> <filename.c>
<exefilecall>





