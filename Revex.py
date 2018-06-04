'''
# Programmer: Brent E. Chambers
# Date: 07/21/2017  #Peace out Spicey! haha
# Filename: Revex.py
# Big ups to J.Steiz for ghpy
# Description: ~!~ Summer of Code ~!~ Almost out baby! WCOBust!
#	Toggle this value to disable the GUI popup on windows critical errors:
#	'GPO (gpedit.msc): Local Computer Policy -> Administrative Templates ->
#	Windows Components -> Windows Error Reporting -> "Prevent Display of..."

'''
from ctypes import *
from my_debugger_defines import *
import subprocess
from time import sleep
from datetime import datetime
import string
import sys

date = datetime.today()

kernel32 = windll.kernel32

# Let's map the Microsoft types to ctypes for clarity
WORD = c_ushort
DWORD = c_ulong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p

# Constants
DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010

class pmanager():
	Lookup = {}
	pid = ''
	phandle = ''

	def __init__(self, exe=''):
		self.path_to_exe = exe
		print "\n[*] Target process execution string:", self.path_to_exe, "staged and ready for testing.\n"
		
	def run_forever(self):
		debug = debugger()
		ret_code = 1
		print "\n********************************"
		print " Launching new process...    "
		print "*********************************\n"
		while ret_code > 0:
#			try:
			out = subprocess.Popen(self.path_to_exe)
			self.phandle = out
			self.pid = out.pid
			print "[*] Process ID: ", out.pid, "\n"
			#EIP = debug.get_eip(int(self.pid))
			out.wait()

#			except Exception as ex:
#				#print "I/O error({0}): {1}".format(e.errno, e.strerror)
#				print "Something happened."

			ret_code = out.returncode
			#EIP = debug.get_eip(self.pid)
			print "\n[+] Process crashed on", date.ctime()
			print "[+] Return code: ", ret_code
			print "[+] EIP: ", EIP
			EIP = debug.get_eip(int(self.pid))
			self.run_forever()
		"""
		try:
			#now = datetime.utcnow()
			print "Launching target executable"# at ", now.ctime()
			out = subprocess.Popen(self.path_to_exe)
		except Exception as ex:
			#self.Lookup[string.split(now, " ")[0]] = `ex`
			print `ex`
			sleep(2)
		"""




class debugger():

	def __init__(self):
		self.h_process			= None
		self.pid				= None
		self.debugger_active 	= False
		self.h_thread			= None
		self.context			= None
		self.exception			= None
		self.exception_address 	= None
		self.breakpoints		= {}

	def load(self,path_to_exe):
	
		# dwCreation flag determines how to create the process
		creation_flags = DEBUG_PROCESS
		#creation_flags = CREATE_NEW_CONSOLE  #to see the GUI
		
		# instantiate the structs
		startupinfo = STARTUPINFO()
		process_information = PROCESS_INFORMATION()
		startupinfo.dwFlags = 0x1			# allow the process
		startupinfo.wShowWindow = 0x0		#to be slown in a sep win
		
		# We then initialize the cb variable in the STARTUPINFO struct
		# which is just the size of the struct itself
		startupinfo.cb = sizeof(startupinfo)
		if kernel32.CreateProcessA(path_to_exe,
									None,
									None,
									None,
									None,
									creation_flags,
									None,
									None,
									byref(startupinfo),
									byref(process_information)):
			print "[*] Successfully launched process for testing."
			print "[*] PID: %d" % process_information.dwProcessId
			#Obtain handle to process for future use
			self.h_process = self.open_process(process_information.dwProcessId)
		else:
			print "[*] Error: 0x%08x." % kernel32.GetLastError()
			
	
	def open_process(self, pid):
		h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,pid,False)
		return h_process
		
	def attach(self, pid):
		self.h_process = self.open_process(pid)
		
		if kernel32.DebugActiveProcess(pid):
			self.debugger_active = True
			self.pid			 = int(pid)
			self.run()
		else:
			print "[*] Unable to attach to the process."
			
			
	def run(self):
		while self.debugger_active == True:
			self.get_debug_event()

	def get_debug_event(self):
		debug_event = DEBUG_EVENT()
		continue_status = DBG_CONTINUE
		
		if kernel32.WaitForDebugEvent(byref(debug_event),INFINITE):
			# EventHandlers are to come
			#raw_input("Press a key to continue...")
			#self.debugger_active = False
			self.h_thread = self.open_thread(debug_event.dwThreadId)
			self.context = self.get_thread_context(self.h_thread)
			print "Event Code: %d Thread ID: %d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId)

			if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
				#Obtain the exception code...
				self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
				self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
				
				if self.exception == EXCEPTION_ACCESS_VIOLATION:
					print "Access Violation Detected."
					raw_input("")
				elif self.exception == EXCEPTION_BREAKPOINT:
					continue_status = self.exception_handler_breakpoint()
					
				elif self.exception == EXCEPTION_GUARD_PAGE:
					print "Guard Page Access Detected."
					
				elif self.exception == EXCEPTION_SINGLE_STEP:
					print "Single Stepping."

			kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

	def exception_handler_breakpoint(self):
		print "[*] Inside the breakpoint handler."
		print "Exception Address: 0x%08x" % self.exception_address
		return DBG_CONTINUE

			
	def detach(self):
		if kernel32.DebugActiveProcessStop(self.pid):
			#print "[*] Finished debugging. Exiting..."
			return True
		else:
			print "There was an error detatching the process."
			return False
			
	def open_thread(self, thread_id):
		h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
		if h_thread is not None:
			return h_thread
			
		else:
			print "[*] Could not obtain a valid thread handle."
			return False
			
	def enumerate_threads(self):
		thread_entry = THREADENTRY32()
		thread_list = []
		snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
		
		if snapshot is not None:
			thread_entry.dwSize = sizeof(thread_entry)
			success = kernel32.Thread32First(snapshot, byref(thread_entry))
			while success:
				if thread_entry.th32OwnerProcessID == self.pid:
					thread_list.append(thread_entry.th32ThreadID)
				success = kernel32.Thread32Next(snapshot, byref(thread_entry))
					
			kernel32.CloseHandle(snapshot)
			return thread_list
		else:
			return false
			
	def get_thread_context(self, thread_id):
		context = CONTEXT()
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
		
		h_thread = self.open_thread(thread_id)
		if kernel32.GetThreadContext(h_thread, byref(context)):
			kernel32.CloseHandle(h_thread)
			return context
		else:
			return False
	
	def dump_registers(self, pid):
		self.attach(pid)
		list = self.enumerate_threads()
		EIP = ''
		for thread in list:
			#print thread
			thread_context = self.get_thread_context(thread)
			print "[*] Dumping registers for thread ID: 0x%08x" % thread	
			print "[**] EIP: 0x%08x" % thread_context.Eip
			print "[**] ESP: 0x%08x" % thread_context.Esp
			print "[**] EBP: 0x%08x" % thread_context.Ebp
			print "[**] EAX: 0x%08x" % thread_context.Eax
			print "[**] EBX: 0x%08x" % thread_context.Ebx
			print "[**] ECX: 0x%08x" % thread_context.Ecx
			print "[**] EDX: 0x%08x" % thread_context.Edx
			#print "[**] ESP: 0x%08x" % thread_context.Esp
			EIP = "0x%08x" % thread_context.Eip
		self.detach()
		
	def get_eip(self, pid):
		self.attach(pid)
		list = self.enumerate_threads()
		EIP = ''
		for thread in list:
			#print "[*] Dumping EIP for thread ID: 0x%08x" % thread
			thread_context = self.get_thread_context(thread)
			#print "[**] EIP: 0x%08x" % thread_context.Eip
			EIP = "0x%08x" % thread_context.Eip
			print EIP
		self.detach()
		return True
	
	def read_process_memory(self, address, length):
		data 		= ""
		read_buf	= create_string_buffer(length)
		count		= c_ulong(0)
		
		if not kernel32.ReadProcessMemory(self.hprocess,
											address,
											read_buf,
											length,
											byref(count)):
			return False
		else:
			data += read_buf.raw
			return data
			
			
	def write_process_memory(self, address, data):
		count = c_ulong(0)
		length = len(data)
		c_data = c_char_p(data[count.value:])
		if not kernel32.WriteProcessMemory(self.h_process,
											address,
											c_data,
											length,
											byref(count)):
			return False
		else:
			return True
			
	def bp_set(self, address):
		if not self.breakpoints.has_key(address):
			try:
				#store the orig byte	
				original_byte = self.read_process_memory(address, 1)
				
				#write the INT3 opcode
				self.write_process_memory(address, "\xCC")
				
				#register the breakpoint in our internal list
				self.breakpoints[address] = (address, original_byte)
			except:
				return False
		return True
		
	def func_resolve(self, dll, function):
		handle = kernel32.GetModuleHandleA(dll)
		address = kernel32.GetProcAddress(handle, function)
		kernel32.CloseHandle(handle)
		return address
		# left off on page 45 -- Yippie Ki Yay mofo!


class STARTUPINFO(Structure):
	_fields_ = [
		("cb", DWORD),
		("lpReserved", LPTSTR),
		("lpDesktop", LPTSTR),
		("lpTitle", LPTSTR),
		("dwX", DWORD),
		("dwY", DWORD),
		("dwXSize", DWORD),
		("dwYSize", DWORD),
		("dwXCountChars", DWORD),
		("dwYCountChars", DWORD),
		("dwFillAttribute",DWORD),
		("dwFlags", DWORD),
		("wShowWindow", WORD),
		("cbReserved2", WORD),
		("lpReserved2", LPBYTE),
		("hStdInput", HANDLE),
		("hStdOutput", HANDLE),
		("hStdError", HANDLE),
	]
	
	
class PROCESS_INFORMATION(Structure):
	_fields_ = [
		("hProcess", HANDLE),
		("hThread", HANDLE),
		("dwProcessId", DWORD),
		("dwThreadId", DWORD),
	]