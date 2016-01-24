from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32
#  
class debugger():
	def __init__(self):
		self.h_process				= None
		self.pid 					= None
		self.debugger_active 		= False
		self.h_thread				= None
		self.context 				= None
		self.breakpoints			= {}
		self.first_breakpoint		= True
		self.hardware_breakpoint	= {}
		self.exception				= None
		self.exception_address		= None

	def load(self, path_to_exe):
		creation_flags = DEBUG_PROCESS

		startupinfo			= STARTUPINFO()
		process_information	= PROCESS_INFORMATION()

		startupinfo.dwFlags		= 0x1
		startupinfo.wShowWindow	= 0x0

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
			print "[*] We have successfully launched the process!"
			print "[*] PID : %d"%process_information.dwProcessId

			self.h_process = self.open_process(process_information.dwProcessId)
		else:
			print "[*] Error : 0x%08x."%kernel32.GetLastError()


	def open_process(self, pid):
		h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid) 
		return h_process

	def attach(self,pid):
		self.h_process = self.open_process(pid)

		if kernel32.DebugActiveProcess(pid):
			self.debugger_active 	= True
			self.pid 		= int(pid)
		else:
			print "[*] Unable to attach to the process"

	def run(self):
		while self.debugger_active == True:
			self.get_debug_event()


	def get_debug_event(self):
		debug_event = DEBUG_EVENT()
		continue_status =  DBG_CONTINUE

		if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
			self.h_thread = self.open_thread(debug_event.dwThreadId)
			self.context = self.get_thread_context(h_thread=self.h_thread)

			print "Event Code : %d Thread ID : %d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId)

			if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
				exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
				self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

				if exception == EXCEPTION_ACCESS_VIOLATION:
					print "Access Violation Detected,"
				elif exception == EXCEPTION_BREAKPOINT:
					continue_status = self.exception_handler_breakpoint()		
				elif exception == EXCEPTION_GUARD_PAGE:
					print "Guard Page Acess Detected."
				elif exception == EXCEPTION_SINGLE_STEP:
					self.exception_handler_single_step()
			
			#raw_input("Press a key to continue...")
			#self.debugger_active = False
			kernel32.ContinueDebugEvent( \
				debug_event.dwProcessId,\
				debug_event.dwThreadId,\
				continue_status )

	def detach(self):
		if kernel32.DebugActiveProcessStop(self.pid):
			print "[*] Finished debugging. Exit..."
			return True
		else:	
			print "Threre was an error"
			return False


	def open_thread(self, thread_id):
		h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

		if 0 == h_thread:
			print "[*] OpenThread Failed. %d"%GetLastError()
			return False
		elif h_thread is not None:
			return h_thread
		else:
			print "[*] Could not obtain a valid thread handle."
			return False

	def enumerate_threads(self):
		thread_entry	= THREADENTRY32()
		thread_list 	= []
		snapshot 	= kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        
		if snapshot is not None:
        
			# You have to set the size of the struct
			# or the call will fail
			thread_entry.dwSize = sizeof(thread_entry)
			success = kernel32.Thread32First(snapshot, byref(thread_entry))
			while success:
				if thread_entry.th32OwnerProcessID == self.pid:
					thread_list.append(thread_entry.th32ThreadID)
    
				success = kernel32.Thread32Next(snapshot, byref(thread_entry))
            
			# No need to explain this call, it closes handles
			# so that we don't leak them.
			kernel32.CloseHandle(snapshot)
			return thread_list
		else:
			return False
	def get_thread_context(self, thread_id = None, h_thread = None):
		context = CONTEXT64()
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

		if not h_thread:
			h_thread = self.open_thread(thread_id)
			
		if kernel32.GetThreadContext(h_thread, byref(context)):
			return context 
		else:
			print "Could not get thread context, %d %x"%(GetLastError(), h_thread)
			return False
			
	def exception_handler_breakpoint(self):
		print "[*] Inside the breakpoint handler."
		print "Exception Address : 0x%x" % self.exception_address

		if not self.breakpoints.has_key(self.exception_address):
			return DBG_CONTINUE
		else:
			print "[*] Hit user defined breakpoint."
			self.write_process_memory(self.exception_address, self.breakpoints[self.exception_address])

			self.context = self.get_thread_context(h_thread=self.h_thread)
			self.context.Rip -= 1
            
			kernel32.SetThreadContext(self.h_thread,byref(self.context))
            
			continue_status = DBG_CONTINUE
		
		return continue_status

	def read_process_memory(self, address, length):
		data		= ""
		read_buf	= create_string_buffer(length)
		count 		= c_ulong(0)

		kernel32.ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, WORD, PVOID]
		if not kernel32.ReadProcessMemory(self.h_process,
							address,
							read_buf,
							length,
							byref(count)):
			print "ReadProcMem Error %d, prochandle %x addr %x"%(kernel32.GetLastError(), self.h_process, address)
			return False
		else:
			data += read_buf.raw 
			print "ReadProcMem ok"
			return data

	def write_process_memory(self, address, data):
		count = c_ulong(0)
		length = len(data)

		c_data = c_char_p(data[count.value:])
		kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, c_char_p, WORD, PVOID]
		if not kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
			print "WritePRocessMem Error"
			return False
		else:
			print "WriteProcMem OK"
			return True

	def bp_set(self, address):
		if not self.breakpoints.has_key(address):
			dbg = 0
			#try:
			dbg+=1
			original_byte = self.read_process_memory(address, 1)
			dbg+=1
			self.write_process_memory(address, "\xCC")
			dbg+=1
			self.breakpoints[address] = (original_byte)
			#except:
			#	print "bp_set error %d"%dbg
			#	return False
			print "bp_set ok %x"%address
		return True

	def func_resolve(self, dll, function):

		kernel32.GetModuleHandleA.restype = HANDLE 
		handle = kernel32.GetModuleHandleA(dll)
		
		kernel32.GetProcAddress.restype = PVOID
		kernel32.GetProcAddress.argtypes = [HANDLE, LPTSTR]
		address = kernel32.GetProcAddress(handle, function)

		print "handle : %x, addr : %x"%(handle, address)
		kernel32.CloseHandle.argtypes = [HANDLE]
		kernel32.CloseHandle(handle)

		return address


	def bp_set_hw(self, address, length, condition):
		print "what"
		if length not in (1, 2, 4):
			return False
		else:
			length -= 1

		if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
			return False

		if not self.hardware_breakpoint.has_key(0):
			available = 0
		elif not self.hardware_breakpoint.has_key(1):
			available = 1
		elif not self.hardware_breakpoint.has_key(2):
			available = 2
		elif not self.hardware_breakpoint.has_key(3):
			available = 3
		else:
			return False

		for thread_id in self.enumerate_threads():
			context = self.get_thread_context(thread_id=thread_id)

			context.Dr7 |= 1 << (available*2)

			if available == 0:
				context.Dr0 = address
			elif available == 1:
				context.Dr1 = address
			elif available == 2:
				context.Dr2 = address
			elif available == 3:
				context.Dr3 = address

			context.Dr7 |= condition << ((available*4)+16)
			context.Dr7 |= length <<((available*4) + 18)

			h_thread = self.open_thread(thread_id)
			kernel32.SetThreadContext(h_thread, byref(context))

			self.hardware_breakpoint[available] = (address, length, condition)


		return True



	def exception_handler_single_step(self):
		if self.context.Dr6 & 0x1 and self.hardware_breakpoint.has_key(0):
			slot = 0
		elif self.context.Dr6 & 0x2 and self.hardware_breakpoint.has_key(1):
			slot = 1
		elif self.context.Dr6 & 0x4 and self.hardware_breakpoint.has_key(2):
			slot = 2
		elif self.context.Dr6 & 0x8 and self.hardware_breakpoint.has_key(3):
			slot = 3
		else:
			continue_status = DBG_EXCEPTION_NOT_HANDLED

		if self.bp_del_hw(slot):
			continue_status = DBG_CONTINUE

		print "[*] Hardware breakpoint removed."
		return continue_status

	def bp_del_hw(self,slot):
		for thread_id in self.enumerate_threads():
			context = self.get_thread_context(thread_id=thread_id)

			context.Dr7 &= ~(1<< (slot*2))

			if slot == 0:
				context.Dr0 = 0x00000000
			elif slot == 1:
				context.Dr1 = 0x00000000
			elif slot == 2 :
				context.Dr2 = 0x00000000
			elif slot == 3:
				context.Dr3 = 0x00000000

			context.Dr7 &= ~(3 << ((slot * 4) + 16)) # breakpoint condition reset
			context.Dr7 &= ~(3 << ((slot * 4) + 18)) # length flag reset

			h_thread = self.open_thread(thread_id)
			kernel32.SetThreadContext(h_thread, byref(context))

		del self.hardware_breakpoint[slot]

		return True