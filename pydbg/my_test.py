import my_debugger
from my_debugger_defines import *

#it's just test to check commit msg of slack.
debugger = my_debugger.debugger()

if False: # test 1
	debugger.load("C:\\windows\\system32\\calc.exe")
else:
	print "*** %d"%PAGE_EXECUTE_READWRITE
	pid = raw_input("Enter the PID of the process to attach to : ")
	debugger.attach(int(pid))
	printf_address = debugger.func_resolve("msvcrt.dll", "printf")
	
	print "[*] Address of printf : 0x%08x"%printf_address
	
	#debugger.bp_set(printf_address)
	debugger.bp_set_hw(printf_address,1,HW_EXECUTE)
	debugger.run()
	#debugger.detach()
