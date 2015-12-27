import my_debugger

debugger = my_debugger.debugger()

if False: # test 1
	debugger.load("C:\\windows\\system32\\calc.exe")
else:
	pid = raw_input("Enter the PID of the process to attach to : ")
	debugger.attach(int(pid))
	
	list = debugger.enumerate_threads()
	
	for thread in list:
	
		thread_context = debugger.get_thread_context(thread)
	
		print "[*] Dumping registers for threadID : 0x%08x"%thread
		print "[**] EIP : 0x%08x"%thread_context.Eip
		print "[**] ESP : 0x%08x"%thread_context.Esp
		print "[**] EBP : 0x%08x"%thread_context.Ebp
		print "[**] EAX : 0x%08x"%thread_context.Eax
		print "[**] EBX : 0x%08x"%thread_context.Ebx
		print "[**] ECX : 0x%08x"%thread_context.Ecx
		print "[**] EDX : 0x%08x"%thread_context.Edx
		print "[*] End Dump"

	debugger.run()
	debugger.detach()
