#hippie_easy

import immlib
import immutils

# this function made for finding RET instruction.
# getImmConst means opearand of RET opcode.
# example - RET 0xC : this function called with 3 arguments.
# In grayhatPython, this function used to find RtlAllocateHeap's RET.
# RtlAllocationHeap has 3 arguments.
def getRet(imm, allocaddr, max_opcodes=300):
	addr = allocaddr
	for a in range(0, max_opcodes):
		op = imm.disasmForward(addr)

		if op.isRet():
			if op.getImmConst() == 0x0C:
				op = imm.disasmBackward(addr, 3)
				return op.getAddress()
		addr = op.getAddress()

	return 0x0


def showResult ( imm, a, rtlallocate ):
	if a[0] == rtlallocate:
		imm.log( "RtlAllocateHeap(0x%08x, 0x%08x, 0x%08x) <- 0x%08x %s" % (a[1][0], a[1][1], a[1][2], a[1][3], extra), address = a[1][3])
		return "done"
	else:
		imm.log ( "RtlFreeHeap(0x%08x, 0x%08x, 0x%08x)"%(a[1][0], a[1][1], a[1][2]))

def main(args):
	imm = immlib.Debugger()
	Name = "hippie"

	fast = imm.getKnowledge(Name)

	if fast:
		# if already hooked, it print result of hook.
		hook_list = fast.getAllLog()

		rtlallocate, rtlfree = imm.getKnowledge("FuncNames")
		for a in hook_list:
			ret = showresult( imm, a, rtlallocate )

			return "Logged : %d hook hits."%len(hook_list)
	
	imm.pause()
	rtlfree = imm.getAddress("ntdll.RtlFreeHeap")
	rtlallocate = imm.getAddress("ntdll.RtlAllocateHeap")
	
	module = imm.getModule("ntdll.dll")

	imm.log("%s"%module.isAnalysed())
	if not module.isAnalysed():
		
		imm.analyseCode( module.getCodebase() )

	rtlallocate = getRet(imm, rtlallocate, 1000)
	imm.log("RtlAllocateHeap hook: 0x%08x"%rtlallocate)

	imm.addKnowledge("FuncNames", (rtlallocate, rtlfree))

	fast = immlib.STDCALLFastLogHook( imm )

	imm.log("Logging on Alloc 0x%08x" % rtlallocate)
	fast.logFunction(rtlallocate)
	fast.logBaseDisplacement("EBP", 8)
	fast.logBaseDisplacement("EBP", 0xc)
	fast.logBaseDisplacement("EBP", 0x10)
	fast.logRegister("EAX")

	imm.log("Logging on RtlFreeHEap 0x%08x"%rtlfree)
	fast.logFunction(rtlfree, 3)

	fast.Hook()

	imm.addKnowledge(Name, fast,force_add = 1)

	return  "Hooks set, press F9 to continue the process."
