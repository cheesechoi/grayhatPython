from immlib import *


def main(args):
	_imm	= Debugger()
	search_code = " ".join(args)
	search_bytes = _imm.assemble(search_code)
	search_result = _imm.search(search_bytes)

	for hit in search_result:
		code_page = _imm.getMemoryPageByAddress(hit)
		access = code_page.getAccess(human = True)

		if "execute" in access.lower():
			_imm.log("[*] Found : %s (0x%08x)" % (search_code,hit), address = hit)

	return "[*] Finished searching for instructions, check the Log window."
