"""
Fix decompilation for syscalls and TLS access.
- Kynex7510
"""

import plugin_utility

import ida_hexrays
import ida_allins


# SVC Handler


class SVCHandler(ida_hexrays.udc_filter_t):
    def __init__(self):
        ida_hexrays.udc_filter_t.__init__(self)

    def match(self, cdg):
        if cdg.insn.itype == ida_allins.ARM_svc:
            id = cdg.insn.Op1.value
            if id in plugin_utility.SYSCALL_TYPES:
                self.init(plugin_utility.SYSCALL_TYPES[id])
                return True

        return False

# TLS Handler


class TLSHandler(ida_hexrays.udc_filter_t):
    def __init__(self):
        ida_hexrays.udc_filter_t.__init__(self)

    def match(self, cdg: ida_hexrays.codegen_t):
        if cdg.insn.itype == ida_allins.ARM_mrc:
            cp = cdg.insn.Op1.specflag1
            op1 = cdg.insn.Op2.value
            rd = cdg.insn.Op2.reg
            crn = cdg.insn.Op2.specflag1
            crm = cdg.insn.Op2.specflag2
            op2 = cdg.insn.Op3.value
            if cp == 15 and op1 == 0 and crn == 13 and crm == 0 and op2 == 3:
                self.init(
                    f"void* __usercall getThreadLocalStorage@<r{rd}>(void);")
                return True

        return False


svc_handler = SVCHandler()
tls_handler = TLSHandler()

if not ida_hexrays.init_hexrays_plugin():
    raise Exception("HexRays initialization failed")

if not ida_hexrays.install_microcode_filter(svc_handler, True):
    raise Exception("SVC handler initialization failed")

if not ida_hexrays.install_microcode_filter(tls_handler, True):
    raise Exception("TLS handler initialization failed")
