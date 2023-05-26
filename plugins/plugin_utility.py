"""
Utility used by plugins.
- Kynex7510
"""

import capstone

import ida_funcs
import ida_segment
import ida_bytes
import ida_name

# Globals

ARM_DASM = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM + capstone.CS_MODE_LITTLE_ENDIAN)
ARM_DASM.detail = True

THUMB_DASM = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB + capstone.CS_MODE_LITTLE_ENDIAN)
THUMB_DASM.detail = True

# Helpers

def _is_thumb(addr):
    return False # TODO

# Utility

"""
Log to console.
"""
def log(plugin_name, message):
    print(f"[{plugin_name}] {message}")

"""
Set name at address.
"""
def rename(addr, name):
    ida_name.set_name(addr, name, 0)

"""
Get segment base by name.
Return 0 on failure.
"""
def get_segment_base(name):
    segm = ida_segment.get_segm_by_name(name)
    if segm:
        linear = ida_segment.get_segm_base(segm)
        return segm.start_ea - linear
    return 0

"""
Get function bytes.
Return None on failure.
"""
def get_func_bytes(func: ida_funcs.func_t):
    return ida_bytes.get_bytes(func.start_ea, func.end_ea - func.start_ea)

"""
Find every syscall in a function.
Returns address + syscall id.
"""
def get_func_syscalls(func_addr, func_bytes):
    result = {}
    dasm = THUMB_DASM if _is_thumb(func_addr) else ARM_DASM
    for insn in dasm.disasm(func_bytes, func_addr):
        if insn.id == capstone.arm.ARM_INS_SVC:
            result[insn.address] = insn.operands[0].value.imm
    return result