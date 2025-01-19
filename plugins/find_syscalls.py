"""
Find syscalls.
- Kynex7510
"""

from plugin_utility import IDAUtils, Logger, Disassembler, SyscallDB

import ida_funcs
import ida_bytes

LOGGER = Logger("find_syscalls.py")
DASM = Disassembler()
SYSCALLDB = SyscallDB()

def _get_func_syscalls(func_addr, func_bytes):
    result = {}
    for insn in DASM.dasm(func_bytes, func_addr):
        if DASM.is_syscall(insn):
            id = insn.operands[0].value.imm
            if id > 0 and id <= 0xFF:
                result[insn.address] = id

    return result

def _handle_func(func: int, sendSyncRequest: bool, comment_syscalls: bool, rename_sync_requests: bool, output_file) -> None:
    # Find syscalls.
    func_bytes = IDAUtils.get_func_bytes(func)
    syscalls = _get_func_syscalls(func.start_ea, func_bytes)
    # Handle all syscalls.
    for address, syscall_id in syscalls.items():
        syscall = SYSCALLDB.get_by_id(syscall_id)
        # Handle svcSendSyncRequest.
        if syscall == sendSyncRequest and rename_sync_requests:
            IDAUtils.set_name(func.start_ea, "UnknownSyncRequest")
        # Log syscall.
        syscall_name = f"svc{syscall.name()}" if syscall else f"UNKNOWN_{hex(syscall_id)[2:].upper()}"
        fmt = f"Found {syscall_name} @{hex(address)}, in function @{hex(func.start_ea)}"
        if output_file:
            output_file.write(fmt + "\n")
        else:
            LOGGER.log(fmt)
        # Add comment.
        if syscall and comment_syscalls:
            ida_bytes.set_cmt(address, f"svc{syscall.name()}", 0)

    return None

if __name__ == "__main__":
    text_base = IDAUtils.get_segment_base(".text")
    if text_base:
        # Ask for commenting syscalls.
        comment_syscalls = IDAUtils.ask_question("Would you like to comment syscalls with their name?")

        # Ask for renaming sync requests.
        rename_sync_requests = IDAUtils.ask_question("Would you like to rename all the functions calling svcSendSyncRequest?")

        # Ask for saving the result.
        output_file = None
        if IDAUtils.ask_question("Would you like to save the result to a file?"):
            output_file = open(IDAUtils.ask_file(True, "Select a file where to save the output", "output.txt"), "w")

        # Find svcSendSyncRequest.
        sendSyncRequest = SYSCALLDB.get_by_name("SendSyncRequest")
        if not sendSyncRequest:
            LOGGER.log("SendSyncRequest not declared!")

        # Iterate all functions.
        current_addr = text_base - 1
        while True:
            func = ida_funcs.get_next_func(current_addr)
            if not func:
                break
            _handle_func(func, sendSyncRequest, comment_syscalls, rename_sync_requests, output_file)
            current_addr = func.start_ea

        if output_file:
            output_file.close()
        LOGGER.log("Done!")
    else:
        raise Exception("Could not find .text base!")
