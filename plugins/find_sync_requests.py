"""
find each function that calls svcSendSyncRequest.
- Kynex7510
"""

import plugin_utility

import ida_funcs
import ida_kernwin

# Globals

PLUGIN_NAME = "find_sync_requests.py"

# Main

ren_counter = 0
text_base = plugin_utility.get_segment_base(".text")
if text_base:
    # Ask for renaming functions.
    should_rename = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_NO, "Would you like to rename all the results?") == ida_kernwin.ASKBTN_YES

    # Iterate all functions in .text.
    current_addr = text_base - 1
    while True:
        func: ida_funcs.func_t = ida_funcs.get_next_func(current_addr)
        if not func:
            break
        # Find syscalls.
        func_bytes = plugin_utility.get_func_bytes(func)
        syscalls = plugin_utility.get_func_syscalls(func.start_ea, func_bytes)
        # Iterate and look for svcSendSyncRequest.
        for address, svcid in syscalls.items():
            if svcid == 0x32:
                if should_rename:
                    plugin_utility.rename(
                        func.start_ea, f"UnknownSyncRequest{ren_counter}")
                    ren_counter += 1
                else:
                    plugin_utility.log(
                        PLUGIN_NAME, f"Found function @{hex(func.start_ea)}, call @{hex(address)}")

        current_addr = func.start_ea
else:
    raise Exception("Could not find .text base")
