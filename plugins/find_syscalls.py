"""
Find syscalls.
- Kynex7510
"""

import plugin_utility

import ida_funcs
import ida_kernwin
import ida_bytes

# Globals

PLUGIN_NAME = "find_syscalls.py"

ssr_counter = 0

# Helper


def handle_func(func, comment_syscalls, rename_sync_requests):
    global ssr_counter

    # Find syscalls.
    func_bytes = plugin_utility.get_func_bytes(func)
    syscalls = plugin_utility.get_func_syscalls(func.start_ea, func_bytes)
    # Handle all syscalls.
    for address, syscall_id in syscalls.items():
        if syscall_id not in plugin_utility.SYSCALL_NAMES:
            continue
        sys_name = plugin_utility.SYSCALL_NAMES[syscall_id]
        # Handle svcSendSyncRequest.
        if syscall_id == 0x32 and rename_sync_requests:
            plugin_utility.rename(
                func.start_ea, f"UnknownSyncRequest{ssr_counter}")
            ssr_counter += 1
        else:
            plugin_utility.log(
                PLUGIN_NAME, f"Found 'svc{sys_name}' @{hex(address)}, in function @{hex(func.start_ea)}")
        # Add comment.
        if comment_syscalls:
            ida_bytes.set_cmt(address, f"svc{sys_name}", 0)

    return

# Main


text_base = plugin_utility.get_segment_base(".text")
if text_base:
    # Ask for commenting syscalls.
    comment_syscalls = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_NO, "Would you like to comment syscalls with their name?") == ida_kernwin.ASKBTN_YES

    # Ask for renaming sync requests.
    ssr_counter = 0
    rename_sync_requests = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_NO, "Would you like to rename all the functions calling svcSendSyncRequest?") == ida_kernwin.ASKBTN_YES

    # Iterate all functions.
    current_addr = text_base - 1
    while True:
        func = ida_funcs.get_next_func(current_addr)
        if not func:
            break
        handle_func(func, comment_syscalls, rename_sync_requests)
        current_addr = func.start_ea

    # Iterate all function chunks.
    current_addr = text_base - 1
    while True:
        func = ida_funcs.get_next_fchunk(current_addr)
        if not func:
            break
        handle_func(func, comment_syscalls, rename_sync_requests)
        current_addr = func.start_ea

    plugin_utility.log(PLUGIN_NAME, "Done!")
else:
    raise Exception("Could not find .text base")
