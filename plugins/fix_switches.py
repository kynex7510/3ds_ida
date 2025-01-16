"""
Fix switch case handling.
- Kynex7510
"""

from plugin_utility import IDAUtils, Logger

import ida_bytes
import ida_xref
import ida_ua
import idc

# ldrb r12, [lr, #-1]
# cmp r3, r12
SWITCH_SIGNATURE = "0xE55EC001 0xE153000C"
SWITCH_NAME = "__ARM_switch8"

LOGGER = Logger("fix_switches.py")

if __name__ == "__main__":
    text_base = IDAUtils.get_segment_base(".text")
    text_size = IDAUtils.get_segment_size(".text")
    if text_base and text_size:
        # Find switch handler.
        patterns = ida_bytes.compiled_binpat_vec_t()
        if ida_bytes.parse_binpat_str(patterns, text_base, SWITCH_SIGNATURE, 16):
            raise Exception("Could not create pattern object")  # Shouldn't happen.
        switch_handler, _ = ida_bytes.bin_search(text_base, text_base + text_size, patterns, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_BITMASK | ida_bytes.BIN_SEARCH_NOSHOW)
        if switch_handler != idc.BADADDR:
            print(switch_handler)
            LOGGER.log(f"Found switch handler: {hex(switch_handler)}")
            # Rename switch handler.
            IDAUtils.set_name(switch_handler, SWITCH_NAME)
            # Iterate and fix switch references.
            switch_addr = ida_xref.get_first_cref_to(switch_handler)
            while switch_addr != idc.BADADDR:
                if switch_addr > text_base and switch_addr < (text_base + text_size):
                    LOGGER.log(f"Fixing switch block: {hex(switch_addr)}")
                    ida_bytes.del_items(switch_addr, 0, 4)
                    ida_ua.create_insn(switch_addr)
                switch_addr = ida_xref.get_next_cref_to(switch_handler, switch_addr)
        else:
            LOGGER.log("Couldn't find switch handler. Nothing to do.")
    else:
        raise Exception("Could not find .text base")