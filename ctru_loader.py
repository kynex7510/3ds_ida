"""
Nintendo 3DS userland loader.
- Kynex7510
"""

import ida_loader
import ida_entry
import ida_segment
import ida_kernwin

# Globals

MAX_THREADS = (0x30000000 - 0x1FF82000) // 0x200

# Helpers

def add_segment(start, size, name, perms) -> None:
    if perms & ida_segment.SEGPERM_EXEC:
        sclass = "CODE"
    else:
        sclass = "DATA"
    if not ida_segment.add_segm(0, start, start + size, name, sclass):
        raise Exception(f"Could not add segment {name}")
    seg = ida_segment.get_segm_by_name(name)
    ida_segment.set_segm_addressing(seg, 1)
    seg.perm = perms

# CodeInfo

class CodeInfo:
    def __init__(self):
        self._code_base = 0
        self._code_size = 0
        self._rodata_base = 0
        self._rodata_size = 0
        self._data_base = 0
        self._data_size = 0
        self._has_vram_access = False
        self._has_dspmem_access = False
        self._has_shared_page_write = False

    def get_code_base(self):
        return self._code_base
    
    def get_code_size(self):
        return self._code_size
    
    def get_rodata_base(self):
        return self._rodata_base

    def get_rodata_size(self):
        return self._rodata_size
    
    def get_data_base(self):
        return self._data_base
    
    def get_data_size(self):
        return self._data_size

    def has_vram_access(self) -> bool:
        return self._has_vram_access

    def has_dspmem_access(self) -> bool:
        return self._has_dspmem_access

    def has_shared_page_write(self) -> bool:
        return self._has_shared_page_write

def parse_ex_header():
    pass

def ask_for_info():
    pass

# Loader

def accept_file(li, filename):
    if filename == "code.bin":
        return {
            "format" : "Nintendo 3DS Userland (ARM11)",
            "processor" : "ARM",
            "options" : 1 | ida_loader.ACCEPT_FIRST,
        }
    
    return 0

def load_file(li, neflags, format):
    cinfo = CodeInfo()

    # Load informations from ExHeader.
    cinfo = parse_ex_header()

    # Else, ask the user to fill in informations.
    if cinfo == None:
        cinfo = ask_for_info()

    # Add base segments.
    add_segment(0x1FF80000, 0x1000, "CONFIG", ida_segment.SEGPERM_READ)
    add_segment(0x1FF81000, 0x1000, "SHARED",
                ida_segment.SEGPERM_READ | (ida_segment.SEGPERM_WRITE if cinfo.has_shared_page_write() else 0))
    add_segment(0x1FF82000, MAX_THREADS * 0x200, "TLS", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)

    # Add code segment.
    add_segment(cinfo.get_base(), 0x3F00000, "CODE", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC)

    # Add ioregs segment.
    # TODO: 0x1EC00000 - 0x00400000

    # Add optional segments.
    if cinfo.has_vram_access():
        add_segment(0x1F000000, 0x600000, "VRAM", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)

    if cinfo.has_dspmem_access():
        add_segment(0x1FF00000, 0x80000, "CONFIG", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)


    # Load types
    # TODO

    # Set entrypoint
    ida_entry.add_entry(base, base, "start", True)

    return 1