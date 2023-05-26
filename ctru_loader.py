"""
Nintendo 3DS ARM11 loader.
- Kynex7510
"""

import struct

import ida_loader
import ida_entry
import ida_segment
import ida_kernwin
import ida_bytes
import ida_lines

# Globals

PAGE_SIZE = 0x1000
MAX_DEPS = 48
SCRIPT_NAME = "ctru_loader.py"
REPO_URL = "https://github.com/kynex7510/3ds_ida"

# Helpers

def get_format_string(path):
    format = "Nintendo 3DS ARM11"
    
    if path.endswith("code.bin"):
        format += " (Raw)"
    #elif path.endswith(".exefs"):
     #   format += " (ExeFS)"
    #elif path.endswith(".cxi"):
    #    format += " (CXI)"
    #elif path.endswith(".cia"):
    #    format += " (CIA)"
    #elif path.endswith(".cro"):
    #    format += " (CRO)"
    else:
        format = ""

    return format

def align_up(val, align):
    return val + (align - 1) & ~(align - 1)

def read_bytes(f, off, size):
    f.seek(off)
    b = f.read(size)
    if len(b) < size:
        raise Exception("Could not read bytes from file")
    return b

def read_dword(f, off):
    return struct.unpack('<I', read_bytes(f, off, 4))[0]

def read_qword(f, off):
    return struct.unpack('<Q', read_bytes(f, off, 8))[0]

def add_segment(start, size, name, perms) -> None:
    if perms & ida_segment.SEGPERM_EXEC:
        sclass = "CODE"
    elif perms == ida_segment.SEGPERM_READ:
        sclass = "CONST"
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
        self._name = "(UNKNOWN)"
        self._title_id = "(UNKNOWN)"
        self._sysmodule = False
        self._text_base = 0
        self._text_size = 0
        self._rodata_base = 0
        self._rodata_size = 0
        self._data_base = 0
        self._data_size = 0

    def valid(self):
        return self._text_size != 0
    
    def get_name(self):
        return self._name

    def get_title_id(self):
        return self._title_id
    
    def is_sysmodule(self):
        return self._sysmodule

    def get_text_base(self):
        return self._text_base
    
    def get_text_size(self):
        return self._text_size
    
    def get_rodata_base(self):
        return self._rodata_base

    def get_rodata_size(self):
        return self._rodata_size
    
    def has_rodata(self):
        return self._rodata_base and self._rodata_size
    
    def get_data_base(self):
        return self._data_base
    
    def get_data_size(self):
        return self._data_size
    
    def has_data(self):
        return self._data_base and self._data_size

def parse_ex_header(f, offset):
    cinfo = CodeInfo()

    # Load title info.
    cinfo._name = str(read_bytes(f, offset, 8).decode())
    cinfo._title_id = hex(read_qword(f, offset + 0x200))[2:].zfill(16)
    cinfo._sysmodule = read_bytes(f, offset + 0x36F, 1)[0] == 0x03

    # Load section info.
    cinfo._text_base = read_dword(f, offset + 0x10)
    cinfo._text_size = read_dword(f, offset + 0x18)
    cinfo._rodata_base = read_dword(f, offset + 0x20)
    cinfo._rodata_size = read_dword(f, offset + 0x28)
    cinfo._data_base = read_dword(f, offset + 0x30)
    cinfo._data_size = read_dword(f, offset + 0x38)

    if not cinfo._sysmodule:
        cinfo._text_size = align_up(cinfo._text_size, PAGE_SIZE)
        cinfo._rodata_size = align_up(cinfo._rodata_size, PAGE_SIZE)
        cinfo._data_size = align_up(cinfo._data_size, PAGE_SIZE)

    return cinfo

def ask_for_info():
    cinfo = CodeInfo()
    cinfo._text_base = ida_kernwin.ask_addr(0x00100000, "Enter the base address for the .text section:")
    cinfo._text_size = ida_kernwin.ask_long(0x1000, "Enter the size of the .text section:")
    cinfo._rodata_base = ida_kernwin.ask_addr(0, "Enter the base address for the .rodata section:")
    cinfo._rodata_size = ida_kernwin.ask_long(0x1000 if cinfo._rodata_base else 0, "Enter the size of the .rodata section:")
    cinfo._data_base = ida_kernwin.ask_addr(0, "Enter the base address for the .data section:")
    cinfo._data_size = ida_kernwin.ask_long(0x1000 if cinfo._data_base else 0, "Enter the size for the .data section:")
    return cinfo

# Loader

def accept_file(li, filename):
    format = get_format_string(filename)

    if format:
        return {
            "format" : format,
            "processor" : "ARM",
            "options" : 1 | ida_loader.ACCEPT_FIRST,
        }
    
    return 0

def load_file(li, neflags, format):
    cinfo = CodeInfo()

    # Load informations from ExHeader.
    exh_path = ida_kernwin.ask_file(False, "exheader.bin", "Choose ExHeader file")
    if exh_path:
        with open(exh_path, "rb") as f:
            cinfo = parse_ex_header(f, 0)

    # Else, ask the user to fill in informations.
    if not cinfo.valid():
        cinfo = ask_for_info()

    # Add base sections.
    add_segment(cinfo.get_text_base(), cinfo.get_text_size(), ".text", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC)
    code_bytes = read_bytes(li, 0, cinfo.get_text_size())
    ida_bytes.put_bytes(cinfo.get_text_base(), code_bytes)

    if cinfo.has_rodata():
        add_segment(cinfo.get_rodata_base(), cinfo.get_rodata_size(), ".rodata", ida_segment.SEGPERM_READ)
        rodata_bytes = read_bytes(li, cinfo.get_rodata_base() - cinfo.get_text_base(), cinfo.get_rodata_size())
        ida_bytes.put_bytes(cinfo.get_rodata_base(), rodata_bytes)

    if cinfo.has_data():
        add_segment(cinfo.get_data_base(), cinfo.get_data_size(), ".data", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)
        data_bytes = read_bytes(li, cinfo.get_data_base() - cinfo.get_text_base(), cinfo.get_data_size())
        ida_bytes.put_bytes(cinfo.get_data_base(), data_bytes)

    # Add ioregs.
    # TODO: 0x1EC00000 - 0x00400000

    # Set entrypoint.
    ida_entry.add_entry(cinfo.get_text_base(), cinfo.get_text_base(), "start", True)

    # We're done.
    ida_lines.add_extra_line(cinfo.get_text_base(), True, f"; Loaded with {SCRIPT_NAME}")
    ida_lines.add_extra_line(cinfo.get_text_base(), True, f"; {REPO_URL}")
    ida_lines.add_extra_line(cinfo.get_text_base(), True, f"; Name: {cinfo.get_name()}")
    ida_lines.add_extra_line(cinfo.get_text_base(), True, f"; Title ID: {cinfo.get_title_id()}")
    ida_lines.add_extra_line(cinfo.get_text_base(), True, f"; Is sysmodule? {'Yes' if cinfo.is_sysmodule() else 'No'}")
    return 1