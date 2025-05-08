"""
Nintendo 3DS loader.
- Kynex7510
"""

import ctr_utility
from ctr_utility import FileFormat

import ida_ida
import ida_kernwin
import ida_segment
import ida_bytes
import ida_entry
import ida_lines

# Globals

SCRIPT_NAME = "ctr_loader.py"
REPO_URL = "https://github.com/kynex7510/3ds_ida"

MEDIA_UNIT = 0x200
MAX_EXEFS_ENTRIES = 10
FIRM_MODULES = [
    0x1002, # sm
    0x1102, # fs
    0x1202, # pm
    0x1302, # loader
    0x1402, # pxi
]

# CodeInfo

class CodeInfo:
    def __init__(self):
        self._name = "(UNKNOWN)"
        self._title_id = "(UNKNOWN)"
        self._code_compressed = False
        self._text_base = 0
        self._text_size = 0
        self._rodata_base = 0
        self._rodata_size = 0
        self._data_base = 0
        self._data_size = 0
        self._bss_size = 0

    @staticmethod
    def load_from_file(f, off):
        cinfo = CodeInfo()

        # Load title info.
        cinfo._name = ctr_utility.read_cstring(f, off, 8)
        cinfo._title_id = hex(ctr_utility.read_qword(f, off + 0x200))[2:].zfill(16).upper()
        cinfo._code_compressed = ctr_utility.read_bytes(f, off + 0x0D, 1)[0] & 1 == 1

        # Load section info.
        cinfo._text_base = ctr_utility.read_dword(f, off + 0x10)
        cinfo._text_size = ctr_utility.read_dword(f, off + 0x18)
        cinfo._rodata_base = ctr_utility.read_dword(f, off + 0x20)
        cinfo._rodata_size = ctr_utility.read_dword(f, off + 0x28)
        cinfo._data_base = ctr_utility.read_dword(f, off + 0x30)
        cinfo._data_size = ctr_utility.read_dword(f, off + 0x38)
        cinfo._bss_size = ctr_utility.read_dword(f, off + 0x3C)

        return cinfo

    @staticmethod
    def load_from_input():
        cinfo = CodeInfo()
        cinfo._code_compressed = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Is the code compressed?") == ida_kernwin.ASKBTN_YES
        cinfo._text_base = ida_kernwin.ask_addr(0x00100000, "Enter the base address for the .text section:")
        cinfo._text_size = ida_kernwin.ask_long(0x1000, "Enter the size of the .text section:")
        cinfo._rodata_base = ida_kernwin.ask_addr(0, "Enter the base address for the .rodata section:")
        cinfo._rodata_size = ida_kernwin.ask_long(0x1000 if cinfo._rodata_base else 0, "Enter the size of the .rodata section:")
        cinfo._data_base = ida_kernwin.ask_addr(0, "Enter the base address for the .data section:")
        cinfo._data_size = ida_kernwin.ask_long(0x1000 if cinfo._data_base else 0, "Enter the size for the .data section:")
        cinfo._bss_size = ida_kernwin.ask_long(0x1000, "Enter the size for the .bss section:")
        return cinfo

    def name(self):
        return self._name

    def title_id(self):
        return self._title_id

    def is_code_compressed(self):
        return self._code_compressed

    def is_sysmodule(self):
        return self._title_id.startswith("00040130")
    
    def is_firm_module(self):
        low = int(self._title_id[8:], base=16) & 0xFFFFFFFE # Clear SAFE_MODE bit.
        return True if low in FIRM_MODULES else False

    def text_base(self):
        return self._text_base

    def text_size(self):
        return self._text_size
    
    def text_offset(self):
        return 0

    def rodata_base(self):
        return self._rodata_base

    def rodata_size(self):
        return self._rodata_size
    
    def rodata_offset(self):
        if (self.is_firm_module()):
            return self.text_offset() + self.text_size()
        
        return self.rodata_base() - self.text_base()

    def has_rodata(self):
        return self._rodata_base and self._rodata_size

    def data_base(self):
        return self._data_base

    def data_size(self):
        return self._data_size
    
    def data_offset(self):
        if (self.is_firm_module()):
            return self.rodata_offset() + self.rodata_size()

        return self.data_base() - self.text_base()

    def has_data(self):
        return self._data_base and self._data_size

    def bss_base(self):
        base = 0
        size = 0

        if self.has_data():
            base = self.data_base()
            size = self.data_size()
        elif self.has_rodata():
            base = self.rodata_base()
            size = self.rodata_size()
        else:
            base = self.text_base()
            size = self.text_size()

        return base + size

    def bss_size(self):
        return self._bss_size

    def has_bss(self):
        return self._bss_size

# Loader

def setup_sections(cinfo, code_bin_data):
    # Add sections.
    ctr_utility.add_segment(cinfo.text_base(), cinfo.text_size(), ".text", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC)
    code_bytes = code_bin_data[cinfo.text_offset():cinfo.text_offset() + cinfo.text_size()]
    ida_bytes.put_bytes(cinfo.text_base(), code_bytes)

    if cinfo.has_rodata():
        ctr_utility.add_segment(cinfo.rodata_base(), cinfo.rodata_size(), ".rodata", ida_segment.SEGPERM_READ)
        rodata_bytes = code_bin_data[cinfo.rodata_offset():cinfo.rodata_offset() + cinfo.rodata_size()]
        ida_bytes.put_bytes(cinfo.rodata_base(), rodata_bytes)

    if cinfo.has_data():
        ctr_utility.add_segment(cinfo.data_base(), cinfo.data_size(), ".data", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)
        data_bytes = code_bin_data[cinfo.data_offset():cinfo.data_offset() + cinfo.data_size()]
        ida_bytes.put_bytes(cinfo.data_base(), data_bytes)

    if cinfo.has_bss():
        ctr_utility.add_segment(cinfo.bss_base(), cinfo.bss_size(), ".bss", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)

    # Set entrypoint.
    ida_entry.add_entry(cinfo.text_base(), cinfo.text_base(), "start", True)

def extract_code_bin(exefs_bytes):
    for i in range(MAX_EXEFS_ENTRIES):
        file_name = str(exefs_bytes[0x10 * i:0x10*i + 8].decode()).rstrip('\0')
        if file_name == ".code":
            file_off = int.from_bytes(exefs_bytes[0x10*i + 0x8:0x10*i + 0xC], 'little')
            file_size = int.from_bytes(exefs_bytes[0x10*i + 0xC:0x10*i + 0x10], 'little')
            return exefs_bytes[0x200 + file_off:0x200 + file_off + file_size]

    ida_kernwin.warning("ExeFS does not contain a .code file.")
    return None

def load_code(f, format, cinfo):
    code_bin_data = None

    # CXI: read .code from exefs.
    if format == FileFormat.CXI:
        exefs_off = ctr_utility.read_dword(f, 0x1A0) * MEDIA_UNIT
        exefs_size = ctr_utility.read_dword(f, 0x1A4) * MEDIA_UNIT
        exefs_bytes = ctr_utility.read_bytes(f, exefs_off, exefs_size)
        code_bin_data = extract_code_bin(exefs_bytes)
        if not code_bin_data:
            return False

    # ExeFS: read .code.
    if format == FileFormat.ExeFS:
        f.seek(0, 2)
        exefs_bytes = ctr_utility.read_bytes(f, 0, f.tell())
        code_bin_data = extract_code_bin(exefs_bytes)
        if not code_bin_data:
            return False

    # Raw: load from file.
    if format == FileFormat.Raw:
        f.seek(0, 2)
        code_bin_data = ctr_utility.read_bytes(f, 0, f.tell())

    # Decompress if needed.
    if cinfo.is_code_compressed():
        code_bin_data = ctr_utility.blz_decompress(code_bin_data)

    setup_sections(cinfo, code_bin_data)
    return True

def load_code_info(f, format):
    # CXI: read from exheader.
    if format == FileFormat.CXI:
        return CodeInfo.load_from_file(f, 0x200)

    # Raw/ExeFS: load from external exheader/user input.
    if format in [FileFormat.Raw, FileFormat.ExeFS]:
        exh_path = ida_kernwin.ask_file(False, "exheader.bin", "Choose ExHeader file")
        if exh_path:
            with open(exh_path, "rb") as f:
                return CodeInfo.load_from_file(f, 0)
        else:
            return CodeInfo.load_from_input()

    # Unreachable.
    raise Exception("Invalid format")

def accept_file(f, path):
    format = FileFormat.get_from_file(f)
    if not format:
        format = FileFormat.get_from_path(path)

    # CRO is handled by the other script.
    if format == FileFormat.CRO:
        return 0

    return ctr_utility.get_accept_file_result(format)

def load_file(f, neflags, format_string):
    format = FileFormat.get_from_format_string(format_string)
    cinfo = load_code_info(f, format)

    if load_code(f, format, cinfo):
        ida_ida.idainfo_set_64bit(False)
        ida_lines.add_extra_line(cinfo.text_base(), True, f"; Loaded with {SCRIPT_NAME}")
        ida_lines.add_extra_line(cinfo.text_base(), True, f"; {REPO_URL}")
        ida_lines.add_extra_line(cinfo.text_base(), True, f"; Name: {cinfo.name()}")
        ida_lines.add_extra_line(cinfo.text_base(), True, f"; Title ID: {cinfo.title_id()}")
        ida_lines.add_extra_line(cinfo.text_base(), True, f"; Is compressed? {'Yes' if cinfo.is_code_compressed() else 'No'}")
        ida_lines.add_extra_line(cinfo.text_base(), True, f"; Is sysmodule? {'Yes' if cinfo.is_sysmodule() else 'No'}")
        ida_lines.add_extra_line(cinfo.text_base(), True, f"; Is FIRM module? {'Yes' if cinfo.is_firm_module() else 'No'}")
        return 1

    return 0
