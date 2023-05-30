"""
Nintendo 3DS ARM11 loader.
- Kynex7510
"""

import enum
from pathlib import Path

import ida_loader
import ida_entry
import ida_segment
import ida_kernwin
import ida_bytes
import ida_lines

# Globals

PAGE_SIZE = 0x1000
MEDIA_UNIT = 0x200
MAX_EXEFS_ENTRIES = 10
SCRIPT_NAME = "ctru_loader.py"
REPO_URL = "https://github.com/kynex7510/3ds_ida"

# Helpers


def blz_decompress(input_data):
    delta_size = int.from_bytes(input_data[-4:], 'little')
    ranges = int.from_bytes(input_data[-8:-4], 'little')
    current_out = len(input_data) + delta_size
    current_in = len(input_data) - (ranges >> 24)
    end = len(input_data) - (ranges & 0xFFFFFF)
    buffer = [b'\0'] * (len(input_data) + delta_size)
    buffer[:len(input_data)] = input_data

    while current_in > end:
        current_in -= 1
        control = buffer[current_in]
        for _ in range(8):
            if control & 0x80:
                current_in -= 1
                b1 = buffer[current_in]
                current_in -= 1
                b2 = buffer[current_in]
                index = ((b2 | (int(b1) << 8)) & 0xFFFF0FFF) + 2
                loops = (b1 >> 4) + 2
                while True:
                    b = buffer[current_out + index]
                    current_out -= 1
                    buffer[current_out] = b
                    loops -= 1
                    if loops < 0:
                        break
            else:
                current_out -= 1
                current_in -= 1
                buffer[current_out] = buffer[current_in]

            control = (control << 1) & 0xFF
            if current_in <= end:
                return bytes(buffer)

    return bytes(buffer)


def align_up(val, align):
    return val + (align - 1) & ~(align - 1)


def read_bytes(f, off, size):
    f.seek(off)
    b = f.read(size)
    if len(b) < size:
        raise Exception("Could not read bytes from file")
    return b


def read_dword(f, off):
    return int.from_bytes(read_bytes(f, off, 4), 'little')


def read_qword(f, off):
    return int.from_bytes(read_bytes(f, off, 8), 'little')


def read_string(f, off, len):
    return str(read_bytes(f, off, len).decode()).rstrip('\0')


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


def extract_code_bin(exefs_bytes):
    for i in range(MAX_EXEFS_ENTRIES):
        file_name = str(exefs_bytes[0x10 * i:0x10*i + 8].decode()).rstrip('\0')
        if file_name == ".code":
            file_off = int.from_bytes(
                exefs_bytes[0x10*i + 0x8:0x10*i + 0xC], 'little')
            file_size = int.from_bytes(
                exefs_bytes[0x10*i + 0xC:0x10*i + 0x10], 'little')
            return exefs_bytes[0x200 + file_off:0x200 + file_off + file_size]

    ida_kernwin.warning("ExeFS does not contain a .code file.")
    return None

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

    @staticmethod
    def load_from_file(f, off):
        cinfo = CodeInfo()

        # Load title info.
        cinfo._name = read_string(f, off, 8)
        cinfo._title_id = hex(read_qword(f, off + 0x200))[2:].zfill(16)
        cinfo._code_compressed = read_bytes(f, off + 0x0D, 1)[0] & 1 == 1

        # Load section info.
        cinfo._text_base = read_dword(f, off + 0x10)
        cinfo._text_size = read_dword(f, off + 0x18)
        cinfo._rodata_base = read_dword(f, off + 0x20)
        cinfo._rodata_size = read_dword(f, off + 0x28)
        cinfo._data_base = read_dword(f, off + 0x30)
        cinfo._data_size = read_dword(f, off + 0x38)

        # Load ioregs info.
        # TODO

        # Align to page if not a sysmodule.
        if not cinfo.is_sysmodule():
            cinfo._text_size = align_up(cinfo._text_size, PAGE_SIZE)
            cinfo._rodata_size = align_up(cinfo._rodata_size, PAGE_SIZE)
            cinfo._data_size = align_up(cinfo._data_size, PAGE_SIZE)

        return cinfo

    @staticmethod
    def load_from_input():
        cinfo = CodeInfo()
        cinfo._code_compressed = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO, "Is the code compressed?") == ida_kernwin.ASKBTN_YES
        cinfo._text_base = ida_kernwin.ask_addr(
            0x00100000, "Enter the base address for the .text section:")
        cinfo._text_size = ida_kernwin.ask_long(
            0x1000, "Enter the size of the .text section:")
        cinfo._rodata_base = ida_kernwin.ask_addr(
            0, "Enter the base address for the .rodata section:")
        cinfo._rodata_size = ida_kernwin.ask_long(
            0x1000 if cinfo._rodata_base else 0, "Enter the size of the .rodata section:")
        cinfo._data_base = ida_kernwin.ask_addr(
            0, "Enter the base address for the .data section:")
        cinfo._data_size = ida_kernwin.ask_long(
            0x1000 if cinfo._data_base else 0, "Enter the size for the .data section:")
        return cinfo

    def valid(self):
        return self._text_size != 0

    def get_name(self):
        return self._name

    def get_title_id(self):
        return self._title_id

    def is_code_compressed(self):
        return self._code_compressed

    def is_sysmodule(self):
        return self._title_id.startswith("00040130")

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

# FileFormat


class FileFormat(enum.Enum):
    Raw = 0
    ExeFS = 1
    CXI = 2
    CIA = 3
    CRO = 4

    @staticmethod
    def get_from_file(f):
        ncch_magic = read_string(f, 0x100, 4)
        crypto_method = read_bytes(f, 0x18B, 1)[0]
        content_type = read_bytes(f, 0x18D, 1)[0]
        if ncch_magic == "NCCH" and (content_type & 0x02):
            # Warn user about encryption.
            if crypto_method != 0x00:
                ida_kernwin.warning(
                    "Encrypted CXI file detected. Please decrypt it before loading it.")
            else:
                return FileFormat.CXI

        return None

    @staticmethod
    def get_from_path(path):
        name = Path(path).name.lower()

        if name == "code.bin":
            return FileFormat.Raw
        elif name.endswith(".exefs"):
            return FileFormat.ExeFS

        return None

    @staticmethod
    def get_from_format_string(format_string: str):
        for i in range(len(FileFormat)):
            if format_string.find(FileFormat(i).name) != -1:
                return FileFormat(i)

        return None

# Loader


def setup_database(cinfo, code_bin_data):
    # Add base sections.
    add_segment(cinfo.get_text_base(), cinfo.get_text_size(), ".text",
                ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC)
    code_bytes = code_bin_data[:cinfo.get_text_size()]
    ida_bytes.put_bytes(cinfo.get_text_base(), code_bytes)

    if cinfo.has_rodata():
        add_segment(cinfo.get_rodata_base(), cinfo.get_rodata_size(),
                    ".rodata", ida_segment.SEGPERM_READ)
        rel_rodata_base = cinfo.get_rodata_base() - cinfo.get_text_base()
        rodata_bytes = code_bin_data[rel_rodata_base:
                                     rel_rodata_base + cinfo.get_rodata_size()]
        ida_bytes.put_bytes(cinfo.get_rodata_base(), rodata_bytes)

    if cinfo.has_data():
        add_segment(cinfo.get_data_base(), cinfo.get_data_size(),
                    ".data", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)
        rel_data_base = cinfo.get_data_base() - cinfo.get_text_base()
        data_bytes = code_bin_data[rel_data_base:
                                   rel_data_base + cinfo.get_data_size()]
        ida_bytes.put_bytes(cinfo.get_data_base(), data_bytes)

    # Add ioregs.
    # TODO

    # Set entrypoint.
    ida_entry.add_entry(cinfo.get_text_base(),
                        cinfo.get_text_base(), "start", True)

    # Add comments.
    ida_lines.add_extra_line(cinfo.get_text_base(),
                             True, f"; Loaded with {SCRIPT_NAME}")
    ida_lines.add_extra_line(cinfo.get_text_base(), True, f"; {REPO_URL}")
    ida_lines.add_extra_line(cinfo.get_text_base(),
                             True, f"; Name: {cinfo.get_name()}")
    ida_lines.add_extra_line(cinfo.get_text_base(
    ), True, f"; Title ID: {cinfo.get_title_id()}")
    ida_lines.add_extra_line(cinfo.get_text_base(
    ), True, f"; Is compressed? {'Yes' if cinfo.is_code_compressed() else 'No'}")
    ida_lines.add_extra_line(cinfo.get_text_base(
    ), True, f"; Is sysmodule? {'Yes' if cinfo.is_sysmodule() else 'No'}")
    return 1


def load_code_info(f, format):
    # CXI: read from exheader.
    if format == FileFormat.CXI:
        return CodeInfo.load_from_file(f, 0x200)

    # Raw/ExeFS: load from external exheader/user input.
    if format in [FileFormat.Raw, FileFormat.ExeFS]:
        exh_path = ida_kernwin.ask_file(
            False, "exheader.bin", "Choose ExHeader file")
        if exh_path:
            with open(exh_path, "rb") as f:
                return CodeInfo.load_from_file(f, 0)
        else:
            return CodeInfo.load_from_input()

    # Unreachable.
    raise Exception("Invalid format")


def load_code(f, format, cinfo):
    code_bin_data = None

    # CXI: read .code from exefs.
    if format == FileFormat.CXI:
        exefs_off = read_dword(f, 0x1A0) * MEDIA_UNIT
        exefs_size = read_dword(f, 0x1A4) * MEDIA_UNIT
        exefs_bytes = read_bytes(f, exefs_off, exefs_size)
        code_bin_data = extract_code_bin(exefs_bytes)
        if not code_bin_data:
            return 0

    # ExeFS: read .code.
    if format == FileFormat.ExeFS:
        f.seek(0, 2)
        exefs_bytes = read_bytes(f, 0, f.tell())
        code_bin_data = extract_code_bin(exefs_bytes)
        if not code_bin_data:
            return 0

    # Raw: load from file.
    if format == FileFormat.Raw:
        f.seek(0, 2)
        code_bin_data = read_bytes(f, 0, f.tell())

    # Decompress if needed.
    if cinfo.is_code_compressed():
        code_bin_data = blz_decompress(code_bin_data)

    return setup_database(cinfo, code_bin_data)


def accept_file(li, path):
    try:
        format = FileFormat.get_from_file(li)
        if not format:
            format = FileFormat.get_from_path(path)

        if format:
            return {
                "format": f"Nintendo 3DS ARM11 ({format.name})",
                "processor": "ARM",
                "options": 1 | ida_loader.ACCEPT_FIRST,
            }

        return 0
    except:
        return 0


def load_file(f, neflags, format_string):
    format = FileFormat.get_from_format_string(format_string)
    cinfo = load_code_info(f, format)
    return load_code(f, format, cinfo)
