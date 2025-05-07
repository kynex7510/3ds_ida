"""
Utilities used by loaders.
- Kynex7510
"""

import enum
from pathlib import Path

import ida_segment
import ida_kernwin
import ida_loader

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
    elif name == ".bss":
        sclass = "BSS"
    else:
        sclass = "DATA"
    if not ida_segment.add_segm(0, start, start + size, name, sclass):
        raise Exception(f"Could not add segment {name}")
    seg = ida_segment.get_segm_by_name(name)
    ida_segment.set_segm_addressing(seg, 1)
    seg.perm = perms

# FileFormat

class FileFormat(enum.Enum):
    Raw = 0
    ExeFS = 1
    CXI = 2
    CIA = 3
    CRO = 4

    @staticmethod
    def get_from_file(f):
        # Check for CXI.
        try:
            ncch_magic = read_string(f, 0x100, 4)
            crypto_method = read_bytes(f, 0x18B, 1)[0]
            content_type = read_bytes(f, 0x18D, 1)[0]
            if ncch_magic == "NCCH" and (content_type & 0x02):
                # Warn user about encryption.
                if crypto_method != 0x00:
                    ida_kernwin.warning("Encrypted CXI file detected. Please decrypt it before loading it.")
                else:
                    return FileFormat.CXI
        except:
            pass

        # Check for CRO.
        try:
            if read_string(f, 0x80, 4) == "CRO0":
                return FileFormat.CRO
        except:
            pass

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
    def get_from_format_string(format_string):
        for i in range(len(FileFormat)):
            if format_string.find(FileFormat(i).name) != -1:
                return FileFormat(i)

        return None
    
def get_accept_file_result(format):
    if format:
        return {
                "format": f"Nintendo 3DS ({format.name})",
                "processor": "ARM",
                "options": 1 | ida_loader.ACCEPT_FIRST,
            }
    
    return 0