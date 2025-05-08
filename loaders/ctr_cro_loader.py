"""
Nintendo 3DS CRO loader.
- Kynex7510
"""

import ctr_utility
from ctr_utility import FileFormat

import ida_ida
import ida_segment

import ida_lines
import ida_bytes

SCRIPT_NAME = "ctr_cro_loader.py"
REPO_URL = "https://github.com/kynex7510/3ds_ida"

# CROInfo

SEGMENT_TEXT = 0
SEGMENT_RODATA = 1
SEGMENT_DATA = 2
SEGMENT_BSS = 3

class Segment:
    def __init__(self, id, offset, data_size, base, size):
        self._id = id
        self._offset = offset
        self._data_size = data_size
        self._base = base
        self._size = size

    def id(self):
        return self._id
    
    def offset(self):
        return self._offset
    
    def data_size(self):
        return self._data_size
    
    def base(self):
        return self._base

    def size(self):
        return self._size

    def get_setup_info(self):
        if self._id == SEGMENT_TEXT:
            return (".text", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC)
        
        if self._id == SEGMENT_RODATA:
            return (".rodata", ida_segment.SEGPERM_READ)
        
        if self._id == SEGMENT_DATA:
            return (".data", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)
        
        if self._id == SEGMENT_BSS:
            return (".bss", ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)
        
        raise Exception(f"Unknown segment ID: {self._id}")

class CROInfo:
    def __init__(self):
        self._name = "(UNKNOWN)"
        self._module_name = "(UNKNOWN)"
        self._segments = []

    @staticmethod
    def load_from_file(f):
        cinfo = CROInfo()

        # Read name.
        name_offset = ctr_utility.read_dword(f, 0x84)
        cinfo._name = ctr_utility.read_cstring(f, name_offset, 16)

        # Read module name.
        module_name_offset = ctr_utility.read_dword(f, 0xC0)
        module_name_size = ctr_utility.read_dword(f, 0xC4)
        cinfo._module_name = ctr_utility.read_string(f, module_name_offset, module_name_size)

        # Read segments.
        segtable_offset = ctr_utility.read_dword(f, 0xC8)
        num_segments = ctr_utility.read_dword(f, 0xCC)

        # Calculate .data base.
        data_base = 0xFFFFFFFF
       
        for i in range(num_segments):
            seg_offset = ctr_utility.read_dword(f, segtable_offset + (0xC * i))
            seg_id = ctr_utility.read_dword(f, segtable_offset + (0xC * i) + 8)

            if seg_id == SEGMENT_DATA:
                data_base = seg_offset
                break

        # Calculate bases and sizes.
        # - .data size is read from CRO, aligned at 4 bytes;
        # - .bss base is .data base + .data size;
        # - .bss size is read from CRO.
        raw_data_size = ctr_utility.read_dword(f, 0xBC)
        data_size = ctr_utility.align_up(raw_data_size, 4)

        bss_base = data_base + data_size
        bss_size = ctr_utility.read_dword(f, 0x94)

        # Load segments.
        for i in range(num_segments):
            seg_offset = ctr_utility.read_dword(f, segtable_offset + (0xC * i))
            seg_data_size = ctr_utility.read_dword(f, segtable_offset + (0xC * i) + 4)
            seg_id = ctr_utility.read_dword(f, segtable_offset + (0xC * i) + 8)

            seg_base = seg_offset
            seg_size = seg_data_size
            if seg_id == SEGMENT_DATA:
                seg_base = data_base
                seg_size = data_size
            elif seg_id == SEGMENT_BSS:
                assert data_base != 0xFFFFFFFF
                seg_base = bss_base
                seg_size = bss_size

            seg = Segment(seg_id, seg_offset, seg_data_size, seg_base, seg_size)
            cinfo._segments.append(seg)

        return cinfo

    def name(self):
        return self._name
    
    def module_name(self):
        return self._module_name

    def segments(self):
        return self._segments
    
    def base(self):
        base = 0xFFFFFFFF
        for seg in self.segments():
            if seg.size() != 0 and seg.base() < base:
                base = seg.base()

        return base

# Loader

def load_cro(f, cinfo):
    # Setup segments.
    for seg in cinfo.segments():
        if seg.size() == 0:
            continue

        name, perms = seg.get_setup_info()
        ctr_utility.add_segment(seg.base(), seg.size(), name, perms)

        if seg.offset() != 0:
            seg_bytes = ctr_utility.read_bytes(f, seg.offset(), seg.data_size())
            ida_bytes.put_bytes(seg.base(), seg_bytes)

    return True

def accept_file(f, path):
    format = FileFormat.get_from_file(f)

    # This script is for CRO only.
    if format == FileFormat.CRO:
        return ctr_utility.get_accept_file_result(format)
    
    return 0

def load_file(f, neflags, format_string):
    cinfo = CROInfo.load_from_file(f)

    if load_cro(f, cinfo):
        ida_ida.idainfo_set_64bit(False)
        ida_lines.add_extra_line(cinfo.base(), True, f"; Loaded with {SCRIPT_NAME}")
        ida_lines.add_extra_line(cinfo.base(), True, f"; {REPO_URL}")
        ida_lines.add_extra_line(cinfo.base(), True, f"; Name: {cinfo.name()}")
        ida_lines.add_extra_line(cinfo.base(), True, f"; Module name: {cinfo.module_name()}")

        return 1

    return 0