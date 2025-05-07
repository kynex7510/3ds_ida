"""
Utility used by plugins.
- Kynex7510
"""

import capstone
import sqlite3

import ida_funcs
import ida_segment
import ida_bytes
import ida_name
import ida_segregs
import ida_idp
import ida_kernwin

class IDAUtils:
    @staticmethod
    def is_thumb(addr: int) -> bool:
        return ida_segregs.get_sreg(addr, ida_idp.str2reg("T")) == 1
    
    @staticmethod
    def set_name(addr, name):
        ida_name.set_name(addr, name, ida_name.SN_FORCE)

    @staticmethod
    def get_segment_base(name):
        segm = ida_segment.get_segm_by_name(name)
        if segm:
            linear = ida_segment.get_segm_base(segm)
            return segm.start_ea - linear
        return 0
    
    @staticmethod
    def get_segment_size(name):
        segm = ida_segment.get_segm_by_name(name)
        if segm:
            return segm.end_ea - segm.start_ea
        return 0
    
    @staticmethod
    def get_func_bytes(func: ida_funcs.func_t):
        return ida_bytes.get_bytes(func.start_ea, func.end_ea - func.start_ea)
    
    @staticmethod
    def ask_question(question: str) -> bool:
        return ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, question) == ida_kernwin.ASKBTN_YES
    
    @staticmethod
    def ask_file(save: bool, prompt: str, default: str) -> str:
        return ida_kernwin.ask_file(save, default, prompt)

    @staticmethod
    def file_size() -> int:
        seg_sizes = [
            IDAUtils.get_segment_size(".text"),
            IDAUtils.get_segment_size(".rodata"),
            IDAUtils.get_segment_size(".data")
        ]

        size = 0
        for s in seg_sizes:
            size += s
        
        assert size != 0
        return size
    
    @staticmethod
    def map_size() -> int:
        return IDAUtils.file_size() + IDAUtils.get_segment_size(".bss")
    
    @staticmethod
    def map_base() -> int:
        seg_bases = [
            IDAUtils.get_segment_base(".text"),
            IDAUtils.get_segment_base(".rodata"),
            IDAUtils.get_segment_base(".data"),
            IDAUtils.get_segment_base(".bss"),
        ]

        base = 0xFFFFFFFF
        for b in seg_bases:
            if b == 0:
                continue

            if b < base:
                base = b

        assert base != 0
        return base

class Logger:
    def __init__(self, plugin_name: str) -> None:
        self.plugin_name = plugin_name

    def log(self, message: str) -> None:
        print(f"[{self.plugin_name}] {message}")

class Disassembler:
    def __init__(self) -> None:
        self._dasm_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM + capstone.CS_MODE_LITTLE_ENDIAN)
        self._dasm_arm.detail = True
        self._dasm_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB + capstone.CS_MODE_LITTLE_ENDIAN)
        self._dasm_thumb.detail = True
        return None

    def dasm(self, data: bytes, addr: int):
        d = self._dasm_thumb if IDAUtils.is_thumb(addr) else self._dasm_arm
        return d.disasm(data, addr)
    
    def is_syscall(self, insn: capstone.CsInsn) -> bool:
        return insn.id == capstone.arm.ARM_INS_SVC

class Syscall:
    def __init__(self, id: int, name: str, signature: str) -> None:
        self._id = id
        self._name = name
        self._signature = signature
        return None
    
    def __eq__(self, other) -> bool:
        if isinstance(other, Syscall):
            return self._id == other._id

        return False
    
    def id(self) -> int:
        return self._id
    
    def name(self) -> str:
        return self._name
    
    def signature(self) -> str:
        return self._signature

class SyscallDB:
    def __init__(self) -> None:
        with open(IDAUtils.ask_file(False, "Select a schema file for syscalls", "schema.sql"), "r") as schema:
            self._sql = sqlite3.connect(":memory:")
            self._sql.cursor().executescript(schema.read())
            self._sql.commit()
        return None
    
    def _get_result(self, c: sqlite3.Cursor) -> Syscall | None:
        t: tuple = c.fetchone()
        if t:
            return Syscall(id=t[0], name=t[1], signature=t[2])

        return None

    def get_by_id(self, id: int) -> Syscall | None:
        c = self._sql.cursor()
        c.execute("SELECT * FROM syscalls WHERE id = ?;", (id, ))
        return self._get_result(c)
    
    def get_by_name(self, name: str) -> Syscall | None:
        c = self._sql.cursor()
        c.execute("SELECT * FROM syscalls WHERE name = ?;", (name, ))
        return self._get_result(c)