"""
Utility used by plugins.
- Kynex7510
"""

import capstone

import ida_funcs
import ida_segment
import ida_bytes
import ida_name
import ida_segregs
import ida_idp

# Globals


ARM_DASM = capstone.Cs(capstone.CS_ARCH_ARM,
                       capstone.CS_MODE_ARM + capstone.CS_MODE_LITTLE_ENDIAN)
ARM_DASM.detail = True

THUMB_DASM = capstone.Cs(
    capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB + capstone.CS_MODE_LITTLE_ENDIAN)
THUMB_DASM.detail = True

SYSCALL_NAMES = {
    0x01: "ControlMemory",
    0x02: "QueryMemory",
    0x03: "ExitProcess",
    0x04: "GetProcessAffinityMask",
    0x05: "SetProcessAffinityMask",
    0x06: "GetProcessIdealProcessor",
    0x07: "SetProcessIdealProcessor",
    0x08: "CreateThread",
    0x09: "ExitThread",
    0x0A: "SleepThread",
    0x0B: "GetThreadPriority",
    0x0C: "SetThreadPriority",
    0x0D: "GetThreadAffinityMask",
    0x0E: "SetThreadAffinityMask",
    0x0F: "GetThreadIdealProcessor",
    0x10: "SetThreadIdealProcessor",
    0x11: "GetProcessorId",
    0x12: "Run",
    0x13: "CreateMutex",
    0x14: "ReleaseMutex",
    0x15: "CreateSemaphore",
    0x16: "ReleaseSemaphore",
    0x17: "CreateEvent",
    0x18: "SignalEvent",
    0x19: "ClearEvent",
    0x1A: "CreateTimer",
    0x1B: "SetTimer",
    0x1C: "CancelTimer",
    0x1D: "ClearTimer",
    0x1E: "CreateMemoryBlock",
    0x1F: "MapMemoryBlock",
    0x20: "UnmapMemoryBlock",
    0x21: "CreateAddressArbiter",
    0x22: "ArbitrateAddress",
    0x23: "CloseHandle",
    0x24: "WaitSynchronization",
    0x25: "WaitSynchronizationN",
    0x26: "SignalAndWait",
    0x27: "DuplicateHandle",
    0x28: "GetSystemTick",
    0x29: "GetHandleInfo",
    0x2A: "GetSystemInfo",
    0x2B: "GetProcessInfo",
    0x2C: "GetThreadInfo",
    0x2D: "ConnectToPort",
    0x2E: "SendSyncRequest1",
    0x2F: "SendSyncRequest2",
    0x30: "SendSyncRequest3",
    0x31: "SendSyncRequest4",
    0x32: "SendSyncRequest",
    0x33: "OpenProcess",
    0x34: "OpenThread",
    0x35: "GetProcessId",
    0x36: "GetProcessIdOfThread",
    0x37: "GetThreadId",
    0x38: "GetResourceLimit",
    0x39: "GetResourceLimitLimitValues",
    0x3A: "GetResourceLimitCurrentValues",
    0x3B: "GetThreadContext",
    0x3C: "Break",
    0x3D: "OutputDebugString",
    0x3E: "ControlPerformanceCounter",
    0x47: "CreatePort",
    0x48: "CreateSessionToPort",
    0x49: "CreateSession",
    0x4A: "AcceptSession",
    0x4B: "ReplyAndReceive1",
    0x4C: "ReplyAndReceive2",
    0x4D: "ReplyAndReceive3",
    0x4E: "ReplyAndReceive4",
    0x4F: "ReplyAndReceive",
    0x50: "BindInterrupt",
    0x51: "UnbindInterrupt",
    0x52: "InvalidateProcessDataCache",
    0x53: "StoreProcessDataCache",
    0x54: "FlushProcessDataCache",
    0x55: "StartInterProcessDma",
    0x56: "StopDma",
    0x57: "GetDmaState",
    0x58: "RestartDma",
    0x59: "SetGpuProt",
    0x5A: "SetWifiEnabled",
    0x60: "DebugActiveProcess",
    0x61: "BreakDebugProcess",
    0x62: "TerminateDebugProcess",
    0x63: "GetProcessDebugEvent",
    0x64: "ContinueDebugEvent",
    0x65: "GetProcessList",
    0x66: "GetThreadList",
    0x67: "GetDebugThreadContext",
    0x68: "SetDebugThreadContext",
    0x69: "QueryDebugProcessMemory",
    0x6A: "ReadProcessMemory",
    0x6B: "WriteProcessMemory",
    0x6C: "SetHardwareBreakPoint",
    0x6D: "GetDebugThreadParam",
    0x70: "ControlProcessMemory",
    0x71: "MapProcessMemory",
    0x72: "UnmapProcessMemory",
    0x73: "CreateCodeSet",
    0x75: "CreateProcess",
    0x76: "TerminateProcess",
    0x77: "SetProcessResourceLimits",
    0x78: "CreateResourceLimit",
    0x79: "SetResourceLimitValues",
    0x7A: "AddCodeSegment",
    0x7B: "Backdoor",
    0x7C: "KernelSetState",
    0x7D: "QueryProcessMemory",
}


# Custom return types are defined at the end of types.h.
SYSCALL_TYPES = {
    0x01: "SvcResult32 __usercall svcControlMemory@<r0, r1>(MemOp op@<r0>, u32 addr0@<r1>, u32 addr1@<r2>, u32 size@<r3>, MemPerm perm@<r4>);",
    0x02: "SvcResultQueryMemory __usercall svcQueryMemory@<r0, r1, r2, r3, r4, r5>(MemInfo* info@<r0>, PageInfo* out@<r1>, u32 addr@<r2>);",
    0x03: "void svcExitProcess(void) __attribute__((noreturn));",
    0x04: "Result __usercall svcGetProcessAffinityMask@<r0>(u8* affinitymask@<r0>, Handle process@<r1>, s32 processorcount@<r2);",
    0x05: "Result __usercall svcSetProcessAffinityMask@<r0>(Handle process@<r0>, const u8* affinitymask@<r1>, s32 processorcount@<r2>);",
    0x06: "SvcResult32 __usercall svcGetProcessIdealProcessor@<r0, r1>(Handle process@<r1>);",
    0x07: "Result __usercall svcSetProcessIdealProcessor@<r0>(Handle process@<r0>, s32 processorid@<r1>);",
    0x08: "SvcResultHandle __usercall svcCreateThread@<r0, r1>(s32 thread_priority@<r0>, ThreadFunc entrypoint@<r1>, u32 arg@<r2>, u32* stack_top@<r3>, s32 processor_id@<r4>);",
    0x09: "void svcExitThread(void) __attribute__((noreturn));",
    0x0A: "void __usercall svcSleepThread(s64 ns@<r1, r0>);",
    0x0B: "SvcResult32 __usercall svcGetThreadPriority@<r0, r1>(Handle handle@<r1>);",
    0x0C: "Result __usercall svcSetThreadPriority@<r0>(Handle thread@<r0>, s32 prio@<r1>);",
    0x0D: "Result __usercall svcGetThreadAffinityMask@<r0>(u8* affinitymask@<r0>, Handle thread@<r1>, s32 processorcount@<r2>);",
    0x0E: "Result __usercall svcSetThreadAffinityMask@<r0>(Handle thread@<r0>, const u8* affinitymask@<r1>, s32 processorcount@<r2>);",
    0x0F: "SvcResult32 __usercall svcGetThreadIdealProcessor@<r0, r1>(Handle thread@<r1>);",
    0x10: "Result __usercalL svcSetThreadIdealProcessor@<r0>(Handle thread@<r0>, s32 processorid@<r1>);",
    0x11: "s32 __usercall svcGetProcessorId@<r0>(void);",
    0x12: "Result __usercall svcRun@<r0>(Handle process@<r0>, s32 priority@<r1>, u32 stack_size@<r2>, s32 argc@<r3>, u16* argv@<r4>, u16* envp@<r5>);",
    0x13: "SvcCreateHandleesult __usercall svcCreateMutex@<r0, r1>(bool initially_locked@<r1>);",
    0x14: "Result __usercall svcReleaseMutex@<r0>(Handle handle@<r0>);",
    0x15: "SvcResultHandle __usercall svcCreateSemaphore@<r0, r1>(s32 initial_count@<r1>, s32 max_count@<r2>);",
    0x16: "SvcResult32 __usercall svcReleaseSemaphore@<r0, r1>(Handle semaphore@<r1>, s32 release_count@<r2>);",
    0x17: "SvcResultHandle __usercall svcCreateEvent@<r0, r1>(ResetType reset_type@<r1>);",
    0x18: "Result __usercall svcSignalEvent@<r0>(Handle handle@<r0>);",
    0x19: "Result __usercall svcClearEvent@<r0>(Handle handle@<r0>);",
    0x1A: "SvcResultHandle __usercall svcCreateTimer@<r0, r1>(ResetType reset_type@<r1>);",
    0x1B: "Result __usercall svcSetTimer@<r0>(Handle timer@<r0>, s64 initial@<r3, r1>, s64 interval@<r4, r2>);",
    0x1C: "Result __usercall svcCancelTimer@<r0>(Handle timer@<r0>);",
    0x1D: "Result __usercall svcClearTimer@<r0>(Handle timer@<r0>);",
    0x1E: "SvcResultHandle __usercall svcCreateMemoryBlock@<r0, r1>(MemPerm other_perm@<r0>, u32 addr@<r1>, u32 size@<r2>, MemPerm my_perm@<r3>);",
    0x1F: "Result __usercall svcMapMemoryBlock@<r0>(Handle memblock@<r0>, u32 addr@<r1>, MemPerm my_perm@<r2>, MemPerm other_perm@<r3>);",
    0x20: "Result __usercall svcUnmapMemoryBlock@<r0>(Handle memblock@<r0>, u32 addr@<r1>);",
    0x21: "SvcResultHandle __usercall svcCreateAddressArbiter@<r0, r1>(void);",
    0x22: "Result __usercall svcArbitrateAddress@<r0>(Handle arbiter@<r0>, u32 addr@<r1>, ArbitrationType type@<r2>, s32 value@<r3>, s64 timeout_ns@<r4, r5>);",
    0x23: "Result __usercall svcCloseHandle@<r0>(Handle handle@<r0>);",
    0x24: "Result __usercall svcWaitSynchronization@<r0>(Handle handle@<r0>, s64 nanoseconds@<r2, r3>);",
    0x25: "SvcResult32 __usercall svcWaitSynchronizationN@<r0, r1>(const Handle* handles@<r1>, s32 handles_num@<r2>, bool wait_all@<r3>, s64 nanoseconds@<r0, r4>);",
    0x27: "SvcResultHandle __usercall svcDuplicateHandle@<r0, r1>(Handle original@<r1>);",
    0x28: "u64 __usercall svcGetSystemTick@<r0, r1>(void);",
    0x29: "SvcResult64 __usercall svcGetHandleInfo@<r0, r1, r2>(Handle handle@<r1>, u32 param@<r2>);",
    0x2A: "SvcResult64 __usercall svcGetSystemInfo@<r0, r1, r2>(u32 type@<r1>, s32 param@<r2>);",
    0x2B: "SvcResult64 __usercall svcGetProcessInfo@<r0, r1, r2>(Handle process@<r1>, u32 type@<r2>);",
    0x2C: "SvcResult64 __usercall svcGetThreadInfo@<r0, r1, r2>(Handle thread@<r1>, ThreadInfoType type@<r2>);",
    0x2D: "SvcResultHandle __usercall svcConnectToPort@<r0, r1>(const char* portName@<r1>);",
    0x32: "Result __usercall svcSendSyncRequest@<r0>(Handle session@<r0>);",
    0x33: "SvcResultHandle __usercall svcOpenProcess@<r0, r1>(u32 processId@<r1>);",
    0x34: "SvcResultHandle __usercall svcOpenThread@<r0, r1>(Handle process@<r0>, u32 threadId@<r1>);",
    0x35: "SvcResult32 __usercall svcGetProcessId@<r0, r1>(Handle handle@<r1>);",
    0x36: "SvcResult32 __usercall svcGetProcessIdOfThread@<r0, r1>(Handle handle@<r1>);",
    0x37: "SvcResult32 __usercall svcGetThreadId@<r0, r1>(Handle handle@<r1>);",
    0x38: "SvcResultHandle __usercall svcGetResourceLimit@<r0, r1>(Handle process@<r1>);",
    0x39: "Result __usercall svcGetResourceLimitLimitValues@<r0>(s64* values@<r0>, Handle resourceLimit@<r1>, ResourceLimitType* names@<r2>, s32 nameCount@<r3>);",
    0x3A: "Result __usercall svcGetResourceLimitCurrentValues@<r0>(s64* values@<r0>, Handle resourceLimit@<r1>, ResourceLimitType* names@<r2>, s32 nameCount@<r3>);",
    0x3C: "void __usercall svcBreak(UserBreakType breakReason@<r0>) __attribute__((noreturn));",
    0x3D: "Result __usercall svcOutputDebugString@<r0>(const char* str@<r0>, s32 length@<r1>);",
    0x3E: "SvcResult64 __usercall svcControlPerformanceCounter@<r0, r2, r1>(PerfCounterOperation op@<r1>, u32 param1@<r2>, u64 param2@<r3, r0>);",
    0x47: "SvcResultHandlePair __usercall svcCreatePort@<r0, r1, r2>(const char* name@<r2>, s32 maxSessions@<r3>);",
    0x48: "SvcResultHandle __usercall svcCreateSessionToPort@<r0, r1>(Handle clientPort@<r1>);",
    0x49: "SvcResultHandlePair __usercall svcCreateSession@<r0, r1, r2>(void);",
    0x4A: "SvcResultHandle __usercall svcAcceptSession@<r0, r1>(Handle port@<r1>);",
    0x4F: "SvcResult32 __usercall svcReplyAndReceive@<r0, r1>(const Handle* handles@<r1>, s32 handleCount@<r2>, Handle replyTarget@<r3>);",
    0x50: "Result __usercall svcBindInterrupt@<r0>(u32 interruptId@<r0>, Handle eventOrSemaphore@<r1>, s32 priority@<r2>, bool isManualClear@<r3>);",
    0x51: "Result __usercall svcUnbindInterrupt@<r0>(u32 interruptId@<r0>, Handle eventOrSemaphore@<r1>);",
    0x52: "Result __usercall svcInvalidateProcessDataCache@<r0>(Handle process@<r0>, u32 addr@<r1>, u32 size@<r2>);",
    0x53: "Result __usercall svcStoreProcessDataCache@<r0>(Handle process@<r0>, u32 addr@<r1>, u32 size@<r2>);",
    0x54: "Result __usercall svcFlushProcessDataCache@<r0>(Handle process@<r0>, u32 addr@<r1>, u32 size@<r2>);",
    0x55: "SvcResultHandle __usercall svcStartInterProcessDma@<r0, r1>(u32 srcAddr@<r0>, Handle dstProcess@<r1>, u32 dstAddr@<r2>, Handle srcProcess@<r3>, u32 size@<r4>, const DmaConfig *cfg@<r5>);",
    0x56: "Result __usercall svcStopDma@<r0>(Handle dma@<r0>);",
    0x57: "SvcResult8 __usercall svcGetDmaState@<r0, r1>(Handle dma@<r1>);",
    0x58: "Result __usercall svcRestartDma@<r0>(Handle dma@<r0>, u32 dstAddr@<r1>, u32 srcAddr@<r2>, u32 size@<r3>, s8 flags@<r4>);",
    0x59: "Result __usercall svcSetGpuProt@<r0>(bool useApplicationRestriction@<r0>);",
    0x5A: "Result __usercall svcSetWifiEnabled@<r0>(bool enabled@<r0>);",
    0x60: "SvcResultHandle __usercall svcDebugActiveProcess@<r0, r1>(u32 processId@<r1>);",
    0x61: "Result __usercall svcBreakDebugProcess@<r0>(Handle debug@<r0>);",
    0x62: "Result __usercall svcTerminateDebugProcess@<r0>(Handle debug@<r0>);",
    0x63: "Result __usercall svcGetProcessDebugEvent@<r0>(DebugEventInfo* info@<r0>, Handle debug@<r1>);",
    0x64: "Result __usercall svcContinueDebugEvent@<r0>(Handle debug@<r0>, DebugFlags flags@<r1>);",
    0x65: "SvcResult32 __usercall svcGetProcessList@<r0, r1>(s32 processIdMaxCount@<r2>);",
    0x66: "SvcResult32 __usercall svcGetThreadList@<r0, r1>(s32 threadIdMaxCount@<r2>, Handle process@<r3>);",
    0x67: "Result __usercall svcGetDebugThreadContext@<r0>(ThreadContext* context@<r0>, Handle debug@<r1>, u32 threadId@<r2>, ThreadContextControlFlags controlFlags@<r3>);",
    0x68: "Result __usercall svcSetDebugThreadContext@<r0>(Handle debug@<r0>, u32 threadId@<r1>, ThreadContext* context@<r2>, ThreadContextControlFlags controlFlags@<r3>);",
    0x69: "SvcResultQueryMemory __usercall svcQueryDebugProcessMemory@<r0, r1, r2, r3, r4, r5>(Handle debug@<r2>, u32 addr@<r3>);",
    0x6A: "Result __usercall svcReadProcessMemory@<r0>(void* buffer@<r0>, Handle debug@<r1>, u32 addr@<r2>, u32 size@<r3>);",
    0x6B: "Result __usercall svcWriteProcessMemory@<r0>(Handle debug@<r0>, const void* buffer@<r1>, u32 addr@<r2>, u32 size@<r3>);",
    0x6C: "Result __usercall svcSetHardwareBreakPoint@<r0>(s32 registerId@<r0>, u32 control@<r1>, u32 value@<r2>);",
    0x6D: "SvcResultGetDebugThreadParam __usercall svcGetDebugThreadParam@<r0, r2, r1, r3>(u32* out@<r1>, Handle debug@<r2>, u32 threadId@<r3>, DebugThreadParameter parameter@<r0>);",
    0x70: "Result __usercall svcControlProcessMemory@<r0>(Handle process@<r0>, u32 addr0@<r1>, u32 addr1@<r2>, u32 size@<r3>, u32 type@<r4>, u32 perm@<r5>);",
    0x71: "Result __usercall svcMapProcessMemory@<r0>(Handle process@<r0>, u32 destAddress@<r1>, u32 size@<r2>);",
    0x72: "Result __usercall svcUnmapProcessMemory@<r0>(Handle process@<r0>, u32 destAddress@<r1>, u32 size@<r2>);",
    0x73: "SvcResultHandle __usercall svcCreateCodeSet@<r0, r1>(u32 dataSegmentLma@<r0>, const CodeSetHeader* info@<r1>, u32 textSegmentLma@<r2>, u32 roSegmentLma@<r3>);",
    0x75: "SvcResultHandle __usercall svcCreateProcess@<r0, r1>(Handle codeset@<r1>, const u32* arm11KernelCaps@<r2>, s32 numArm11KernelCaps@<r3>);",
    0x76: "Result __usercall svcTerminateProcess@<r0>(Handle process@<r0>);",
    0x77: "Result __usercall svcSetProcessResourceLimits@<r0>(Handle process@<r0>, Handle resourceLimit@<r1>);",
    0x78: "SvcResultHandle __usercall svcCreateResourceLimit@<r0, r1>(void);",
    0x79: "Result __usercall svcSetResourceLimitValues@<r0>(Handle resourceLimit@<r0>, const ResourceLimitType* names@<r1>, const s64* values@<r2>, s32 nameCount@<r3>);",
    0x7B: "Result __usercall svcBackdoor@<r0>(s32 (*callback)(void)@<r0>);",
    0x7C: "Result __usercall svcKernelSetState@<r0>(u32 type@<r0>, ...);",
    0x7D: "SvcResultQueryMemory __usercall svcQueryProcessMemory@<r0, r1, r2, r3, r4, r5>(Handle process@<r2>, u32 addr@<r3>);",
}

# Helpers


def _is_thumb(addr):
    return ida_segregs.get_sreg(addr, ida_idp.str2reg("T")) == 1

# Utility


"""
Log to console.
"""


def log(plugin_name, message):
    print(f"[{plugin_name}] {message}")


"""
Set name at address.
"""


def rename(addr, name):
    ida_name.set_name(addr, name, 0)


"""
Get segment base by name.
Return 0 on failure.
"""


def get_segment_base(name):
    segm = ida_segment.get_segm_by_name(name)
    if segm:
        linear = ida_segment.get_segm_base(segm)
        return segm.start_ea - linear
    return 0


"""
Get function bytes.
Return None on failure.
"""


def get_func_bytes(func: ida_funcs.func_t):
    return ida_bytes.get_bytes(func.start_ea, func.end_ea - func.start_ea)


"""
Find every syscall in a function.
Returns address + syscall id.
"""


def get_func_syscalls(func_addr, func_bytes):
    result = {}
    dasm = THUMB_DASM if _is_thumb(func_addr) else ARM_DASM
    for insn in dasm.disasm(func_bytes, func_addr):
        if insn.id == capstone.arm.ARM_INS_SVC:
            id = insn.operands[0].value.imm
            result[insn.address] = id
    return result
