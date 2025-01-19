CREATE TABLE syscalls(
    id INT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    signature VARCHAR(256) NOT NULL
);

CREATE UNIQUE INDEX syscall_names ON syscalls (name);

INSERT INTO syscalls (id, name, signature) VALUES
(0x01, 'ControlMemory', 'SvcResult32 __usercall svcControlMemory@<r0, r1>(MemPerm perm@<r0>, u32 addr@<r1>, u32 size@<r2>, MemOp op@<r3>);'),
(0x06, 'CreateMemoryBlock', 'SvcResultHandle __usercall svcCreateMemoryBlock@<r0, r1>(MemPerm otherPerm@<r0>, u32 addr@<r1>, u32 size@<r2>, MemPerm myPerm@<r3>);'),
(0x07, 'MapMemoryBlock', 'Result __usercall svcMapMemoryBlock@<r0>(Handle block@<r0>, u32 addr@<r1>, MemPerm perm@<r2>);'),
(0x08, 'UnmapMemoryBlock', 'Result __usercall svcUnmapMemoryBlock@<r0>(Handle block@<r0>, u32 addr@<r1>);'),
(0x0D, 'GetResourceLimit', 'SvcResultHandle __usercall svcGetResourceLimit@<r0, r1>(Handle process@<r1>);'),
(0x11, 'ExitProcess', 'void svcExitProcess(void) __attribute__((noreturn));'),
(0x1B, 'CreateThread', 'SvcResultHandle __usercall svcCreateThread@<r0, r1>(s32 threadPriority@<r0>, ThreadFunc entrypoint@<r1>, u32 arg@<r2>, u32* stackTop@<r3>, s32 processorId@<r4>);'),
(0x1D, 'ExitThread', 'void svcExitThread(void) __attribute__((noreturn));'),
(0x1E, 'SleepThread', 'void __usercall svcSleepThread(s64 ns@<r0, r1>);'),
(0x25, "SetThreadAffinityMask", 'Result __usercall svcSetThreadAffinityMask@<r0>(Handle thread@<r0>, const u8* affinityMask@<r1>, u32 processorCount@<r2>);'),
(0x26, 'GetThreadIdealProcessor', 'SvcResult32 __usercall svcGetThreadIdealProcessor@<r0, r1>(Handle thread@<r1>);'),
(0x27, 'SetThreadIdealProcessor', 'Result __usercall svcSetThreadIdealProcessor@<r0>(Handle thread@<r0>, s32 processorId@<r1>);'),
(0x2B, 'ConnectToPort', 'SvcResultHandle __usercall svcConnectToPort@<r0, r1>(const char* portName@<r1>);'),
(0x2E, 'SendSyncRequest', 'Result __usercall svcSendSyncRequest@<r0>(Handle session@<r0>);'),
(0x30, 'CreateMutex', 'SvcResultHandle __usercall svcCreateMutex@<r0, r1>(bool initiallyLocked@<r1>);'),
(0x31, 'ReleaseMutex', 'Result __usercall svcReleaseMutex@<r0>(Handle mutex@<r0>);'),
(0x34, 'CreateEvent', 'SvcResultHandle __usercall svcCreateEvent@<r0, r1>(ResetType resetType@<r1>);'),
(0x35, 'SignalEvent', 'Result __usercall svcSignalEvent@<r0>(Handle event@<r0>);'),
(0x36, 'ClearEvent', 'Result __usercall svcClearEvent@<r0>(Handle event@<r0>);'),
(0x3B, 'CloseHandle', 'Result __usercall svcCloseHandle@<r0>(Handle handle@<r0>);'),
(0x3C, 'WaitSynchronizationN', 'SvcResult32 __usercall svcWaitSynchronizationN@<r0, r1>(const Handle* handles@<r1>, s32 numHandles@<r2>, bool waitAll@<r3>, s64 nanoseconds@<r0, r4>);'),
(0x3D, 'GetSystemTick', 'u64 __usercall svcGetSystemTick@<r0, r1>(void);'),
(0x51, 'Break', 'void __usercall svcBreak(UserBreakType breakReason@<r0>) __attribute__((noreturn));'),
(0x52, 'OutputDebugString', 'Result __usercall svcOutputDebugString@<r0>(const char* str@<r0>, s32 length@<r1>);'),
(0x5C, 'DuplicateHandle', 'SvcResultHandle __usercall svcDuplicateHandle@<r0, r1>(Handle thread@<r1>);'),
(0x5D, 'CreateAddressArbiter', 'SvcResultHandle __usercall svcCreateAddressArbiter@<r0, r1>(void);'),
(0x5E, 'ArbitrateAddress', 'Result __usercall svcArbitrateAddress@<r0>(Handle arbiter@<r0>, u32 addr@<r1>, ArbitrationType type@<r2>, s32 value@<r3>);');