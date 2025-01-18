CREATE TABLE syscalls(
    id INT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    signature VARCHAR(256) NOT NULL
);

CREATE UNIQUE INDEX syscall_names ON syscalls (name);

INSERT INTO syscalls (id, name, signature) VALUES
(0x11, 'ExitProcess', 'void svcExitProcess(void) __attribute__((noreturn));'),
(0x1B, 'CreateThread', 'SvcResultHandle __usercall svcCreateThread@<r0, r1>(s32 threadPriority@<r0>, ThreadFunc entrypoint@<r1>, u32 arg@<r2>, u32* stackTop@<r3>, s32 processorId@<r4>);'),
(0x1E, 'SleepThread', 'void __usercall svcSleepThread(s64 ns@<r0, r1>);'),
(0x25, "SetThreadAffinityMask", 'Result __usercall svcSetThreadAffinityMask@<r0>(Handle thread@<r0>, const u8* affinityMask@<r1>, u32 processorCount@<r2>);'),
(0x2B, 'ConnectToPort', 'SvcResultHandle __usercall svcConnectToPort@<r0, r1>(const char* portName@<r1>);'),
(0x2E, 'SendSyncRequest', 'Result __usercall svcSendSyncRequest@<r0>(Handle session@<r0>);'),
(0x3B, 'CloseHandle', 'Result __usercall svcCloseHandle@<r0>(Handle handle@<r0>);'),
(0x51, 'Break', 'void __usercall svcBreak(UserBreakType breakReason@<r0>) __attribute__((noreturn));'),
(0x5D, 'CreateAddressArbiter', 'SvcResultHandle __usercall svcCreateAddressArbiter@<r0, r1>(void);'),
(0x5E, 'ArbitrateAddress', 'Result __usercall svcArbitrateAddress@<r0>(Handle arbiter@<r0>, u32 addr@<r1>, ArbitrationType type@<r2>, s32 value@<r3>);'),

/* CreateMemoryBlock?*/
(0x1, 'CreateMemoryBlock', 'SvcResultHandle __usercall svcCreateMemoryBlock@<r0, r1>(MemPerm other_perm_alleged@<r0>, u32 addr@<r1>, u32 size@<r2>, MemPerm my_perm_alleged@<r3>);'),

/* GetProcessId?*/
(0x0D, 'GetProcessId', 'SvcResult32 __usercall svcGetProcessId@<r0, r1>(Handle process@<r1>);'),

/* GetThreadIdealProcessor?*/
(0x26, 'GetThreadIdealProcessor', 'SvcResult32 __usercall svcGetThreadIdealProcessor@<r0, r1>(Handle thread@<r1>);'),

/* SetThreadIdealProcessor?*/
(0x27, 'SetThreadIdealProcessor', 'Result __usercall svcSetThreadIdealProcessor@<r0>(Handle thread@<r0>, u32 val@<r1>);'),

/* CreateMutex?*/
(0x34, 'CreateMutex', 'SvcResultHandle __usercall svcCreateMutex@<r0, r1>(bool initiallyLocked@<r1>);'),

/* ReleaseMutex?*/
(0x35, 'ReleaseMutex', 'Result __usercall svcReleaseMutex@<r0>(Handle handle@<r0>);'),

/* GetThreadId?*/
(0x5C, '5C', 'SvcResult32 __usercall svcUnknown5C@<r0, r1>(Handle thread@<r1>);'),

/* ??? */
(0x08, '8', 'Result __usercall svcUnknown8@<r0>(void *unknown0@<r0>, void *unknown1@<r1>);'),
(0x31, '31', 'Result __usercall svcUnknown31@<r0>(void* unknown@<r0>);'),
(0x36, '36', 'Result __usercall svcUnknown36@<r0>(void *unknown0@<r0>);');