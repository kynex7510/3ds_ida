CREATE TABLE syscalls(
    id INT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    signature VARCHAR(256) NOT NULL
);

CREATE UNIQUE INDEX syscall_names ON syscalls (name);

INSERT INTO syscalls (id, name, signature) VALUES
(0x11, 'ExitProcess', 'void svcExitProcess(void) __attribute__((noreturn));'),
(0x1B, 'CreateThread', 'SvcResultHandle __usercall svcCreateThread@<r0, r1>(s32 thread_priority@<r0>, ThreadFunc entrypoint@<r1>, u32 arg@<r2>, u32* stack_top@<r3>, s32 processor_id@<r4>);'),
(0x1E, 'SleepThread', 'void __usercall svcSleepThread(s64 ns@<r0, r1>);'),
(0x2B, 'ConnectToPort', 'SvcResultHandle __usercall svcConnectToPort@<r0, r1>(const char* portName@<r1>);'),
(0x2E, 'SendSyncRequest', 'Result __usercall svcSendSyncRequest@<r0>(Handle session@<r0>);'),
(0x3B, 'CloseHandle', 'Result __usercall svcCloseHandle@<r0>(Handle handle@<r0>);'),
(0x5E, 'ArbitrateAddress', 'Result __usercall svcArbitrateAddress@<r0>(Handle arbiter@<r0>, u32 addr@<r1>, ArbitrationType type@<r2>, s32 value@<r3>);');