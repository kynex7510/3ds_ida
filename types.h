// Most of these come from libctru: https://github.com/devkitPro/libctru

typedef unsigned char u8;
typedef char s8;
typedef short s16;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;
typedef long long s64;
typedef u32 Handle;
typedef void (*ThreadFunc)(void *);

typedef u32 LightLock;

enum Result {
    SUCCESS = 0,
    GSP_ALREADY_DONE = 0x00002BEB,
    OS_ALREADY_INITIALIZED = 0x08A01BF9,
    SRV_ALREADY_INITIALIZED = 0x08A067F9,
    GSP_BUSY = 0xC8402BF0,
    APT_ALREADY_EXISTS = 0xC8A0CFFC,
    APT_NO_DATA = 0xC8A0CFEF,
    OS_SESSION_CLOSED = 0xC920181A,
    GSP_PERMANENT = 0xD8202A06,
	OS_OUT_OF_MEM = 0xD8601837,
    GSP_INVALID_STATE_516 = 0xD8A02A04,
    GSP_INVALID_STATE_517 = 0xD8A02A05,
    SRV_NOT_INITIALIZED = 0xD8A067F8,
    CFG_INVALID_HANDLE = 0xD8A103F7,
    CFG_ALREADY_INITIALIZED = 0xD8A103F9,
    SVC_QUERY_FAILED = 0xD8A12C08,
    SRV_INVALID_STRING_LENGTH = 0xD9006405,
    SVC_TOO_BIG_ADDR = 0xD9012FF1,
    SVC_TOO_BIG_SIZE = 0xD9012FF2,
    CFG_CANCELLED = 0xD92103FB,
    HID_ALREADY_INITIALIZED = 0xE0A04FF9,
    APT_NOT_INITIALIZED = 0xE0A0CFF8,
    APT_ALREADY_INITIALIZED = 0xE0A0CFF9,
    SVC_ALREADY_INIT = 0xE0A12FF9,
    GSP_NOT_IMPLEMENTED = 0xE0C02BF4,
    SVC_ALIGN_ADDR = 0xE0E01BF1,
    SVC_INVALID_SIZE = 0xE0E01BF2,
    SVC_INVALID_PARAMS = 0xE0E01BF5,
    SVC_INVALID_OPERATION = 0xE0E01BEE,
    GSP_INVALID_ARGUMENT = 0xE0E02A01,
    GSP_INVALID_SELECTION = 0xE0E02BE8,
    GSP_INVALID_SIZE = 0xE0E02BEC,
    GSP_MISALIGNED_SIZE = 0xE0E02BF2,
    GSP_INVALID_ADDRESS = 0xE0E02BF5,
    SVC_INVALID_HANDLE = 0xE1612FF7,
};

struct DmaDeviceConfig {
	s8 deviceId;
	s8 allowedAlignments;
	s16 burstSize;
	s16 transferSize;
	s16 burstStride;
	s16 transferStride;
};

struct DmaConfig {
	s8 channelId;
	s8 endianSwapSize;
	u8 flags;
	u8 _padding;
	DmaDeviceConfig srcCfg;
	DmaDeviceConfig dstCfg;
};

enum MemOp {
    MEMOP_FREE = 1,
    MEMOP_RESERVE = 2,
    MEMOP_ALLOC = 3,
    MEMOP_MAP = 4,
    MEMOP_UNMAP = 5,
    MEMOP_PROT = 6,
    MEMOP_REGION_APP = 0x100,
    MEMOP_REGION_SYSTEM = 0x200,
    MEMOP_REGION_BASE = 0x300,
    MEMOP_OP_MASK = 0xFF,
    MEMOP_REGION_MASK = 0xF00,
    MEMOP_LINEAR_FLAG = 0x10000,
    MEMOP_ALLOC_LINEAR = MEMOP_LINEAR_FLAG | MEMOP_ALLOC,
};

enum MemPerm {
    MEMPERM_READ = 1,
    MEMPERM_WRITE = 2,
    MEMPERM_EXECUTE = 4,
    MEMPERM_READWRITE = MEMPERM_READ | MEMPERM_WRITE,
    MEMPERM_READEXECUTE = MEMPERM_READ | MEMPERM_EXECUTE,
    MEMPERM_DONTCARE = 0x10000000,
};

enum MemState {
    MEMSTATE_FREE       = 0,
    MEMSTATE_RESERVED   = 1,
    MEMSTATE_IO         = 2,
    MEMSTATE_STATIC     = 3,
    MEMSTATE_CODE       = 4,
    MEMSTATE_PRIVATE    = 5,
    MEMSTATE_SHARED     = 6,
    MEMSTATE_CONTINUOUS = 7,
    MEMSTATE_ALIASED    = 8,
    MEMSTATE_ALIAS      = 9,
    MEMSTATE_ALIASCODE  = 10, 
    MEMSTATE_LOCKED     = 11, 
};

struct MemInfo {
    u32 base;
    u32 size;
    MemPerm perm;
    MemState state;
};

struct PageInfo {
    u32 flags;
};

enum ResourceLimitType {
	RESLIMIT_PRIORITY       = 0,
	RESLIMIT_COMMIT         = 1,
	RESLIMIT_THREAD         = 2,
	RESLIMIT_EVENT          = 3,
	RESLIMIT_MUTEX          = 4,
	RESLIMIT_SEMAPHORE      = 5,
	RESLIMIT_TIMER          = 6,
	RESLIMIT_SHAREDMEMORY   = 7,
	RESLIMIT_ADDRESSARBITER = 8,
	RESLIMIT_CPUTIME        = 9,
};

enum UserBreakType {
	USERBREAK_PANIC = 0,
	USERBREAK_ASSERT = 1,
	USERBREAK_USER = 2,
	USERBREAK_LOAD_RO = 3,
	USERBREAK_UNLOAD_RO = 4,
};

enum ArbitrationType {
	ARBITRATION_SIGNAL                                  = 0,
	ARBITRATION_WAIT_IF_LESS_THAN                       = 1,
	ARBITRATION_DECREMENT_AND_WAIT_IF_LESS_THAN         = 2,
	ARBITRATION_WAIT_IF_LESS_THAN_TIMEOUT               = 3,
	ARBITRATION_DECREMENT_AND_WAIT_IF_LESS_THAN_TIMEOUT = 4,
};

struct RecursiveLock
{
  LightLock *lock;
  u32 thread_tag;
  u32 counter;
};

enum EventState
{
  CLEARED_STICKY = 0xFFFFFFFE,
  CLEARED_ONESHOT = 0xFFFFFFFF,
  SIGNALED_ONESHOT = 0x0,
  SIGNALED_STICKY = 0x1,
};

struct LightEvent
{
  EventState state;
  LightLock lock;
};

struct LightSemaphore {
	s32 current_count;
	s16 num_threads_acq;
	s16 max_count;
};

enum ResetType {
	RESET_ONESHOT = 0,
	RESET_STICKY  = 1,
	RESET_PULSE   = 2,
};

enum PerfCounterOperation {
	PERFCOUNTEROP_ENABLE = 0,
	PERFCOUNTEROP_DISABLE = 1,
	PERFCOUNTEROP_GET_VALUE = 2,
	PERFCOUNTEROP_SET_VALUE = 3,
	PERFCOUNTEROP_GET_OVERFLOW_FLAGS = 4,
	PERFCOUNTEROP_RESET = 5,
	PERFCOUNTEROP_GET_EVENT = 6,
	PERFCOUNTEROP_SET_EVENT = 7,
	PERFCOUNTEROP_SET_VIRTUAL_COUNTER_ENABLED = 8,
};

struct AttachProcessEvent {
	u64 program_id;
	char process_name[8];
	u32 process_id;
	u32 other_flags;
};

struct AttachThreadEvent {
	u32 creator_thread_id;
	u32 thread_local_storage;
	u32 entry_point;
};

enum ExitThreadEventReason {
	EXITTHREAD_EVENT_EXIT = 0,
	EXITTHREAD_EVENT_TERMINATE = 1,
	EXITTHREAD_EVENT_EXIT_PROCESS = 2,
	EXITTHREAD_EVENT_TERMINATE_PROCESS = 3,
};

struct ExitThreadEvent {
	ExitThreadEventReason reason;
};

enum ExitProcessEventReason {
	EXITPROCESS_EVENT_EXIT = 0,
	EXITPROCESS_EVENT_TERMINATE = 1,
	EXITPROCESS_EVENT_DEBUG_TERMINATE = 2,
};

struct ExitProcessEvent {
	ExitProcessEventReason reason;
};

struct FaultExceptionEvent {
	u32 fault_information;
};

enum StopPointType {
	STOPPOINT_SVC_FF        = 0,
	STOPPOINT_BREAKPOINT    = 1,
	STOPPOINT_WATCHPOINT    = 2,
};

struct StopPointExceptionEvent {
	StopPointType type;
	u32 fault_information;
};

struct UserBreakExceptionEvent {
	UserBreakType type;
	u32 croInfo;
	u32 croInfoSize;
};

struct DebuggerBreakExceptionEvent {
	s32 thread_ids[4];
};

enum ExceptionEventType {
	EXCEVENT_UNDEFINED_INSTRUCTION = 0,
	EXCEVENT_PREFETCH_ABORT        = 1,
	EXCEVENT_DATA_ABORT            = 2,
	EXCEVENT_UNALIGNED_DATA_ACCESS = 3,
	EXCEVENT_ATTACH_BREAK          = 4,
	EXCEVENT_STOP_POINT            = 5,
	EXCEVENT_USER_BREAK            = 6,
	EXCEVENT_DEBUGGER_BREAK        = 7,
	EXCEVENT_UNDEFINED_SYSCALL     = 8,
};

struct ExceptionEvent {
	ExceptionEventType type;
	u32 address;
	union {
		FaultExceptionEvent fault;
		StopPointExceptionEvent stop_point;
		UserBreakExceptionEvent user_break;
		DebuggerBreakExceptionEvent debugger_break;
	};
};

struct ScheduleInOutEvent {
	u64 clock_tick;
};

struct SyscallInOutEvent {
	u64 clock_tick;
	u32 syscall;
};

struct OutputStringEvent {
	u32 string_addr;
	u32 string_size;
};

struct MapEvent {
	u32 mapped_addr;
	u32 mapped_size;
	MemPerm memperm;
	MemState memstate;
} MapEvent;

enum DebugEventType {
	DBGEVENT_ATTACH_PROCESS = 0,
	DBGEVENT_ATTACH_THREAD  = 1,
	DBGEVENT_EXIT_THREAD    = 2,
	DBGEVENT_EXIT_PROCESS   = 3,
	DBGEVENT_EXCEPTION      = 4,
	DBGEVENT_DLL_LOAD       = 5,
	DBGEVENT_DLL_UNLOAD     = 6,
	DBGEVENT_SCHEDULE_IN    = 7,
	DBGEVENT_SCHEDULE_OUT   = 8,
	DBGEVENT_SYSCALL_IN     = 9,
	DBGEVENT_SYSCALL_OUT    = 10,
	DBGEVENT_OUTPUT_STRING  = 11,
	DBGEVENT_MAP            = 12,
};

struct DebugEventInfo {
	DebugEventType type;
	u32 thread_id;
	u32 flags;
	u8 remnants[4];
	union {
		AttachProcessEvent attach_process;
		AttachThreadEvent attach_thread;
		ExitThreadEvent exit_thread;
		ExitProcessEvent exit_process;
		ExceptionEvent exception;
		ScheduleInOutEvent scheduler;
		SyscallInOutEvent syscall;
		OutputStringEvent output_string;
		MapEvent map;
	};
} DebugEventInfo;

enum DebugFlags {
	DBG_INHIBIT_USER_CPU_EXCEPTION_HANDLERS = 0x01,
	DBG_SIGNAL_FAULT_EXCEPTION_EVENTS = 0x02,
	DBG_SIGNAL_SCHEDULE_EVENTS = 0x04,
	DBG_SIGNAL_SYSCALL_EVENTS = 0x08,
	DBG_SIGNAL_MAP_EVENTS = 0x10,
};

enum DebugThreadParameter {
	DBGTHREAD_PARAMETER_PRIORITY = 0,
	DBGTHREAD_PARAMETER_SCHEDULING_MASK_LOW = 1,
	DBGTHREAD_PARAMETER_CPU_IDEAL = 2,
	DBGTHREAD_PARAMETER_CPU_CREATOR = 3,
};

enum ThreadContextControlFlags {
	THREADCONTEXT_CONTROL_CPU_GPRS  = 0x01,
	THREADCONTEXT_CONTROL_CPU_SPRS  = 0x02,
	THREADCONTEXT_CONTROL_CPU_REGS  = THREADCONTEXT_CONTROL_CPU_GPRS | THREADCONTEXT_CONTROL_CPU_SPRS,

	THREADCONTEXT_CONTROL_FPU_GPRS  = 0x04,
	THREADCONTEXT_CONTROL_FPU_SPRS  = 0x08,
	THREADCONTEXT_CONTROL_FPU_REGS  = THREADCONTEXT_CONTROL_FPU_GPRS | THREADCONTEXT_CONTROL_FPU_SPRS,

	THREADCONTEXT_CONTROL_ALL = THREADCONTEXT_CONTROL_CPU_REGS | THREADCONTEXT_CONTROL_FPU_REGS,
} ThreadContextControlFlags;

struct CpuRegisters {
	u32 r[13];
	u32 sp;
	u32 lr;
	u32 pc;
	u32 cpsr;
};

struct FpuRegisters {
	union {
		struct PACKED { double d[16]; };
		float  s[32];
	};
	u32 fpscr;
	u32 fpexc;
};

struct ThreadContext {
	CpuRegisters cpu_registers;
	FpuRegisters fpu_registers;
};

struct CodeSetHeader {
	u8 name[8];
	u16 version;
	u16 padding[3];
	u32 text_addr;
	u32 text_size;
	u32 ro_addr;
	u32 ro_size;
	u32 rw_addr;
	u32 rw_size;
	u32 text_size_total;
	u32 ro_size_total;
	u32 rw_size_total;
	u32 padding2;
	u64 program_id;
};

struct SvcResult8 {
	Result result; // r0
	u8 value; // r1
};

struct SvcResult32 {
	Result result; // r0
	u32 value; // r1
};

struct SvcResult64 {
	Result result; // r0
	s64 value; // r1-r2
};

struct SvcResultHandle {
	Result result; // r0
	Handle handle; // r1
};

struct SvcResultHandlePair {
	Result result; // r0
	Handle handle1; // r1
	Handle handle2; // r2
};

struct SvcResultQueryMemory {
	Result result; // r0
	MemInfo mem_info; // r1-r4
	PageInfo page_info; // r5
};

struct SvcResultGetDebugThreadParam {
	Result result; // r0
	s64 unused; // r1 - r2
	u32 out; // r3
};