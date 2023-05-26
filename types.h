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
    OS_OUT_OF_MEM = 0xD8601837,
    GSP_BUSY = 0xC8402BF0,
    APT_ALREADY_EXISTS = 0xC8A0CFFC,
    APT_NO_DATA = 0xC8A0CFEF,
    OS_SESSION_CLOSED = 0xC920181A,
    GSP_PERMANENT = 0xD8202A06,
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

typedef u8 APT_AppletAttr;

enum NS_APPID {
	APPID_NONE = 0,
	APPID_HOMEMENU = 0x101,
	APPID_CAMERA = 0x110,
	APPID_FRIENDS_LIST = 0x112,
	APPID_GAME_NOTES = 0x113,
	APPID_WEB = 0x114,
	APPID_INSTRUCTION_MANUAL = 0x115,
	APPID_NOTIFICATIONS = 0x116,
	APPID_MIIVERSE = 0x117,
	APPID_MIIVERSE_POSTING = 0x118,
	APPID_AMIIBO_SETTINGS = 0x119,
	APPID_APPLICATION = 0x300,
	APPID_ESHOP = 0x301,
	APPID_SOFTWARE_KEYBOARD = 0x401,
	APPID_APPLETED = 0x402,
	APPID_PNOTE_AP = 0x404,
	APPID_SNOTE_AP = 0x405,
	APPID_ERROR = 0x406,
	APPID_MINT = 0x407,
	APPID_EXTRAPAD = 0x408,
	APPID_MEMOLIB = 0x409,
};

enum APT_AppletPos {
	APTPOS_NONE     = -1,
	APTPOS_APP      = 0,
	APTPOS_APPLIB   = 1,
	APTPOS_SYS      = 2,
	APTPOS_SYSLIB   = 3,
	APTPOS_RESIDENT = 4,
};