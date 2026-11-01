#ifndef __STACKPLZ_CONSTS_H__
#define __STACKPLZ_CONSTS_H__

#define TASK_COMM_LEN 16
#define MAX_COUNT 20
#define MAX_FILTER_COUNT 6
#define MAX_PATH_COMPONENTS   48
#define MAX_LOOP_COUNT 32
#define MAX_STRCMP_LEN 256
#define STRARR_MAGIC_LEN 0xffff0000

#if defined(__MODULE_STACK)
    #define MAX_OP_COUNT 64
#elif defined(__MODULE_SYSCALL)
    #define MAX_OP_COUNT 256
#else
    #define MAX_OP_COUNT 512
#endif

// arch/arm64/include/asm/thread_info.h
#define _TIF_32BIT       (1 << 22)

#if defined(__TARGET_ARCH_arm)
    #define PTR_SIZE 4
#else
    #define PTR_SIZE 8
#endif

// clang-format off
#define MAX_PERCPU_BUFSIZE (1 << 15)  // set by the kernel as an upper bound
#define PATH_MAX    4096
#define MAX_STRING_SIZE    16384
#define MAX_BYTES_ARR_SIZE    4096       // same as PATH_MAX
#define MAX_BUF_READ_SIZE    4096
#define ARGS_BUF_SIZE       32000

// 配合 common_list 使用的 8 段 key 偏移
// 每段的宽度 = COMMON_LIST_SEGMENT_STRIDE，必须大于该段可能出现的最大值，
// 否则 key 会跨段碰撞（例如 PID_WHITELIST_START+pid 撞上 TID_WHITELIST_START+tid，
// 造成误放行 / 误丢弃）。原实现用 0x400(1024)，而 Android 上 pid/tid 常态 > 1024、
// uid 常 > 10000，必然碰撞。
// 现取 0x400000(4194304) = Linux PID_MAX_LIMIT：pid/tid 全部取值都落在本段内，
// uid 实际取值(<~200000)亦然。common_list 是哈希表(BPF_HASH)，key 空间稀疏不占内存，
// 因此加宽段宽不增加 map 体积；总条目上限仍是 1024。
#define COMMON_LIST_SEGMENT_STRIDE 0x400000
#define SYS_WHITELIST_START (COMMON_LIST_SEGMENT_STRIDE)
#define SYS_BLACKLIST_START (SYS_WHITELIST_START + COMMON_LIST_SEGMENT_STRIDE)
#define UID_WHITELIST_START (SYS_BLACKLIST_START + COMMON_LIST_SEGMENT_STRIDE)
#define UID_BLACKLIST_START (UID_WHITELIST_START + COMMON_LIST_SEGMENT_STRIDE)
#define PID_WHITELIST_START (UID_BLACKLIST_START + COMMON_LIST_SEGMENT_STRIDE)
#define PID_BLACKLIST_START (PID_WHITELIST_START + COMMON_LIST_SEGMENT_STRIDE)
#define TID_WHITELIST_START (PID_BLACKLIST_START + COMMON_LIST_SEGMENT_STRIDE)
#define TID_BLACKLIST_START (TID_WHITELIST_START + COMMON_LIST_SEGMENT_STRIDE)

#define THREAD_NAME_WHITELIST 1
#define THREAD_NAME_BLACKLIST 2

#define TRACE_COMMON 0
#define TRACE_ALL 1

enum buf_idx_e
{
    STRING_BUF_IDX,
    ZERO_BUF_IDX,
    MAX_BUFFERS
};


#endif // __STACKPLZ_CONSTS_H__
