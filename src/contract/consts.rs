//! Compile-time constants mirroring `ebpf/common/consts.h`.
//!
//! These drive `#[repr(C)]` struct sizing and BPF map value sizes. Every value
//! here MUST match the C `#define` so the byte layout is identical.

/// Length of the `comm` field. `TASK_COMM_LEN`.
pub const TASK_COMM_LEN: usize = 16;

/// Max filter rules per point. `MAX_FILTER_COUNT`.
pub const MAX_FILTER_COUNT: usize = 6;

/// Max ops in a stack (uprobe) `point_args_t.op_key_list`. `MAX_OP_COUNT`
/// under `-D__MODULE_STACK`.
pub const MAX_OP_COUNT_STACK: usize = 64;

/// Max ops in a syscall `point_args_t.op_key_list`. `MAX_OP_COUNT`
/// under `-D__MODULE_SYSCALL`.
pub const MAX_OP_COUNT_SYSCALL: usize = 256;

/// Default `MAX_OP_COUNT` (perf_mmap / unspecified module).
pub const MAX_OP_COUNT_DEFAULT: usize = 512;

/// Max bytes compared by the kernel string filter. `MAX_STRCMP_LEN`. Bounds
/// `arg_filter_t.str_val` and the user-side validation.
pub const MAX_STRCMP_LEN: usize = 256;

/// Sentinel written as the size of a truncated string-array element. The
/// userspace reader stops iterating when it sees this. `STRARR_MAGIC_LEN`.
pub const STRARR_MAGIC_LEN: u32 = 0xffff_0000;

/// Upper bound on a single `bpf_probe_read_user_str` save. `MAX_STRING_SIZE`.
pub const MAX_STRING_SIZE: usize = 16384;

/// Upper bound on a single buffer/struct read. `MAX_BUF_READ_SIZE`.
pub const MAX_BUF_READ_SIZE: usize = 4096;

/// `ARGS_BUF_SIZE` — the args region of `event_data_t` and thus the max TLV
/// payload following `event_context_t`.
pub const ARGS_BUF_SIZE: usize = 32000;

/// `MAX_PERCPU_BUFSIZE` — the per-CPU scratch buffer size (`buf_t`).
pub const MAX_PERCPU_BUFSIZE: usize = 1 << 15;

/// `_TIF_32BIT` bit in `thread_info.flags`.
pub const _TIF_32BIT: u32 = 1 << 22;

/// arm64 pointer size. (`PTR_SIZE` under `__TARGET_ARCH_arm64`.)
pub const PTR_SIZE: usize = 8;

// ---- `common_list` offset segments (each gets a 0x400-wide key window) ----

pub const SYS_WHITELIST_START: u32 = 0x400;
pub const SYS_BLACKLIST_START: u32 = SYS_WHITELIST_START + 0x400;
pub const UID_WHITELIST_START: u32 = SYS_BLACKLIST_START + 0x400;
pub const UID_BLACKLIST_START: u32 = UID_WHITELIST_START + 0x400;
pub const PID_WHITELIST_START: u32 = UID_BLACKLIST_START + 0x400;
pub const PID_BLACKLIST_START: u32 = PID_WHITELIST_START + 0x400;
pub const TID_WHITELIST_START: u32 = PID_BLACKLIST_START + 0x400;
pub const TID_BLACKLIST_START: u32 = TID_WHITELIST_START + 0x400;

/// `common_list` is one map with a 0x400 stride per (sys/uid/pid/tid ×
/// white/black) segment. This is the width of each segment.
pub const COMMON_LIST_SEGMENT_STRIDE: u32 = 0x400;

/// Map key value for `thread_filter` entries that are whitelist members.
pub const THREAD_NAME_WHITELIST: u32 = 1;
/// Map key value for `thread_filter` entries that are blacklisted.
pub const THREAD_NAME_BLACKLIST: u32 = 2;

/// `common_filter_t.trace_mode` value: only trace configured syscalls.
pub const TRACE_COMMON: u32 = 0;
/// `common_filter_t.trace_mode` value: trace all syscalls.
pub const TRACE_ALL: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_list_segments_are_strided_by_0x400() {
        assert_eq!(SYS_BLACKLIST_START - SYS_WHITELIST_START, 0x400);
        assert_eq!(UID_WHITELIST_START - SYS_BLACKLIST_START, 0x400);
        assert_eq!(UID_BLACKLIST_START - UID_WHITELIST_START, 0x400);
        assert_eq!(PID_WHITELIST_START - UID_BLACKLIST_START, 0x400);
        assert_eq!(PID_BLACKLIST_START - PID_WHITELIST_START, 0x400);
        assert_eq!(TID_WHITELIST_START - PID_BLACKLIST_START, 0x400);
        assert_eq!(TID_BLACKLIST_START - TID_WHITELIST_START, 0x400);
    }

    #[test]
    fn max_op_count_matches_makefile_module_defines() {
        // 64 under __MODULE_STACK, 256 under __MODULE_SYSCALL.
        assert_eq!(MAX_OP_COUNT_STACK, 64);
        assert_eq!(MAX_OP_COUNT_SYSCALL, 256);
        // Derived point_args_t sizes (checked again in struct tests):
        //   stack:   12 + 4*64  = 268
        //   syscall: 12 + 4*256 = 1036
        assert_eq!(12 + 4 * MAX_OP_COUNT_STACK, 268);
        assert_eq!(12 + 4 * MAX_OP_COUNT_SYSCALL, 1036);
    }

    #[test]
    fn strarr_magic_len_is_high_half_set() {
        // The low 16 bits carry the real length when non-truncated.
        assert_eq!(STRARR_MAGIC_LEN & 0xffff_0000, 0xffff_0000);
    }
}
