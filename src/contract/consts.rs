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

// ---- `common_list` offset segments (each gets a stride-wide key window) ----

/// Width of each `common_list` key segment. Must exceed the largest value that
/// can appear in that segment, otherwise keys collide across segments (e.g.
/// `PID_WHITELIST_START + pid` colliding with `TID_WHITELIST_START + tid`).
/// The old `0x400` was far too small: Android pids/tids routinely exceed 1024
/// and uids exceed 10000, so keys crossed into the neighbouring segment.
/// `0x400000` (equal to Linux `PID_MAX_LIMIT`) covers every pid/tid value and
/// every realistic uid. `common_list` is a BPF hash map, so a sparse key space
/// costs no memory; the entry cap stays at 1024.
pub const COMMON_LIST_SEGMENT_STRIDE: u32 = 0x400000;

pub const SYS_WHITELIST_START: u32 = COMMON_LIST_SEGMENT_STRIDE;
pub const SYS_BLACKLIST_START: u32 = SYS_WHITELIST_START + COMMON_LIST_SEGMENT_STRIDE;
pub const UID_WHITELIST_START: u32 = SYS_BLACKLIST_START + COMMON_LIST_SEGMENT_STRIDE;
pub const UID_BLACKLIST_START: u32 = UID_WHITELIST_START + COMMON_LIST_SEGMENT_STRIDE;
pub const PID_WHITELIST_START: u32 = UID_BLACKLIST_START + COMMON_LIST_SEGMENT_STRIDE;
pub const PID_BLACKLIST_START: u32 = PID_WHITELIST_START + COMMON_LIST_SEGMENT_STRIDE;
pub const TID_WHITELIST_START: u32 = PID_BLACKLIST_START + COMMON_LIST_SEGMENT_STRIDE;
pub const TID_BLACKLIST_START: u32 = TID_WHITELIST_START + COMMON_LIST_SEGMENT_STRIDE;

/// Highest key any segment can reach. Must stay inside `u32`.
pub const COMMON_LIST_MAX_KEY: u32 = TID_BLACKLIST_START + COMMON_LIST_SEGMENT_STRIDE;

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
    fn common_list_segments_are_strided_by_segment_stride() {
        assert_eq!(
            SYS_BLACKLIST_START - SYS_WHITELIST_START,
            COMMON_LIST_SEGMENT_STRIDE
        );
        assert_eq!(
            UID_WHITELIST_START - SYS_BLACKLIST_START,
            COMMON_LIST_SEGMENT_STRIDE
        );
        assert_eq!(
            UID_BLACKLIST_START - UID_WHITELIST_START,
            COMMON_LIST_SEGMENT_STRIDE
        );
        assert_eq!(
            PID_WHITELIST_START - UID_BLACKLIST_START,
            COMMON_LIST_SEGMENT_STRIDE
        );
        assert_eq!(
            PID_BLACKLIST_START - PID_WHITELIST_START,
            COMMON_LIST_SEGMENT_STRIDE
        );
        assert_eq!(
            TID_WHITELIST_START - PID_BLACKLIST_START,
            COMMON_LIST_SEGMENT_STRIDE
        );
        assert_eq!(
            TID_BLACKLIST_START - TID_WHITELIST_START,
            COMMON_LIST_SEGMENT_STRIDE
        );
    }

    /// Regression test for the "0x400 stride" defect (report item D4): with a
    /// 1024-wide window, `PID_WHITELIST_START + pid` collided with
    /// `TID_WHITELIST_START + tid` for real Android values (pid/tid > 1024) and
    /// `UID_WHITELIST_START + uid` collided for uids > 10000, causing filters to
    /// wrongly allow or wrongly drop processes. Every segment must now be wide
    /// enough that all realistic keys stay inside their own segment.
    #[test]
    fn common_list_segments_do_not_collide_for_realistic_ids() {
        // Linux PID_MAX_LIMIT is 4*1024*1024, so pid/tid <= PID_MAX_LIMIT - 1.
        const PID_MAX_LIMIT: u32 = 4 * 1024 * 1024;
        // Highest syscall number we ever key on (aarch64 is < 470).
        const SYSNO_MAX: u32 = 1023;
        // uids: 0..19999 app ranges, 99000..99999 isolated apps; 10^6 is a
        // comfortable ceiling (uid_t extremes do not occur on Android).
        const UID_MAX: u32 = 999_999;

        let segments: [(&str, u32, u32); 8] = [
            ("sys whitelist", SYS_WHITELIST_START, SYSNO_MAX),
            ("sys blacklist", SYS_BLACKLIST_START, SYSNO_MAX),
            ("uid whitelist", UID_WHITELIST_START, UID_MAX),
            ("uid blacklist", UID_BLACKLIST_START, UID_MAX),
            ("pid whitelist", PID_WHITELIST_START, PID_MAX_LIMIT - 1),
            ("pid blacklist", PID_BLACKLIST_START, PID_MAX_LIMIT - 1),
            ("tid whitelist", TID_WHITELIST_START, PID_MAX_LIMIT - 1),
            ("tid blacklist", TID_BLACKLIST_START, PID_MAX_LIMIT - 1),
        ];

        for (i, (name_a, start_a, max_a)) in segments.iter().enumerate() {
            let last_key_a = start_a + max_a;
            assert!(
                last_key_a < COMMON_LIST_MAX_KEY,
                "{name_a}: highest key {last_key_a:#x} escapes the segment space"
            );
            for (name_b, start_b, _) in segments.iter().skip(i + 1) {
                assert!(
                    last_key_a < *start_b,
                    "{name_a} [{start_a:#x}..{last_key_a:#x}] collides with {name_b} (starts {start_b:#x})"
                );
            }
        }
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
