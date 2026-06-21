//! `#[repr(C)]` mirror of every on-wire / in-map struct defined in
//! `ebpf/types.h`. Field order, types, and total size MUST match the C
//! definitions exactly so Rust can cast these to/from the raw bytes that cross
//! the kernel boundary.
//!
//! Layout verification (offsets + sizes) lives in the `tests` module at the
//! bottom and in `tests/contracts.rs`.

use crate::contract::consts::{
    MAX_OP_COUNT_STACK, MAX_OP_COUNT_SYSCALL, MAX_PERCPU_BUFSIZE, MAX_STRCMP_LEN, TASK_COMM_LEN,
};
use crate::contract::enums::CTX_REGS_LEN;

/// `event_context_t` — the fixed 56-byte header of every perf record. The TLV
/// args blob follows immediately after this. Mirrors `event_context` in
/// `types.h`.
///
/// Layout (little-endian on aarch64):
/// ```text
/// off  0  u64 ts
/// off  8  u32 eventid            (EventId: 456/457/458)
/// off 12  u32 host_tid           (pid_tgid & 0xffffffff)
/// off 16  u32 host_pid           (pid_tgid >> 32)
/// off 20  u32 tid                (namespace pid)
/// off 24  u32 pid                (namespace tgid)
/// off 28  u32 uid
/// off 32  char comm[16]
/// off 48  u8  argnum
/// off 49  char padding[7]
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct EventContext {
    pub ts: u64,
    pub eventid: u32,
    pub host_tid: u32,
    pub host_pid: u32,
    pub tid: u32,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub argnum: u8,
    pub padding: [u8; 7],
}

/// `common_filter_t` — global behavior filter (map `common_filter`, key 0).
/// 20 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct CommonFilter {
    pub is_32bit: u32,
    pub trace_mode: u32,
    pub trace_uid_group: u32,
    pub signal: u32,
    pub tsignal: u32,
}

/// `config_entry_t` — global config (map `base_config`, key 0). 8 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ConfigEntry {
    pub stackplz_pid: u32,
    pub thread_whitelist: u32,
}

/// `thread_name_t` — key for the `thread_filter` map. 16 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ThreadName {
    pub name: [u8; TASK_COMM_LEN],
}

/// `str_buf_t` — value type for `str_buf`/`str_buf_gen`/`str_buf_map`, and key
/// for `str_buf`. 256 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StrBuf {
    pub str_val: [u8; MAX_STRCMP_LEN],
}
// `[u8; 256]` doesn't impl `Default` (std only impls Default for arrays up to
// 32 elements), so provide it manually.
impl Default for StrBuf {
    fn default() -> Self {
        Self { str_val: [0; MAX_STRCMP_LEN] }
    }
}
// SAFETY: repr(C) over a single byte array — no padding holes, every bit
// pattern valid. Manual impl instead of `#[derive(Pod)]` because bytemuck's
// array `Pod` impl is size-limited and `[u8; 256]` can exceed it depending on
// the bytemuck version.
unsafe impl bytemuck::Pod for StrBuf {}
unsafe impl bytemuck::Zeroable for StrBuf {}

/// `arg_filter_t` — per-arg match filter (map `arg_filter`, keyed by u64 id).
/// 272 bytes.
///
/// Layout (repr(C), no manual padding needed):
///   off   0  u32 filter_type        (4 bytes)
///   off   4  u8  str_val[256]       (256 bytes)
///   off 260  u32 str_len            (4 bytes, ends at 264)
///   off 264  u64 num_val            (8 bytes; 264 is 8-aligned, no gap)
/// Total = 272.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ArgFilter {
    pub filter_type: u32,
    pub str_val: [u8; MAX_STRCMP_LEN],
    pub str_len: u32,
    pub num_val: u64,
}
// SAFETY: repr(C) with no implicit padding (264 is 8-aligned, so `num_val`
// follows `str_len` with no gap). All fields are integers/byte arrays with
// valid all-zero representations.
unsafe impl bytemuck::Pod for ArgFilter {}
unsafe impl bytemuck::Zeroable for ArgFilter {}

impl Default for ArgFilter {
    fn default() -> Self {
        Self {
            filter_type: 0,
            str_val: [0; MAX_STRCMP_LEN],
            str_len: 0,
            num_val: 0,
        }
    }
}

/// `op_config_t` — one bytecode op (map `op_list`, keyed by u32 op index).
/// 24 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct OpConfig {
    pub code: u32,
    pub pre_code: u32,
    pub post_code: u32,
    /// C inserts 4 bytes of padding here to 8-align `value`.
    pub _pad: [u8; 4],
    pub value: u64,
}

/// `op_ctx_t` — per-CPU VM execution state (map `op_ctx_map`, 2 slots).
/// 72 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct OpCtx {
    pub save_index: u8,
    pub reg_index: u8,
    pub loop_count: u8,
    pub break_count: u8,
    pub apply_filter: u8,
    pub skip_flag: u8,
    pub match_whitelist: u8,
    pub match_blacklist: u8,
    pub loop_index: u32,
    pub op_key_index: u32,
    pub op_code: u32,
    pub post_code: u32,
    pub str_len: u32,
    pub read_len: u32,
    pub read_addr: u64,
    pub reg_value: u64,
    pub pointer_value: u64,
    pub tmp_value: u64,
    pub reg_0: u64,
}

/// `ctx_regs_t` — register snapshot persisted between sys_enter and sys_exit
/// (map `ctx_regs_map`, keyed by u64). 272 bytes (31*8 + 8 + 8 + 8).
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct CtxRegs {
    pub regs: [u64; CTX_REGS_LEN],
    pub sp: u64,
    pub pc: u64,
    pub flag: u64,
}

impl Default for CtxRegs {
    fn default() -> Self {
        Self { regs: [0; CTX_REGS_LEN], sp: 0, pc: 0, flag: 0 }
    }
}

/// `point_args_t` — per-hook config (maps `sysenter_point_args` /
/// `sysexit_point_args` / `uprobe_point_args`). The generic parameter `N` is
/// `MAX_OP_COUNT` (64 for uprobe, 256 for syscall), so size varies by object.
///
/// `PointArgs<MAX_OP_COUNT_STACK>` is 268 bytes (12 + 4*64);
/// `PointArgs<MAX_OP_COUNT_SYSCALL>` is 1036 bytes (12 + 4*256).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PointArgs<const N: usize> {
    pub enter_key: u32,
    pub signal: u32,
    pub op_count: u32,
    pub op_key_list: [u32; N],
}
// SAFETY: repr(C) of u32 fields + [u32; N]. No padding holes (N u32s keep
// 4-alignment), all-zero is valid. Manual impl is required: the `#[derive(Pod)]`
// macro cannot prove `[u32; N]: Pod` for a generic `N`.
unsafe impl<const N: usize> bytemuck::Pod for PointArgs<N> {}
unsafe impl<const N: usize> bytemuck::Zeroable for PointArgs<N> {}

impl<const N: usize> Default for PointArgs<N> {
    fn default() -> Self {
        Self { enter_key: 0, signal: 0, op_count: 0, op_key_list: [0; N] }
    }
}

/// Stack (uprobe) variant: 64 ops.
pub type StackPointArgs = PointArgs<MAX_OP_COUNT_STACK>;
/// Syscall variant: 256 ops.
pub type SyscallPointArgs = PointArgs<MAX_OP_COUNT_SYSCALL>;

/// `buf_t` — per-CPU scratch buffer (map `bufs`, 2 slots). 32768 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BufT {
    pub buf: [u8; MAX_PERCPU_BUFSIZE],
}
// SAFETY: repr(C) over a single byte array — no holes, all bit patterns valid.
// Manual impl because [u8; 32768] exceeds bytemuck's array Pod size limit.
unsafe impl bytemuck::Pod for BufT {}
unsafe impl bytemuck::Zeroable for BufT {}

impl Default for BufT {
    fn default() -> Self {
        Self { buf: [0; MAX_PERCPU_BUFSIZE] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Field offset of `field` within `T` via the safe `std::mem::offset_of!`
    /// (stabilized in Rust 1.77).
    macro_rules! offset {
        ($ty:ty, $field:ident) => {
            std::mem::offset_of!($ty, $field)
        };
    }

    #[test]
    fn event_context_is_56_bytes_with_correct_offsets() {
        assert_eq!(std::mem::size_of::<EventContext>(), 56);
        assert_eq!(offset!(EventContext, ts), 0);
        assert_eq!(offset!(EventContext, eventid), 8);
        assert_eq!(offset!(EventContext, host_tid), 12);
        assert_eq!(offset!(EventContext, host_pid), 16);
        assert_eq!(offset!(EventContext, tid), 20);
        assert_eq!(offset!(EventContext, pid), 24);
        assert_eq!(offset!(EventContext, uid), 28);
        assert_eq!(offset!(EventContext, comm), 32);
        assert_eq!(offset!(EventContext, argnum), 48);
    }

    #[test]
    fn common_filter_is_20_bytes() {
        assert_eq!(std::mem::size_of::<CommonFilter>(), 20);
    }

    #[test]
    fn config_entry_is_8_bytes() {
        assert_eq!(std::mem::size_of::<ConfigEntry>(), 8);
    }

    #[test]
    fn thread_name_is_16_bytes() {
        assert_eq!(std::mem::size_of::<ThreadName>(), 16);
    }

    #[test]
    fn str_buf_is_256_bytes() {
        assert_eq!(std::mem::size_of::<StrBuf>(), MAX_STRCMP_LEN);
        assert_eq!(MAX_STRCMP_LEN, 256);
    }

    #[test]
    fn arg_filter_is_272_bytes_num_val_at_offset_264() {
        assert_eq!(std::mem::size_of::<ArgFilter>(), 272);
        assert_eq!(offset!(ArgFilter, num_val), 264);
        assert_eq!(offset!(ArgFilter, str_len), 4 + MAX_STRCMP_LEN);
    }

    #[test]
    fn op_config_is_24_bytes_value_at_offset_16() {
        // C op_config_t { u32 code; u32 pre_code; u32 post_code; u64 value; }
        // — value lands at offset 16 (12 bytes of u32s + 4 implicit padding).
        assert_eq!(std::mem::size_of::<OpConfig>(), 24);
        assert_eq!(offset!(OpConfig, value), 16);
    }

    #[test]
    fn op_ctx_is_72_bytes() {
        // read_addr (first u64) follows 8*u8 + 6*u32 = 8 + 24 = 32 bytes,
        // which is 8-aligned, so it lands at offset 32 (no gap).
        assert_eq!(std::mem::size_of::<OpCtx>(), 72);
        assert_eq!(offset!(OpCtx, read_addr), 32);
    }

    #[test]
    fn ctx_regs_is_272_bytes() {
        assert_eq!(std::mem::size_of::<CtxRegs>(), 272);
        assert_eq!(std::mem::size_of::<[u64; CTX_REGS_LEN]>(), 31 * 8);
        assert_eq!(offset!(CtxRegs, sp), 31 * 8);
    }

    #[test]
    fn point_args_sizes_match_module_defines() {
        assert_eq!(std::mem::size_of::<StackPointArgs>(), 268);
        assert_eq!(std::mem::size_of::<SyscallPointArgs>(), 1036);
    }

    #[test]
    fn buf_t_is_32k() {
        assert_eq!(std::mem::size_of::<BufT>(), MAX_PERCPU_BUFSIZE);
        assert_eq!(MAX_PERCPU_BUFSIZE, 32768);
    }

    #[test]
    fn event_context_pod_roundtrip() {
        let ctx = EventContext {
            ts: 0x1111,
            eventid: 456,
            host_tid: 0x22,
            host_pid: 0x33,
            tid: 0x44,
            pid: 0x55,
            uid: 0x66,
            comm: {
                let mut c = [0u8; 16];
                c[..4].copy_from_slice(b"app\0");
                c
            },
            argnum: 3,
            padding: [0; 7],
        };
        let bytes = bytemuck::bytes_of(&ctx);
        assert_eq!(bytes.len(), 56);
        // ts LE at offset 0.
        assert_eq!(&bytes[0..8], 0x1111u64.to_le_bytes());
        // eventid at offset 8.
        assert_eq!(&bytes[8..12], 456u32.to_le_bytes());
        // argnum at offset 48.
        assert_eq!(bytes[48], 3);
    }

    #[test]
    fn unused_const_marker() {
        // ARGS_BUF_SIZE is part of the contract even though it sizes a
        // scratch buffer not exposed on the wire; assert it once.
        assert_eq!(crate::contract::consts::ARGS_BUF_SIZE, 32000);
        assert_eq!(crate::contract::consts::STRARR_MAGIC_LEN, 0xffff_0000);
    }
}
