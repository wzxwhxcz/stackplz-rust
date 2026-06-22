//! The dev-branch kernel contract layer.
//!
//! This module mirrors, at the `#[repr(C)]` and enum level, the on-wire and
//! in-BPF-map data structures defined in the Go project's `ebpf/` C tree
//! (copied verbatim from upstream `src/`). It is the foundation for every
//! other dev-branch subsystem: the argtype VM, the config layer, the module
//! runtime, and RPC all build on the types and constants defined here.
//!
//! Sub-modules:
//! - [`consts`]  — `#define` values from `common/consts.h` (sizes, offsets).
//! - [`enums`]   — `enum` discriminants from `types.h` (EventId, OpCode, ...).
//! - [`types`]   — `#[repr(C)]` structs (EventContext, ArgFilter, ...).
//! - [`args`]    — TLV cursor over the variable-length args blob.
//! - [`decode`]  — high-level perf-record decode (header + args dispatch).
//!
//! Platform-independent: every type is `#[repr(C)]` and the decode logic is
//! pure byte arithmetic, so the contract unit tests run on any host (Windows
//! included) without libbpf-rs or the eBPF objects.

pub mod args;
pub mod consts;
pub mod decode;
pub mod enums;
pub mod types;

// Primary re-exports for convenience.
pub use args::{ArgEntry, ArgShape, ArgsCursor, StrArrElem};
pub use consts::{
    ARGS_BUF_SIZE, COMMON_LIST_SEGMENT_STRIDE, MAX_BUF_READ_SIZE, MAX_FILTER_COUNT,
    MAX_OP_COUNT_DEFAULT, MAX_OP_COUNT_STACK, MAX_OP_COUNT_SYSCALL, MAX_PERCPU_BUFSIZE,
    MAX_STRCMP_LEN, MAX_STRING_SIZE, PID_BLACKLIST_START, PID_WHITELIST_START, PTR_SIZE,
    STRARR_MAGIC_LEN, SYS_BLACKLIST_START, SYS_WHITELIST_START, TASK_COMM_LEN,
    THREAD_NAME_BLACKLIST, THREAD_NAME_WHITELIST, TID_BLACKLIST_START, TID_WHITELIST_START,
    TRACE_ALL, TRACE_COMMON, UID_BLACKLIST_START, UID_WHITELIST_START,
};
pub use decode::{
    decode_perf_record, PerfRecord, SyscallEnterEvent, SyscallExitEvent, UprobeEnterEvent,
    EVENT_CONTEXT_SIZE,
};
pub use enums::{ArgFilterType, ArgType, Arm64Reg, BufIdx, EventId, OpCode, PointFlag, TraceGroup};
pub use types::{
    ArgFilter, BufT, CommonFilter, ConfigEntry, CtxRegs, EventContext, OpConfig, OpCtx, PointArgs,
    StackPointArgs, StrBuf, SyscallPointArgs, ThreadName,
};

/// The `MAX_EVENT_SIZE` C macro: `sizeof(event_context_t) + ARGS_BUF_SIZE`.
/// Upper bound on a perf record's total length.
pub const MAX_EVENT_SIZE: usize = EVENT_CONTEXT_SIZE + ARGS_BUF_SIZE;
