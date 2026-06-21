//! Enumerations mirroring the C enums in `ebpf/types.h` and
//! `ebpf/common/consts.h`.
//!
//! These are the wire/contract values exchanged with the eBPF programs and
//! stored in BPF maps. They are `#[repr(u32)]` so their numeric values are
//! fixed and match the C enum exactly.

/// `enum event_id_e` — discriminant carried in `event_context_t.eventid`.
/// Identifies which eBPF program emitted a perf record.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventId {
    SyscallEnter = 456,
    SyscallExit = 457,
    UprobeEnter = 458,
}

impl EventId {
    /// Parse from a raw `u32` event id. Returns `None` for unknown ids.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            456 => Some(Self::SyscallEnter),
            457 => Some(Self::SyscallExit),
            458 => Some(Self::UprobeEnter),
            _ => None,
        }
    }
}

/// `enum op_code_e` — the bytecode the kernel VM in `utils.h::read_args`
/// interprets. Numbering starts at 233 (`OP_SKIP`).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpCode {
    Skip = 233,
    ResetCtx,
    SetRegIndex,
    SetReadLen,
    SetReadLenRegValue,
    SetReadLenPointerValue,
    SetReadCount,
    AddOffset,
    SubOffset,
    MoveRegValue,
    MovePointerValue,
    MoveTmpValue,
    SetTmpValue,
    ForBreak,
    SetBreakCount,
    SetBreakCountRegValue,
    SetBreakCountPointerValue,
    SaveAddr,
    AddReg,
    SubReg,
    ReadReg,
    SaveReg,
    ReadPointer,
    SavePointer,
    SaveStruct,
    FilterValue,
    FilterBuffer,
    FilterString,
    SaveString,
    SavePtrString,
    ReadStdString,
    ReadIl2cppString,
    SaveString16,
    SavePtrString16,
}

impl OpCode {
    /// Parse from a raw `u32`. Returns `None` for values outside the enum.
    pub fn from_u32(v: u32) -> Option<Self> {
        // 34 contiguous members, OP_SKIP=233 .. OP_SAVE_PTR_STRING16=266.
        if !(233..=266).contains(&v) {
            return None;
        }
        // SAFETY: OpCode is repr(u32) with contiguous field-less variants
        // 233..=266, and we just validated v is in that range.
        Some(unsafe { std::mem::transmute::<u32, Self>(v) })
    }

    /// The numeric value as used in `op_config_t.code`/`pre_code`/`post_code`.
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// `enum arg_type_e` — the *BaseType* category of an argument type. Mirrors the
/// C enum in `types.h` (41 members). Note this is distinct from the userspace
/// `TypeIndex` registry (see argtype).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArgType {
    None = 0,
    Num,
    ExpInt,
    Int,
    Uint,
    Int8,
    Int16,
    Uint8,
    Uint16,
    Int32,
    Uint32,
    Int64,
    Uint64,
    String,
    StringArr,
    Pointer,
    Struct,
    Timespec,
    Stat,
    Statfs,
    Sigaction,
    Utsname,
    Sockaddr,
    Rusage,
    Iovec,
    EpollEvent,
    Sigset,
    Pollfd,
    Sysinfo,
    Siginfo,
    Msghdr,
    Itimerspec,
    StackT,
    Timeval,
    Timezone,
    PthreadAttr,
    Array,
    ArrayInt32,
    ArrayUint32,
    Buffer,
}

/// `enum point_flag_e` — per-point behavior flags carried in
/// `point_arg.point_flag`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointFlag {
    Forbidden = 0,
    SysEnterExit,
    SysEnter,
    SysExit,
    UprobeEnterRead,
}

/// `enum arg_filter_e` — filter rule kind in `arg_filter_t.filter_type`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArgFilterType {
    Unknown = 0,
    Equal,
    Greater,
    Less,
    Whitelist,
    Blacklist,
    Replace,
}

impl ArgFilterType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Unknown),
            1 => Some(Self::Equal),
            2 => Some(Self::Greater),
            3 => Some(Self::Less),
            4 => Some(Self::Whitelist),
            5 => Some(Self::Blacklist),
            6 => Some(Self::Replace),
            _ => None,
        }
    }
}

/// `enum trace_group_e` — uid-group bitmask in
/// `common_filter_t.trace_uid_group`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceGroup {
    None = 1 << 0,
    Root = 1 << 1,
    System = 1 << 2,
    Shell = 1 << 3,
    App = 1 << 4,
    Iso = 1 << 5,
}

/// `enum buf_idx_e` — index into the per-CPU `bufs` array.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BufIdx {
    /// `STRING_BUF_IDX = 0`.
    StringBuf = 0,
    /// `ZERO_BUF_IDX = 1`.
    ZeroBuf = 1,
}

/// arm64 register indices (subset used for the TLV header args 1/2/3 and
/// register saves). Mirrors `enum arm64_reg_e`.
#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arm64Reg {
    X0 = 0,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
    X8,
    X9,
    X10,
    X11,
    X12,
    X13,
    X14,
    X15,
    X16,
    X17,
    X18,
    X19,
    X20,
    X21,
    X22,
    X23,
    X24,
    X25,
    X26,
    X27,
    X28,
    X29,
    Lr,
    Sp,
    Pc,
    Max,
    Index,
    Abs,
}

/// Number of general-purpose arm64 registers saved in `ctx_regs_t.regs`
/// (x0..x28). `sp`/`pc`/`flag` are separate fields. Matches the
/// `for (i = 0; i < 31; i++)` loop in `stack.c`/`syscall.c`.
pub const CTX_REGS_LEN: usize = 31;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_id_values_match_c_enum() {
        assert_eq!(EventId::SyscallEnter as u32, 456);
        assert_eq!(EventId::SyscallExit as u32, 457);
        assert_eq!(EventId::UprobeEnter as u32, 458);
        assert_eq!(EventId::from_u32(456), Some(EventId::SyscallEnter));
        assert_eq!(EventId::from_u32(999), None);
    }

    #[test]
    fn opcode_starts_at_233_and_is_contiguous() {
        assert_eq!(OpCode::Skip as u32, 233);
        // 34 members total (233..=266).
        assert_eq!(OpCode::SavePtrString16 as u32, 266);
        assert_eq!(OpCode::from_u32(233), Some(OpCode::Skip));
        assert_eq!(OpCode::from_u32(266), Some(OpCode::SavePtrString16));
        assert_eq!(OpCode::from_u32(232), None);
        assert_eq!(OpCode::from_u32(267), None);
        // SaveStruct is the 25th opcode (0-indexed 24 from Skip).
        assert_eq!(OpCode::SaveStruct as u32, 233 + 24);
    }

    #[test]
    fn arg_type_enum_count_matches_c() {
        // 40 members: None=0 .. Buffer=39.
        assert_eq!(ArgType::None as u32, 0);
        assert_eq!(ArgType::Buffer as u32, 39);
    }

    #[test]
    fn arg_filter_type_round_trip() {
        assert_eq!(ArgFilterType::from_u32(0), Some(ArgFilterType::Unknown));
        assert_eq!(ArgFilterType::from_u32(6), Some(ArgFilterType::Replace));
        assert_eq!(ArgFilterType::from_u32(7), None);
    }

    #[test]
    fn trace_group_is_bitmask() {
        assert_eq!(TraceGroup::Root as u32, 1 << 1);
        assert_eq!(TraceGroup::Iso as u32, 1 << 5);
    }

    #[test]
    fn buf_idx_values() {
        assert_eq!(BufIdx::StringBuf as u32, 0);
        assert_eq!(BufIdx::ZeroBuf as u32, 1);
    }

    #[test]
    fn ctx_regs_len_is_31() {
        // The save loop is `for (i = 0; i < 31; i++) saved_regs.regs[i] = ...`.
        assert_eq!(CTX_REGS_LEN, 31);
    }
}
