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

// Pins the `transmute` in `OpCode::from_u32`: the variant range is contiguous
// 233..=266. This only catches additions/removals: swapping two middle members
// leaves both endpoints fixed and would slip through — the per-variant wire
// values are pinned by `opcode_values_match_c_enum` in the tests below.
const _: () = assert!(OpCode::Skip as u32 == 233 && OpCode::SavePtrString16 as u32 == 266);

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
/// C enum in `types.h` (40 members). Note this is distinct from the userspace
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

    /// L1: every `OpCode` variant is pinned to its wire value, mirroring
    /// `ebpf/types.h` `enum op_code_e` (`OP_SKIP = 233` ..
    /// `OP_SAVE_PTR_STRING16 = 266`). The compile-time assert above only guards
    /// additions/removals; these asserts are what catch a middle-member swap
    /// (e.g. `FilterValue` ↔ `SaveString`, which would silently mis-wire the
    /// kernel VM).
    #[test]
    fn opcode_values_match_c_enum() {
        assert_eq!(OpCode::Skip as u32, 233);
        assert_eq!(OpCode::ResetCtx as u32, 234);
        assert_eq!(OpCode::SetRegIndex as u32, 235);
        assert_eq!(OpCode::SetReadLen as u32, 236);
        assert_eq!(OpCode::SetReadLenRegValue as u32, 237);
        assert_eq!(OpCode::SetReadLenPointerValue as u32, 238);
        assert_eq!(OpCode::SetReadCount as u32, 239);
        assert_eq!(OpCode::AddOffset as u32, 240);
        assert_eq!(OpCode::SubOffset as u32, 241);
        assert_eq!(OpCode::MoveRegValue as u32, 242);
        assert_eq!(OpCode::MovePointerValue as u32, 243);
        assert_eq!(OpCode::MoveTmpValue as u32, 244);
        assert_eq!(OpCode::SetTmpValue as u32, 245);
        assert_eq!(OpCode::ForBreak as u32, 246);
        assert_eq!(OpCode::SetBreakCount as u32, 247);
        assert_eq!(OpCode::SetBreakCountRegValue as u32, 248);
        assert_eq!(OpCode::SetBreakCountPointerValue as u32, 249);
        assert_eq!(OpCode::SaveAddr as u32, 250);
        assert_eq!(OpCode::AddReg as u32, 251);
        assert_eq!(OpCode::SubReg as u32, 252);
        assert_eq!(OpCode::ReadReg as u32, 253);
        assert_eq!(OpCode::SaveReg as u32, 254);
        assert_eq!(OpCode::ReadPointer as u32, 255);
        assert_eq!(OpCode::SavePointer as u32, 256);
        assert_eq!(OpCode::SaveStruct as u32, 257);
        assert_eq!(OpCode::FilterValue as u32, 258);
        assert_eq!(OpCode::FilterBuffer as u32, 259);
        assert_eq!(OpCode::FilterString as u32, 260);
        assert_eq!(OpCode::SaveString as u32, 261);
        assert_eq!(OpCode::SavePtrString as u32, 262);
        assert_eq!(OpCode::ReadStdString as u32, 263);
        assert_eq!(OpCode::ReadIl2cppString as u32, 264);
        assert_eq!(OpCode::SaveString16 as u32, 265);
        assert_eq!(OpCode::SavePtrString16 as u32, 266);
    }

    /// M2: every `ArgType` variant is pinned to its wire value, mirroring
    /// `ebpf/types.h` `enum arg_type_e` (`TYPE_NONE = 0` .. `TYPE_BUFFER =
    /// 39`).
    #[test]
    fn arg_type_values_match_c_enum() {
        assert_eq!(ArgType::None as u32, 0);
        assert_eq!(ArgType::Num as u32, 1);
        assert_eq!(ArgType::ExpInt as u32, 2);
        assert_eq!(ArgType::Int as u32, 3);
        assert_eq!(ArgType::Uint as u32, 4);
        assert_eq!(ArgType::Int8 as u32, 5);
        assert_eq!(ArgType::Int16 as u32, 6);
        assert_eq!(ArgType::Uint8 as u32, 7);
        assert_eq!(ArgType::Uint16 as u32, 8);
        assert_eq!(ArgType::Int32 as u32, 9);
        assert_eq!(ArgType::Uint32 as u32, 10);
        assert_eq!(ArgType::Int64 as u32, 11);
        assert_eq!(ArgType::Uint64 as u32, 12);
        assert_eq!(ArgType::String as u32, 13);
        assert_eq!(ArgType::StringArr as u32, 14);
        assert_eq!(ArgType::Pointer as u32, 15);
        assert_eq!(ArgType::Struct as u32, 16);
        assert_eq!(ArgType::Timespec as u32, 17);
        assert_eq!(ArgType::Stat as u32, 18);
        assert_eq!(ArgType::Statfs as u32, 19);
        assert_eq!(ArgType::Sigaction as u32, 20);
        assert_eq!(ArgType::Utsname as u32, 21);
        assert_eq!(ArgType::Sockaddr as u32, 22);
        assert_eq!(ArgType::Rusage as u32, 23);
        assert_eq!(ArgType::Iovec as u32, 24);
        assert_eq!(ArgType::EpollEvent as u32, 25);
        assert_eq!(ArgType::Sigset as u32, 26);
        assert_eq!(ArgType::Pollfd as u32, 27);
        assert_eq!(ArgType::Sysinfo as u32, 28);
        assert_eq!(ArgType::Siginfo as u32, 29);
        assert_eq!(ArgType::Msghdr as u32, 30);
        assert_eq!(ArgType::Itimerspec as u32, 31);
        assert_eq!(ArgType::StackT as u32, 32);
        assert_eq!(ArgType::Timeval as u32, 33);
        assert_eq!(ArgType::Timezone as u32, 34);
        assert_eq!(ArgType::PthreadAttr as u32, 35);
        assert_eq!(ArgType::Array as u32, 36);
        assert_eq!(ArgType::ArrayInt32 as u32, 37);
        assert_eq!(ArgType::ArrayUint32 as u32, 38);
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
}
