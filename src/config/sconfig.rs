//! Shared hook config primitives. Mirrors `user/config/iconfig.go`.
//!
//! The two filter structs (`StackFilter`, `SyscallFilter`) are the **on-wire BPF
//! map values** that get written into the `filter_map` HASH map at runtime.
//! Their layout MUST match `struct filter_t` in `ebpf/stack.c` and
//! `ebpf/raw_syscalls.c` byte-for-byte (little-endian, no padding holes).
//!
//! Verified against the C sources:
//! - `src/stack.c`        `struct filter_t { u32 uid; u32 pid; u32 tid_blacklist_mask; u32 tid_blacklist[5]; }`        = 32 bytes
//! - `src/raw_syscalls.c` `struct filter_t { u32 uid; u32 pid; u32 nr; u32 tid_blacklist_mask; u32 tid_blacklist[5]; }` = 36 bytes

use anyhow::{bail, Result};

/// Maximum number of entries in the tid blacklist. Mirrors Go constant.
pub const MAX_TID_BLACKLIST_COUNT: usize = 5;

/// Shared hook options, embedded into both `ProbeConfig` and `SyscallConfig`.
/// Mirrors `SConfig` in `iconfig.go:26-35`.
#[derive(Debug, Clone, Default)]
pub struct SConfig {
    pub uid: u64,
    pub pid: u64,
    pub tid_blacklist_mask: u32,
    pub tid_blacklist: [u32; MAX_TID_BLACKLIST_COUNT],
    pub unwind_stack: bool,
    pub show_regs: bool,
    pub reg_name: String,
    pub debug: bool,
}

impl SConfig {
    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }
}

/// BPF `filter_map` value for the `stack` (uprobe) module.
/// Mirrors `StackFilter` in `iconfig.go:5-10` and `struct filter_t` in `stack.c:22-27`.
///
/// Layout (little-endian):
///   offset  0: u32 uid
///   offset  4: u32 pid
///   offset  8: u32 tid_blacklist_mask
///   offset 12: u32 tid_blacklist[5]
///   total  = 32 bytes
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct StackFilter {
    pub uid: u32,
    pub pid: u32,
    pub tid_blacklist_mask: u32,
    pub tid_blacklist: [u32; MAX_TID_BLACKLIST_COUNT],
}

/// BPF `filter_map` value for the `syscall` (tracepoint) module.
/// Mirrors `SyscallFilter` in `iconfig.go:12-18` and `struct filter_t` in
/// `raw_syscalls.c:23-29`. Note the extra `nr` field between `pid` and
/// `tid_blacklist_mask`.
///
/// Layout (little-endian):
///   offset  0: u32 uid
///   offset  4: u32 pid
///   offset  8: u32 nr
///   offset 12: u32 tid_blacklist_mask
///   offset 16: u32 tid_blacklist[5]
///   total  = 36 bytes
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct SyscallFilter {
    pub uid: u32,
    pub pid: u32,
    pub nr: u32,
    pub tid_blacklist_mask: u32,
    pub tid_blacklist: [u32; MAX_TID_BLACKLIST_COUNT],
}

/// Trait abstraction over hook configs. Mirrors the `IConfig` interface
/// (`iconfig.go:20-24`): `GetSConfig() / SetDebug() / Info()`.
pub trait HookConfig: Send + Sync {
    fn sconfig(&self) -> &SConfig;
    fn sconfig_mut(&mut self) -> &mut SConfig;
    fn set_debug(&mut self, debug: bool) {
        self.sconfig_mut().debug = debug;
    }
    fn info(&self) -> String;
    fn debug(&self) -> bool {
        self.sconfig().debug
    }
}

/// Helper: build a `StackFilter` from an `SConfig` snapshot.
/// Mirrors `ProbeConfig.GetFilter()` (`config_hook.go:58-66`).
pub fn stack_filter_from(s: &SConfig) -> StackFilter {
    StackFilter {
        uid: s.uid as u32,
        pid: s.pid as u32,
        tid_blacklist_mask: s.tid_blacklist_mask,
        tid_blacklist: s.tid_blacklist,
    }
}

/// Helper: build a `SyscallFilter` from an `SConfig` snapshot + syscall number.
/// Mirrors `SyscallConfig.GetFilter()` (`config_syscall.go:26-35`).
pub fn syscall_filter_from(s: &SConfig, nr: i64) -> SyscallFilter {
    SyscallFilter {
        uid: s.uid as u32,
        pid: s.pid as u32,
        nr: nr as u32,
        tid_blacklist_mask: s.tid_blacklist_mask,
        tid_blacklist: s.tid_blacklist,
    }
}

/// Build a tid blacklist (array + mask) from a comma-separated string.
/// Mirrors `persistentPreRunEFunc` tid parsing (`root.go:81-92`).
///
/// Returns `(blacklist_array, mask)`. Errors if more than 5 entries.
pub fn parse_tid_blacklist(raw: &str) -> Result<([u32; MAX_TID_BLACKLIST_COUNT], u32)> {
    let mut blacklist = [0u32; MAX_TID_BLACKLIST_COUNT];
    let mut mask: u32 = 0;
    if raw.is_empty() {
        return Ok((blacklist, mask));
    }
    let parts: Vec<&str> = raw.split(',').collect();
    if parts.len() > MAX_TID_BLACKLIST_COUNT {
        bail!(
            "max tid blacklist count is {}, provided count:{}",
            MAX_TID_BLACKLIST_COUNT,
            parts.len()
        );
    }
    for (i, v) in parts.iter().enumerate() {
        let value: u32 = v.trim().parse().unwrap_or(0);
        blacklist[i] = value;
        mask |= 1u32 << i;
    }
    Ok((blacklist, mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_filter_layout_matches_c_struct() {
        // Must equal `struct filter_t` in stack.c exactly.
        assert_eq!(std::mem::size_of::<StackFilter>(), 32);
        // Field offsets via the safe std::mem::offset_of! macro.
        assert_eq!(std::mem::offset_of!(StackFilter, uid), 0);
        assert_eq!(std::mem::offset_of!(StackFilter, pid), 4);
        assert_eq!(std::mem::offset_of!(StackFilter, tid_blacklist_mask), 8);
        assert_eq!(std::mem::offset_of!(StackFilter, tid_blacklist), 12);
    }

    #[test]
    fn syscall_filter_layout_matches_c_struct() {
        // Must equal `struct filter_t` in raw_syscalls.c exactly (with nr field).
        assert_eq!(std::mem::size_of::<SyscallFilter>(), 36);
        // Field offsets via the safe std::mem::offset_of! macro.
        assert_eq!(std::mem::offset_of!(SyscallFilter, uid), 0);
        assert_eq!(std::mem::offset_of!(SyscallFilter, pid), 4);
        assert_eq!(std::mem::offset_of!(SyscallFilter, nr), 8);
        assert_eq!(std::mem::offset_of!(SyscallFilter, tid_blacklist_mask), 12);
        assert_eq!(std::mem::offset_of!(SyscallFilter, tid_blacklist), 16);
    }

    #[test]
    fn stack_filter_byte_roundtrip() {
        let f = StackFilter {
            uid: 0x12345678,
            pid: 0xAABBCCDD,
            tid_blacklist_mask: 0x00000007,
            tid_blacklist: [10, 20, 30, 0, 0],
        };
        let bytes: &[u8] = bytemuck::bytes_of(&f);
        // little-endian u32 at offset 0
        assert_eq!(&bytes[0..4], 0x12345678u32.to_le_bytes());
        assert_eq!(&bytes[4..8], 0xAABBCCDDu32.to_le_bytes());
        assert_eq!(&bytes[8..12], 0x00000007u32.to_le_bytes());
        assert_eq!(&bytes[12..16], 10u32.to_le_bytes());
        assert_eq!(&bytes[16..20], 20u32.to_le_bytes());
        assert_eq!(&bytes[20..24], 30u32.to_le_bytes());
    }

    #[test]
    fn syscall_filter_byte_roundtrip() {
        let f = SyscallFilter {
            uid: 1,
            pid: 2,
            nr: 63,
            tid_blacklist_mask: 0b11,
            tid_blacklist: [100, 200, 0, 0, 0],
        };
        let bytes: &[u8] = bytemuck::bytes_of(&f);
        assert_eq!(&bytes[0..4], 1u32.to_le_bytes());
        assert_eq!(&bytes[4..8], 2u32.to_le_bytes());
        assert_eq!(&bytes[8..12], 63u32.to_le_bytes());
        assert_eq!(&bytes[12..16], 0b11u32.to_le_bytes());
        assert_eq!(&bytes[16..20], 100u32.to_le_bytes());
        assert_eq!(&bytes[20..24], 200u32.to_le_bytes());
    }

    #[test]
    fn parse_tid_blacklist_basic() {
        let (arr, mask) = parse_tid_blacklist("100,200").unwrap();
        assert_eq!(arr, [100, 200, 0, 0, 0]);
        assert_eq!(mask, 0b00011);
    }

    #[test]
    fn parse_tid_blacklist_empty() {
        let (arr, mask) = parse_tid_blacklist("").unwrap();
        assert_eq!(arr, [0; 5]);
        assert_eq!(mask, 0);
    }

    #[test]
    fn parse_tid_blacklist_too_many() {
        assert!(parse_tid_blacklist("1,2,3,4,5,6").is_err());
    }

    #[test]
    fn parse_tid_blacklist_full() {
        let (_, mask) = parse_tid_blacklist("1,2,3,4,5").unwrap();
        assert_eq!(mask, 0b11111);
    }
}
