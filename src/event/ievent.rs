//! Common event primitives and on-wire buffer layouts. Mirrors dev's
//! `user/event/ievent.go` (`CommonEvent`) + `user/event/event_context.go`
//! (`UnwindBuf` / `RegsBuf` / `UnwindOption`; master kept all of these in
//! `ievent.go`).
//!
//! All multi-byte fields are **little-endian** (decoded with `from_le_bytes`),
//! matching Go's `encoding/binary.LittleEndian`.

use anyhow::{anyhow, Result};

/// Option block passed to the native unwinder's `StackPlz` FFI. Mirrors the C++
/// `UnwindOption` it casts `void* opt` to (unwinddaemon `lib.cpp:229-235`) and
/// dev's `ContextEvent.GetOpt()` (`user/event/event_context.go:278-289`).
///
/// `#[repr(C)]` so the layout is what `StackPlz` reads: `abi` @0, `stack_size`
/// @8, `dyn_size` @16, `reg_mask` @24, `show_pc` @32, total 40 bytes (seven
/// trailing padding bytes). The offsets were re-checked against the bundled dev
/// `libstackplz.so` disassembly (`StackPlz` loads `[x1]`, `[x1,#0x18]`,
/// `[x1,#0x10]`, `ldrb [x1,#0x20]`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UnwindOption {
    pub abi: u64,
    pub stack_size: u64,
    pub dyn_size: u64,
    pub reg_mask: u64,
    pub show_pc: bool,
}

/// Parsed perf unwind buffer (regs + stack dump).
/// Mirrors `UnwindBuf` (`user/event/event_context.go:50`) and `ParseContext`
/// (`event_context.go:58`).
///
/// On-wire layout (little-endian):
///   u64  abi
///   u64  regs[33]
///   u64  stack_size
///   u8   data[stack_size]
///   u64  dyn_size
#[derive(Debug, Clone)]
pub struct UnwindBuf {
    pub abi: u64,
    pub regs: [u64; super::REG_COUNT],
    pub stack_size: u64,
    pub data: Vec<u8>,
    pub dyn_size: u64,
}

impl Default for UnwindBuf {
    fn default() -> Self {
        Self {
            abi: 0,
            regs: [0; super::REG_COUNT],
            stack_size: 0,
            data: Vec::new(),
            dyn_size: 0,
        }
    }
}

impl UnwindBuf {
    /// Build the `UnwindOption` passed to `StackPlz`, mirroring dev's
    /// `ContextEvent.GetOpt()` (`user/event/event_context.go:278-289`): the ARM64
    /// register mask covers all 33 sampled registers.
    pub fn unwind_option(&self, show_pc: bool) -> UnwindOption {
        UnwindOption {
            abi: self.abi,
            stack_size: self.stack_size,
            dyn_size: self.dyn_size,
            reg_mask: crate::ebpf::bpf_common::ARM64_REG_MASK,
            show_pc,
        }
    }

    /// Parse from a little-endian byte cursor. Mirrors
    /// `UnwindBuf.ParseContext(buf)` (`user/event/event_context.go:58`). Advances `pos`.
    pub fn parse(buf: &[u8], pos: &mut usize) -> Result<Self> {
        let abi = read_u64(buf, pos)?;
        let mut regs = [0u64; super::REG_COUNT];
        for r in regs.iter_mut() {
            *r = read_u64(buf, pos)?;
        }
        let stack_size =
            usize::try_from(read_u64(buf, pos)?).map_err(|_| anyhow!("stack_size too large"))?;
        let data = read_bytes(buf, pos, stack_size)?;
        let dyn_size = read_u64(buf, pos)?;
        Ok(UnwindBuf {
            abi,
            regs,
            stack_size: stack_size as u64,
            data,
            dyn_size,
        })
    }
}

/// Parsed perf registers-only buffer.
/// Mirrors `RegsBuf` (`user/event/event_context.go:77`) and `RegsBuf.ParseContext`
/// (`event_context.go:82`).
#[derive(Debug, Clone)]
pub struct RegsBuf {
    pub abi: u64,
    pub regs: [u64; super::REG_COUNT],
}

impl Default for RegsBuf {
    fn default() -> Self {
        Self {
            abi: 0,
            regs: [0; super::REG_COUNT],
        }
    }
}

impl RegsBuf {
    pub fn parse(buf: &[u8], pos: &mut usize) -> Result<Self> {
        let abi = read_u64(buf, pos)?;
        let mut regs = [0u64; super::REG_COUNT];
        for r in regs.iter_mut() {
            *r = read_u64(buf, pos)?;
        }
        Ok(RegsBuf { abi, regs })
    }
}

/// Common base event. Mirrors `CommonEvent` (`user/event/ievent.go:50`).
/// Holds the raw perf sample buffer and shared references.
#[derive(Debug, Default)]
pub struct CommonEvent {
    /// Raw perf record sample bytes (set by `SetRecord`).
    pub raw: Vec<u8>,
}

impl CommonEvent {
    pub fn set_record(&mut self, raw: Vec<u8>) {
        self.raw = raw;
    }
}

// ---- little-endian cursor helpers ----------------------------------------

pub(crate) fn read_u64(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let v = u64::from_le_bytes(read_array::<8>(buf, pos)?);
    Ok(v)
}
pub(crate) fn read_bytes(buf: &[u8], pos: &mut usize, n: usize) -> Result<Vec<u8>> {
    if n > buf.len().saturating_sub(*pos) {
        return Err(anyhow!(
            "buffer underflow: need {} bytes at pos {} (len {})",
            n,
            pos,
            buf.len()
        ));
    }
    let out = buf[*pos..*pos + n].to_vec();
    *pos += n;
    Ok(out)
}

fn read_array<const N: usize>(buf: &[u8], pos: &mut usize) -> Result<[u8; N]> {
    let slice = read_bytes(buf, pos, N)?;
    let mut arr = [0u8; N];
    arr.copy_from_slice(&slice);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwind_option_matches_cpp_layout() {
        // C++ `UnwindOption` (unwinddaemon `lib.cpp:229-235`): 4 × u64 + bool,
        // 40 bytes including the trailing padding.
        assert_eq!(std::mem::size_of::<UnwindOption>(), 40);
        assert_eq!(std::mem::offset_of!(UnwindOption, abi), 0);
        assert_eq!(std::mem::offset_of!(UnwindOption, stack_size), 8);
        assert_eq!(std::mem::offset_of!(UnwindOption, dyn_size), 16);
        assert_eq!(std::mem::offset_of!(UnwindOption, reg_mask), 24);
        assert_eq!(std::mem::offset_of!(UnwindOption, show_pc), 32);
    }

    #[test]
    fn unwind_buf_roundtrip() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u64.to_le_bytes()); // abi
        for val in (0x1000u64..).take(33) {
            bytes.extend_from_slice(&val.to_le_bytes()); // regs
        }
        bytes.extend_from_slice(&4u64.to_le_bytes()); // stack_size
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // data
        bytes.extend_from_slice(&0x2000u64.to_le_bytes()); // dyn_size

        let mut pos = 0;
        let ub = UnwindBuf::parse(&bytes, &mut pos).unwrap();
        assert_eq!(ub.abi, 1);
        assert_eq!(ub.regs[0], 0x1000);
        assert_eq!(ub.regs[32], 0x1020);
        assert_eq!(ub.stack_size, 4);
        assert_eq!(ub.data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(ub.dyn_size, 0x2000);
        assert_eq!(pos, bytes.len());

        let opt = ub.unwind_option(false);
        assert_eq!(opt.abi, 1);
        assert_eq!(opt.stack_size, 4);
        assert_eq!(opt.dyn_size, 0x2000);
        assert_eq!(opt.reg_mask, crate::ebpf::bpf_common::ARM64_REG_MASK);
        assert!(!opt.show_pc);
    }

    #[test]
    fn regs_buf_roundtrip() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes()); // abi
        for val in 0u64..33 {
            bytes.extend_from_slice(&val.to_le_bytes());
        }
        let mut pos = 0;
        let rb = RegsBuf::parse(&bytes, &mut pos).unwrap();
        assert_eq!(rb.abi, 2);
        assert_eq!(rb.regs[31], 31);
        assert_eq!(pos, bytes.len());
    }

    #[test]
    fn underflow_is_error() {
        let bytes = [0u8; 4]; // too small for a u64
        let mut pos = 0;
        assert!(read_u64(&bytes, &mut pos).is_err());
    }
}
