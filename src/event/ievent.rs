//! Common event primitives and on-wire buffer layouts. Mirrors
//! `user/event/ievent.go`.
//!
//! All multi-byte fields are **little-endian** (decoded with `from_le_bytes`),
//! matching Go's `encoding/binary.LittleEndian`.

use anyhow::{anyhow, Result};

/// Argument block passed to the native unwinder's `StackPlz` FFI.
/// Mirrors `LibArg` (`ievent.go:104-109`). `#[repr(C)]` so the layout matches
/// what `get_stack(...)` expects (see `load_so.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LibArg {
    pub abi: u64,
    pub regs: [u64; super::REG_COUNT],
    pub stack_size: u64,
    pub dyn_size: u64,
}
// `[u64; 33]` lacks a std `Default` impl (std caps array Default at 32
// elements), so provide one manually.
impl Default for LibArg {
    fn default() -> Self {
        Self {
            abi: 0,
            regs: [0; super::REG_COUNT],
            stack_size: 0,
            dyn_size: 0,
        }
    }
}
// SAFETY: repr(C) of u64 fields + [u64; 33]; all fields are u64-aligned with no
// padding holes, and all-zero is a valid representation. Manual impl instead of
// `#[derive(Pod)]` because bytemuck's array Pod impl is size-limited and
// [u64; 33] (33 registers) can exceed that limit.
unsafe impl bytemuck::Pod for LibArg {}
unsafe impl bytemuck::Zeroable for LibArg {}

/// Parsed perf unwind buffer (regs + stack dump).
/// Mirrors `UnwindBuf` (`ievent.go:111-117`) and `ParseContext`
/// (`ievent.go:128-149`).
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
    /// Build the `LibArg` view passed to the native unwinder.
    /// Mirrors `UnwindBuf.GetLibArg()` (`ievent.go:119-126`).
    pub fn lib_arg(&self) -> LibArg {
        LibArg {
            abi: self.abi,
            regs: self.regs,
            stack_size: self.stack_size,
            dyn_size: self.dyn_size,
        }
    }

    /// Parse from a little-endian byte cursor. Mirrors
    /// `UnwindBuf.ParseContext(buf)` (`ievent.go:128-149`). Advances `pos`.
    pub fn parse(buf: &[u8], pos: &mut usize) -> Result<Self> {
        let abi = read_u64(buf, pos)?;
        let mut regs = [0u64; super::REG_COUNT];
        for r in regs.iter_mut() {
            *r = read_u64(buf, pos)?;
        }
        let stack_size = read_u64(buf, pos)? as usize;
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
/// Mirrors `RegsBuf` (`ievent.go:151-154`) and `RegsBuf.ParseContext`.
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

/// Common base event. Mirrors `CommonEvent` (`ievent.go:25-30`).
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

pub(crate) fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32> {
    let v = u32::from_le_bytes(read_array::<4>(buf, pos)?);
    Ok(v)
}
pub(crate) fn read_u64(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let v = u64::from_le_bytes(read_array::<8>(buf, pos)?);
    Ok(v)
}
pub(crate) fn read_bytes(buf: &[u8], pos: &mut usize, n: usize) -> Result<Vec<u8>> {
    if *pos + n > buf.len() {
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
    fn lib_arg_size_matches_layout() {
        // 1 + 33 + 1 + 1 = 36 u64s = 288 bytes, packed (u64 aligned, no holes).
        assert_eq!(std::mem::size_of::<LibArg>(), 36 * 8);
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

        let arg = ub.lib_arg();
        assert_eq!(arg.stack_size, 4);
        assert_eq!(arg.dyn_size, 0x2000);
        assert_eq!(arg.regs[32], 0x1020);
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
