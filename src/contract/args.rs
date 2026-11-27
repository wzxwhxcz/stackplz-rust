//! TLV args-blob reader for the dev perf payload.
//!
//! After the fixed 56-byte `EventContext` header, a perf record carries a
//! variable-length **TLV (tag-length-value) args blob** produced by the eBPF
//! helper functions in `ebpf/common/buffer.h`. Each appended arg starts with a
//! `u8 index` (the positional arg slot) and one of the payload encodings:
//!
//! | writer (C)           | on-wire shape                  | used for                |
//! |----------------------|-------------------------------|-------------------------|
//! | `save_to_submit_buf` | `[index][raw bytes]`          | regs, sysno, fixed nums |
//! | `save_bytes_to_buf`  | `[index][i32 size][bytes]`    | buffers, structs, utf16 |
//! | `save_str_to_buf`    | `[index][i32 size][bytes]`    | ASCII strings           |
//!
//! `save_str_arr_to_buf` (`[index][u8 count]{[i32 sz][str]...}`) has no
//! reader: it is not emitted by any op in the interpreter, so argv/envp have
//! no wire shape here (deleted with R11-11; add a reader only with a real op).
//!
//! The reader does NOT know each arg's expected width on its own — the fixed
//! `save_to_submit_buf` entries (sysno=u32, lr/sp/pc=u64) are consumed by the
//! header-decode layer; the argtype layer (Phase 1+) consumes the rest. This
//! module provides a low-level cursor that yields raw `[index] -> &[u8]` slices
//! plus typed helpers, leaving interpretation to higher layers.

use anyhow::{anyhow, Result};

/// Low-level TLV cursor over the args blob.
///
/// Construct with [`ArgsCursor::new`] (the slice is everything after the
/// 56-byte `EventContext` header). Each [`Self::next_raw_borrow`] /
/// [`Self::next_length_prefixed`] / [`Self::next_bytes`] consumes one entry.
/// There is no requirement that all entries share a shape — the eBPF
/// programs interleave fixed and variable entries; callers consume them in the
/// order the kernel wrote them (sysno, lr, sp, pc, then argtype-driven args).
pub struct ArgsCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> std::fmt::Debug for ArgsCursor<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArgsCursor")
            .field("remaining", &self.buf.len().saturating_sub(self.pos))
            .field("pos", &self.pos)
            .finish()
    }
}

impl<'a> ArgsCursor<'a> {
    /// Wrap the args blob (the bytes after `EventContext`).
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Consume a `save_to_submit_buf` entry without copying: returns the index
    /// and a slice of the remaining blob of length `n`.
    pub fn next_raw_borrow(&mut self, n: usize) -> Result<(u8, &'a [u8])> {
        let index = self.read_u8()?;
        let data = self.read_bytes(n)?;
        Ok((index, data))
    }

    /// Consume `n` raw bytes with no index byte in front.
    ///
    /// Exists for the userspace parse layer, which mirrors Go's `binary.Read`
    /// on an `Arg_struct`/`Arg_reg`: those readers consume the *fixed* struct
    /// size, not the declared length. See [`crate::argtype::parse`].
    pub fn next_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.read_bytes(n)
    }

    /// Read an `Arg_str` header (`[u8 index][u32 len]`, 5 bytes) and return
    /// `(index, len)` without consuming any payload. Go reads the same header
    /// through `binary.Read(buf, &Arg_str{})`.
    pub fn next_arg_str_header(&mut self) -> Result<(u8, u32)> {
        let index = self.read_u8()?;
        let len = self.read_i32()?;
        Ok((index, len as u32))
    }

    /// Consume a `save_bytes_to_buf` / `save_str_to_buf` entry:
    /// `[u8 index][i32 size][bytes; size]`. Returns the index, the declared
    /// size, and the payload slice.
    pub fn next_length_prefixed(&mut self) -> Result<(u8, i32, &'a [u8])> {
        let index = self.read_u8()?;
        let size = self.read_i32()?;
        // The kernel clamps size to MAX_BYTES_ARR_SIZE / MAX_STRING_SIZE, so a
        // negative size should never appear; treat it as empty.
        let n = if size < 0 { 0 } else { size as usize };
        let data = self.read_bytes(n)?;
        Ok((index, size, data))
    }

    // ---- LE primitives ----------------------------------------------------

    fn read_u8(&mut self) -> Result<u8> {
        let b = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| anyhow!("args underflow: u8 at {}", self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_i32(&mut self) -> Result<i32> {
        let data = self.read_bytes(4)?;
        Ok(i32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        // checked_add: on 32-bit, `pos + n` could wrap around and pass the
        // bounds check even though the range is invalid (num-overflow-explicit).
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| anyhow!("args length overflow: pos {} + {}", self.pos, n))?;
        if end > self.buf.len() {
            return Err(anyhow!(
                "args underflow: need {} bytes at {} (len {})",
                n,
                self.pos,
                self.buf.len()
            ));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_entry(index: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![index];
        v.extend_from_slice(payload);
        v
    }

    fn lp_entry(index: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![index];
        v.extend_from_slice(&(payload.len() as i32).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn raw_entry_roundtrip() {
        // sysno (u32) at index 0, lr (u64) at index 1 — as the kernel emits.
        let mut blob = Vec::new();
        blob.extend_from_slice(&raw_entry(0, &63u32.to_le_bytes()));
        blob.extend_from_slice(&raw_entry(1, &0x4000u64.to_le_bytes()));
        let mut c = ArgsCursor::new(&blob);
        let (i0, sysno) = c.next_raw_borrow(4).unwrap();
        assert_eq!(i0, 0);
        assert_eq!(u32::from_le_bytes(sysno.try_into().unwrap()), 63);
        let (i1, lr) = c.next_raw_borrow(8).unwrap();
        assert_eq!(i1, 1);
        assert_eq!(u64::from_le_bytes(lr.try_into().unwrap()), 0x4000);
        // Everything consumed: the next read underflows.
        assert!(c.next_raw_borrow(1).is_err());
    }

    #[test]
    fn length_prefixed_roundtrip() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&lp_entry(4, b"hello world"));
        let mut c = ArgsCursor::new(&blob);
        let (idx, sz, data) = c.next_length_prefixed().unwrap();
        assert_eq!(idx, 4);
        assert_eq!(sz, 11);
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn zero_size_length_prefixed() {
        // save_bytes_to_buf with size==0 still consumes the index+size header.
        let blob = lp_entry(5, &[]);
        let mut c = ArgsCursor::new(&blob);
        let (idx, sz, data) = c.next_length_prefixed().unwrap();
        assert_eq!(idx, 5);
        assert_eq!(sz, 0);
        assert!(data.is_empty());
        // Header consumed; nothing left to read.
        assert!(c.next_length_prefixed().is_err());
    }

    #[test]
    fn interleaved_shapes_consume_in_order() {
        // sysno(raw u32), lr(raw u64), a string(length-prefixed).
        let mut blob = Vec::new();
        blob.extend_from_slice(&raw_entry(0, &63u32.to_le_bytes()));
        blob.extend_from_slice(&raw_entry(1, &0x10u64.to_le_bytes()));
        blob.extend_from_slice(&lp_entry(4, b"path"));
        let mut c = ArgsCursor::new(&blob);
        let _ = c.next_raw_borrow(4).unwrap();
        let _ = c.next_raw_borrow(8).unwrap();
        let (i, _, d) = c.next_length_prefixed().unwrap();
        assert_eq!((i, d), (4, b"path".as_ref()));
        assert!(c.next_length_prefixed().is_err());
    }

    #[test]
    fn underflow_is_error() {
        let blob = [0u8; 2]; // too short for index + i32 size
        let mut c = ArgsCursor::new(&blob);
        // index (1 byte) ok, then i32 needs 4 bytes -> underflow.
        assert!(c.next_length_prefixed().is_err());
    }

    #[test]
    fn read_bytes_overflow_n_returns_err_not_panic() {
        let blob = vec![0u8; 4];
        let mut c = ArgsCursor::new(&blob);
        // `usize::MAX` makes `pos + n` wrap on 32-bit and exceed the buffer on
        // 64-bit; either way it must be Err, never a panic.
        assert!(c.read_bytes(usize::MAX).is_err());
        assert_eq!(c.read_bytes(4).unwrap().len(), 4);
        assert!(c.read_bytes(5).is_err());
    }
}
