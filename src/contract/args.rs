//! TLV args-blob reader for the dev perf payload.
//!
//! After the fixed 56-byte `EventContext` header, a perf record carries a
//! variable-length **TLV (tag-length-value) args blob** produced by the eBPF
//! helper functions in `ebpf/common/buffer.h`. Each appended arg starts with a
//! `u8 index` (the positional arg slot) and one of three payload encodings:
//!
//! | writer (C)            | on-wire shape                  | used for                |
//! |-----------------------|--------------------------------|-------------------------|
//! | `save_to_submit_buf`  | `[index][raw bytes]`           | regs, sysno, fixed nums |
//! | `save_bytes_to_buf`   | `[index][i32 size][bytes]`     | buffers, structs, utf16 |
//! | `save_str_to_buf`     | `[index][i32 size][bytes]`     | ASCII strings           |
//! | `save_str_arr_to_buf` | `[index][u8 count]{[i32 sz][str]...}` | argv/envp           |
//!
//! For the length-prefixed forms, a `size` of `STRARR_MAGIC_LEN = 0xffff0000`
//! marks a truncated string-array element (the reader stops iterating that
//! array's elements at that point).
//!
//! The reader does NOT know each arg's expected width on its own — the fixed
//! `save_to_submit_buf` entries (sysno=u32, lr/sp/pc=u64) are consumed by the
//! header-decode layer; the argtype layer (Phase 1+) consumes the rest. This
//! module provides a low-level cursor that yields raw `[index] -> &[u8]` slices
//! plus typed helpers, leaving interpretation to higher layers.

use crate::contract::consts::STRARR_MAGIC_LEN;
use anyhow::{anyhow, Result};

/// One decoded TLV arg: the index slot plus the raw payload bytes (after the
/// index byte and any length prefix). The original writer is recoverable from
/// the shape, but here we keep it minimal: callers know their expected shape.
#[derive(Debug, Clone)]
pub struct ArgEntry<'a> {
    /// The positional arg index (the `[u8 index]` byte).
    pub index: u8,
    /// Raw payload bytes following the index (and any length prefix).
    pub data: &'a [u8],
}

/// The three on-wire shapes a TLV entry can take. Mirrors the writers in
/// `ebpf/common/buffer.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgShape {
    /// `save_to_submit_buf`: `[index][raw bytes]`. No length prefix; the byte
    /// count is fixed by the arg's type (caller-supplied).
    Raw,
    /// `save_bytes_to_buf` / `save_str_to_buf` / `save_utf16_to_buf`:
    /// `[index][i32 size][bytes]`.
    LengthPrefixed,
    /// `save_str_arr_to_buf`: `[index][u8 count]{[i32 sz][str]...}`.
    StringArray,
}

/// A decoded string-array element. `size == STRARR_MAGIC_LEN` means truncated.
#[derive(Debug, Clone)]
pub struct StrArrElem<'a> {
    pub size: i32,
    pub bytes: &'a [u8],
    pub truncated: bool,
}

/// Low-level TLV cursor over the args blob.
///
/// Construct with [`ArgsCursor::new`] (the slice is everything after the
/// 56-byte `EventContext` header). Each [`Self::next_raw`] /
/// [`Self::next_length_prefixed`] / [`Self::next_string_array`] consumes one
/// entry. There is no requirement that all entries share a shape — the eBPF
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

    /// Current byte offset (for diagnostics).
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes remaining unread.
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// True if the whole blob has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Consume a `save_to_submit_buf` entry: `[u8 index][raw bytes; n]`.
    ///
    /// `n` is the fixed byte count the caller expects for this index (e.g. 4
    /// for sysno, 8 for a register). Returns the index and the `n` bytes.
    pub fn next_raw(&mut self, n: usize) -> Result<ArgEntry<'a>> {
        let index = self.read_u8()?;
        let data = self.read_bytes(n)?;
        Ok(ArgEntry { index, data })
    }

    /// Consume a `save_to_submit_buf` entry without copying: returns the index
    /// and a slice of the remaining blob of length `n`.
    pub fn next_raw_borrow(&mut self, n: usize) -> Result<(u8, &'a [u8])> {
        let index = self.read_u8()?;
        let data = self.read_bytes(n)?;
        Ok((index, data))
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

    /// Consume a `save_str_arr_to_buf` entry: `[u8 index][u8 count]` followed
    /// by `count` elements of `[i32 sz][bytes; sz]`. An element whose `sz` is
    /// `STRARR_MAGIC_LEN` is truncated and ends iteration early.
    pub fn next_string_array(&mut self) -> Result<(u8, Vec<StrArrElem<'a>>)> {
        let index = self.read_u8()?;
        let count = self.read_u8()?;
        let mut elems = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let sz = self.read_i32()?;
            if (sz as u32) == STRARR_MAGIC_LEN {
                // Truncated element: the kernel writes the magic and stops.
                elems.push(StrArrElem {
                    size: sz,
                    bytes: &[],
                    truncated: true,
                });
                break;
            }
            let n = if sz < 0 { 0 } else { sz as usize };
            let bytes = self.read_bytes(n)?;
            elems.push(StrArrElem {
                size: sz,
                bytes,
                truncated: false,
            });
        }
        Ok((index, elems))
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
        if self.pos + n > self.buf.len() {
            return Err(anyhow!(
                "args underflow: need {} bytes at {} (len {})",
                n,
                self.pos,
                self.buf.len()
            ));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
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

    fn sa_entry(index: u8, elems: &[&[u8]]) -> Vec<u8> {
        let mut v = vec![index, elems.len() as u8];
        for e in elems {
            v.extend_from_slice(&(e.len() as i32).to_le_bytes());
            v.extend_from_slice(e);
        }
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
        assert!(c.is_empty());
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
        assert!(c.is_empty());
    }

    #[test]
    fn string_array_roundtrip() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&sa_entry(7, &[b"/bin/sh", b"-c", b"ls"]));
        let mut c = ArgsCursor::new(&blob);
        let (idx, elems) = c.next_string_array().unwrap();
        assert_eq!(idx, 7);
        assert_eq!(elems.len(), 3);
        assert_eq!(elems[0].bytes, b"/bin/sh");
        assert_eq!(elems[1].bytes, b"-c");
        assert_eq!(elems[2].bytes, b"ls");
        assert!(!elems[0].truncated);
    }

    #[test]
    fn string_array_stops_at_truncated_element() {
        // Kernel writes the STRARR_MAGIC_LEN as the size of a truncated tail
        // element. The reader must stop and mark it truncated.
        let mut blob = vec![8u8, 3]; // index=8, count=3
        blob.extend_from_slice(&7i32.to_le_bytes());
        blob.extend_from_slice(b"/bin/sh");
        blob.extend_from_slice(&STRARR_MAGIC_LEN.to_le_bytes());
        // no further bytes (the magic terminates the array)
        let mut c = ArgsCursor::new(&blob);
        let (idx, elems) = c.next_string_array().unwrap();
        assert_eq!(idx, 8);
        assert_eq!(elems.len(), 2);
        assert_eq!(elems[0].bytes, b"/bin/sh");
        assert!(elems[1].truncated);
    }

    #[test]
    fn interleaved_shapes_consume_in_order() {
        // sysno(raw u32), lr(raw u64), a string(length-prefixed), an argv(array).
        let mut blob = Vec::new();
        blob.extend_from_slice(&raw_entry(0, &63u32.to_le_bytes()));
        blob.extend_from_slice(&raw_entry(1, &0x10u64.to_le_bytes()));
        blob.extend_from_slice(&lp_entry(4, b"path"));
        blob.extend_from_slice(&sa_entry(5, &[b"a", b"b"]));
        let mut c = ArgsCursor::new(&blob);
        let _ = c.next_raw_borrow(4).unwrap();
        let _ = c.next_raw_borrow(8).unwrap();
        let (i, _, d) = c.next_length_prefixed().unwrap();
        assert_eq!((i, d), (4, b"path".as_ref()));
        let (i, e) = c.next_string_array().unwrap();
        assert_eq!(i, 5);
        assert_eq!(e.len(), 2);
        assert!(c.is_empty());
    }

    #[test]
    fn underflow_is_error() {
        let blob = [0u8; 2]; // too short for index + i32 size
        let mut c = ArgsCursor::new(&blob);
        // index (1 byte) ok, then i32 needs 4 bytes -> underflow.
        assert!(c.next_length_prefixed().is_err());
    }
}
