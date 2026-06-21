//! Common event header decode. Mirrors `ContextEvent` (`event_context.go`).
//!
//! On-wire common header (little-endian), decoded in this exact order
//! (`ContextEvent.Decode`, `event_context.go:49-66`):
//!   u32  sample_size   // perf record's "size" field (header, often ignored)
//!   u32  pid
//!   u32  tid
//!   u64  timestamp_ns
//!   char comm[16]      // TASK_COMM_LEN

use super::ievent::{read_bytes, read_u32, read_u64};
use super::{RegsBuf, UnwindBuf, COMM_LEN};
use anyhow::Result;

/// Decoded common header from a perf record. Mirrors the field set of
/// `ContextEvent` (`event_context.go`).
#[derive(Debug, Clone, Default)]
pub struct ContextEvent {
    pub sample_size: u32,
    pub pid: u32,
    pub tid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; COMM_LEN],
    /// Parsed if `unwind_stack` was requested.
    pub unwind: Option<UnwindBuf>,
    /// Parsed if only `show_regs` was requested.
    pub regs_only: Option<RegsBuf>,
}

impl ContextEvent {
    /// Decode the common header, then the optional UnwindBuf / RegsBuf based
    /// on the capture flags. Mirrors `ContextEvent.Decode()` +
    /// `ParseContextStack()` (`event_context.go`).
    pub fn decode(
        raw: &[u8],
        unwind_stack: bool,
        show_regs: bool,
        pos: &mut usize,
    ) -> Result<Self> {
        let sample_size = read_u32(raw, pos)?;
        let pid = read_u32(raw, pos)?;
        let tid = read_u32(raw, pos)?;
        let timestamp_ns = read_u64(raw, pos)?;
        let comm = {
            let mut c = [0u8; COMM_LEN];
            let v = read_bytes(raw, pos, COMM_LEN)?;
            c.copy_from_slice(&v);
            c
        };

        let mut evt = ContextEvent { sample_size, pid, tid, timestamp_ns, comm, unwind: None, regs_only: None };

        if unwind_stack {
            evt.unwind = Some(UnwindBuf::parse(raw, pos)?);
        } else if show_regs {
            evt.regs_only = Some(RegsBuf::parse(raw, pos)?);
        }
        Ok(evt)
    }

    /// `[pid|tid|comm]` UUID string. Mirrors `ContextEvent.GetUUID()`
    /// (`event_context.go:99`). `comm` is null/space-trimmed (`B2STrim`).
    pub fn uuid(&self) -> String {
        format!("[{}|{}|{}]", self.pid, self.tid, b2s_trim(&self.comm))
    }

    /// Selected register dump (from UnwindBuf or RegsBuf), as the JSON block
    /// appended after `, Regs:` in the event output. Mirrors
    /// `ContextEvent.GetStackTrace()` register formatting
    /// (`event_context.go`). Keys: x0..x29, lr, sp, pc.
    pub fn regs_json(&self) -> Option<String> {
        let regs = self.unwind.as_ref().map(|u| &u.regs).or_else(|| self.regs_only.as_ref().map(|r| &r.regs))?;
        Some(regs_to_json(regs))
    }
}

/// Trim trailing NULs and spaces from a byte slice, returning a UTF-8 string.
/// Mirrors `util.B2STrim`.
pub fn b2s_trim(bytes: &[u8]) -> String {
    let end = bytes.iter().rposition(|&b| b != 0 && b != b' ').map(|i| i + 1).unwrap_or(0);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Format 33 arm64 register values as a JSON object.
/// Keys in order: `x0..x29`, `lr`, `sp`, `pc` (values are hex strings).
/// Mirrors the JSON map built in `GetStackTrace`.
pub fn regs_to_json(regs: &[u64]) -> String {
    let mut s = String::from("{");
    for (i, val) in regs.iter().take(30).enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("\"x{}\":\"0x{:x}\"", i, val));
    }
    // regs[30]=lr, regs[31]=sp, regs[32]=pc
    s.push_str(&format!(",\"lr\":\"0x{:x}\"", regs[30]));
    s.push_str(&format!(",\"sp\":\"0x{:x}\"", regs[31]));
    s.push_str(&format!(",\"pc\":\"0x{:x}\"", regs[32]));
    s.push('}');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(pid: u32, tid: u32, ts: u64, comm: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&8u32.to_le_bytes()); // sample_size
        b.extend_from_slice(&pid.to_le_bytes());
        b.extend_from_slice(&tid.to_le_bytes());
        b.extend_from_slice(&ts.to_le_bytes());
        let mut comm_buf = [0u8; COMM_LEN];
        let cb = comm.as_bytes();
        let n = cb.len().min(COMM_LEN);
        comm_buf[..n].copy_from_slice(&cb[..n]);
        b.extend_from_slice(&comm_buf);
        b
    }

    #[test]
    fn decode_header_only() {
        let bytes = header_bytes(1234, 5678, 0xCAFEBABE, "myproc");
        let mut pos = 0;
        let evt = ContextEvent::decode(&bytes, false, false, &mut pos).unwrap();
        assert_eq!(evt.pid, 1234);
        assert_eq!(evt.tid, 5678);
        assert_eq!(evt.timestamp_ns, 0xCAFEBABE);
        assert_eq!(b2s_trim(&evt.comm), "myproc");
        assert!(evt.unwind.is_none());
        assert!(evt.regs_only.is_none());
    }

    #[test]
    fn uuid_format() {
        let mut bytes = header_bytes(1, 2, 0, "app\x00\x00");
        // intentionally no extra fields
        let _ = &mut bytes;
        let mut pos = 0;
        let evt = ContextEvent::decode(&bytes, false, false, &mut pos).unwrap();
        assert_eq!(evt.uuid(), "[1|2|app]");
    }

    #[test]
    fn decode_with_unwind_buf() {
        let mut bytes = header_bytes(1, 2, 3, "x");
        // append a minimal UnwindBuf
        bytes.extend_from_slice(&1u64.to_le_bytes()); // abi
        bytes.extend_from_slice(&[0u8; 33 * 8]); // regs (zeroed)
        bytes.extend_from_slice(&0u64.to_le_bytes()); // stack_size = 0 (no data)
        bytes.extend_from_slice(&0u64.to_le_bytes()); // dyn_size
        let mut pos = 0;
        let evt = ContextEvent::decode(&bytes, true, false, &mut pos).unwrap();
        assert!(evt.unwind.is_some());
        assert!(evt.regs_only.is_none());
    }

    #[test]
    fn regs_json_key_order() {
        let mut regs = [0u64; 33];
        for (i, r) in regs.iter_mut().enumerate() {
            *r = i as u64;
        }
        let j = regs_to_json(&regs);
        assert!(j.starts_with("{\"x0\":\"0x0\""));
        assert!(j.contains("\"x29\":\"0x1d\""));
        assert!(j.contains("\"lr\":\"0x1e\""));
        assert!(j.contains("\"sp\":\"0x1f\""));
        assert!(j.contains("\"pc\":\"0x20\""));
        assert!(j.ends_with('}'));
    }

    #[test]
    fn b2s_trim_trims_nulls_and_spaces() {
        assert_eq!(b2s_trim(b"hello\x00\x00"), "hello");
        assert_eq!(b2s_trim(b"hi  "), "hi");
        assert_eq!(b2s_trim(b"\x00\x00"), "");
    }
}
