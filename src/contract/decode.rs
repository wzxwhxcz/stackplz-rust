//! High-level perf-record decoder for the dev payload.
//!
//! A perf record on the wire is:
//!   `[EventContext: 56 bytes][args blob: record.len - 56 bytes]`
//!
//! The args blob is a TLV stream whose layout depends on which eBPF program
//! emitted the record (`event_context.eventid`). This module parses the fixed
//! prefix common to all programs and exposes the remaining TLV args via an
//! [`ArgsCursor`] for the argtype layer (Phase 1+) to consume type-aware.
//!
//! Fixed prefix emitted by the kernel programs (see `stack.c` /
//! `syscall.c`):
//!
//! - **SYSCALL_ENTER** (`syscall.c::raw_syscalls_sys_enter`):
//!     - idx 0: `u32 sysno`
//!     - idx 1: `u64 lr`      (arm64: regs[30]; arm32: regs[14])
//!     - idx 2: `u64 sp`      (arm64: regs.sp;  arm32: regs[13])
//!     - idx 3: `u64 pc`      (regs.pc)
//!     - idx 4..: argtype-driven args
//!
//! - **SYSCALL_EXIT** (`syscall.c::raw_syscalls_sys_exit`):
//!     - idx 0: `u32 sysno`
//!     - idx 1..: argtype-driven args (no lr/sp/pc on exit)
//!     - the return value is written at `op_ctx.save_index` (1 + #args); it is
//!       recovered here as a trailing raw `u64` once all configured args are
//!       consumed.
//!
//! - **UPROBE_ENTER** (`stack.c::probe_stack_warp`):
//!     - idx 0: `u32 point_key`
//!     - idx 1: `u64 lr`
//!     - idx 2: `u64 sp`
//!     - idx 3: `u64 pc`
//!     - idx 4..: argtype-driven args
//!
//! The argtype layer will pull idx 4+; until then, [`SyscallEnterEvent`] etc.
//! expose the parsed prefix plus a cursor positioned at the first argtype arg.

use crate::contract::args::ArgsCursor;
use crate::contract::enums::EventId;
use crate::contract::types::EventContext;
use anyhow::{anyhow, Result};

/// Size of the fixed `EventContext` header (mirrors `sizeof(event_context_t)`).
pub const EVENT_CONTEXT_SIZE: usize = 56;

/// The decoded perf record: the common header plus the program-specific view.
#[derive(Debug)]
pub enum PerfRecord<'a> {
    SyscallEnter(SyscallEnterEvent<'a>),
    SyscallExit(SyscallExitEvent<'a>),
    UprobeEnter(UprobeEnterEvent<'a>),
}

/// Common header carried by every record variant.
pub trait HasContext {
    fn context(&self) -> &EventContext;
}

/// `SYSCALL_ENTER` (eventid 456).
#[derive(Debug)]
pub struct SyscallEnterEvent<'a> {
    pub context: EventContext,
    pub sysno: u32,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    /// Cursor over the remaining TLV args (idx 4+), for the argtype layer.
    pub args: ArgsCursor<'a>,
}

/// `SYSCALL_EXIT` (eventid 457).
#[derive(Debug)]
pub struct SyscallExitEvent<'a> {
    pub context: EventContext,
    pub sysno: u32,
    /// Cursor over the TLV args (idx 1+). The return value sits at the end at
    /// `op_ctx.save_index`; the argtype layer knows how many args precede it.
    pub args: ArgsCursor<'a>,
}

/// `UPROBE_ENTER` (eventid 458).
#[derive(Debug)]
pub struct UprobeEnterEvent<'a> {
    pub context: EventContext,
    pub point_key: u32,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    /// Cursor over the remaining TLV args (idx 4+).
    pub args: ArgsCursor<'a>,
}

impl<'a> HasContext for SyscallEnterEvent<'a> {
    fn context(&self) -> &EventContext {
        &self.context
    }
}
impl<'a> HasContext for SyscallExitEvent<'a> {
    fn context(&self) -> &EventContext {
        &self.context
    }
}
impl<'a> HasContext for UprobeEnterEvent<'a> {
    fn context(&self) -> &EventContext {
        &self.context
    }
}
impl<'a> HasContext for PerfRecord<'a> {
    fn context(&self) -> &EventContext {
        match self {
            PerfRecord::SyscallEnter(e) => &e.context,
            PerfRecord::SyscallExit(e) => &e.context,
            PerfRecord::UprobeEnter(e) => &e.context,
        }
    }
}

/// Decode a raw perf record (`bpf_perf_event_output` payload) into the
/// program-specific view.
///
/// The caller passes the full record (header + args). The header is copied out
/// into an owned `EventContext`; the args blob is borrowed for the cursor.
pub fn decode_perf_record(raw: &[u8]) -> Result<PerfRecord<'_>> {
    if raw.len() < EVENT_CONTEXT_SIZE {
        return Err(anyhow!(
            "perf record too short: {} bytes (need >= {})",
            raw.len(),
            EVENT_CONTEXT_SIZE
        ));
    }

    // The header is `#[repr(C)]` Pod; cast the first 56 bytes directly.
    let context: EventContext = *bytemuck::from_bytes(&raw[..EVENT_CONTEXT_SIZE]);
    let args_blob = &raw[EVENT_CONTEXT_SIZE..];

    let eventid = EventId::from_u32(context.eventid)
        .ok_or_else(|| anyhow!("unknown event id {} (not 456/457/458)", context.eventid))?;

    Ok(match eventid {
        EventId::SyscallEnter => {
            let mut c = ArgsCursor::new(args_blob);
            let sysno = read_raw_u32(&mut c, 0)?;
            let lr = read_raw_u64(&mut c, 1)?;
            let sp = read_raw_u64(&mut c, 2)?;
            let pc = read_raw_u64(&mut c, 3)?;
            PerfRecord::SyscallEnter(SyscallEnterEvent {
                context,
                sysno,
                lr,
                sp,
                pc,
                args: c,
            })
        }
        EventId::SyscallExit => {
            let mut c = ArgsCursor::new(args_blob);
            let sysno = read_raw_u32(&mut c, 0)?;
            PerfRecord::SyscallExit(SyscallExitEvent {
                context,
                sysno,
                args: c,
            })
        }
        EventId::UprobeEnter => {
            let mut c = ArgsCursor::new(args_blob);
            let point_key = read_raw_u32(&mut c, 0)?;
            let lr = read_raw_u64(&mut c, 1)?;
            let sp = read_raw_u64(&mut c, 2)?;
            let pc = read_raw_u64(&mut c, 3)?;
            PerfRecord::UprobeEnter(UprobeEnterEvent {
                context,
                point_key,
                lr,
                sp,
                pc,
                args: c,
            })
        }
    })
}

/// Read a fixed `save_to_submit_buf` `u32` entry, asserting its index.
fn read_raw_u32(c: &mut ArgsCursor<'_>, expect_index: u8) -> Result<u32> {
    let (idx, data) = c.next_raw_borrow(4)?;
    if idx != expect_index {
        return Err(anyhow!(
            "syscall/uprobe arg index mismatch: expected {}, got {}",
            expect_index,
            idx
        ));
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(data);
    Ok(u32::from_le_bytes(arr))
}

/// Read a fixed `save_to_submit_buf` `u64` entry, asserting its index.
fn read_raw_u64(c: &mut ArgsCursor<'_>, expect_index: u8) -> Result<u64> {
    let (idx, data) = c.next_raw_borrow(8)?;
    if idx != expect_index {
        return Err(anyhow!(
            "syscall/uprobe arg index mismatch: expected {}, got {}",
            expect_index,
            idx
        ));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(data);
    Ok(u64::from_le_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(eventid: u32, comm: &str) -> EventContext {
        let mut c = [0u8; 16];
        let n = comm.len().min(16);
        c[..n].copy_from_slice(&comm.as_bytes()[..n]);
        EventContext {
            ts: 0x1000,
            eventid,
            host_tid: 1,
            host_pid: 2,
            tid: 3,
            pid: 4,
            uid: 5,
            comm: c,
            argnum: 4,
            padding: [0; 7],
        }
    }

    fn raw_buf(ctx: &EventContext, args: &[u8]) -> Vec<u8> {
        let mut v = bytemuck::bytes_of(ctx).to_vec();
        v.extend_from_slice(args);
        v
    }

    fn raw_u32(idx: u8, v: u32) -> Vec<u8> {
        let mut b = vec![idx];
        b.extend_from_slice(&v.to_le_bytes());
        b
    }

    fn raw_u64(idx: u8, v: u64) -> Vec<u8> {
        let mut b = vec![idx];
        b.extend_from_slice(&v.to_le_bytes());
        b
    }

    #[test]
    fn decode_syscall_enter() {
        let ctx = header(456, "myproc");
        let mut args = Vec::new();
        args.extend_from_slice(&raw_u32(0, 63)); // sysno
        args.extend_from_slice(&raw_u64(1, 0x4000)); // lr
        args.extend_from_slice(&raw_u64(2, 0x5000)); // sp
        args.extend_from_slice(&raw_u64(3, 0x6000)); // pc
        let raw = raw_buf(&ctx, &args);
        let rec = decode_perf_record(&raw).unwrap();
        match rec {
            PerfRecord::SyscallEnter(e) => {
                assert_eq!(e.sysno, 63);
                assert_eq!(e.lr, 0x4000);
                assert_eq!(e.sp, 0x5000);
                assert_eq!(e.pc, 0x6000);
                assert_eq!(e.context.pid, 4);
                assert!(e.args.is_empty()); // no argtype args appended
            }
            _ => panic!("expected SyscallEnter"),
        }
    }

    #[test]
    fn decode_syscall_exit_no_lr_sp_pc() {
        // sys_exit only emits sysno + configured args + return value.
        let ctx = header(457, "myproc");
        let mut args = Vec::new();
        args.extend_from_slice(&raw_u32(0, 221)); // sysno (execve)
                                                  // (return value would be appended by argtype layer at save_index)
        let raw = raw_buf(&ctx, &args);
        let rec = decode_perf_record(&raw).unwrap();
        match rec {
            PerfRecord::SyscallExit(e) => {
                assert_eq!(e.sysno, 221);
                assert!(e.args.is_empty());
            }
            _ => panic!("expected SyscallExit"),
        }
    }

    #[test]
    fn decode_uprobe_enter() {
        let ctx = header(458, "app");
        let mut args = Vec::new();
        args.extend_from_slice(&raw_u32(0, 1)); // point_key
        args.extend_from_slice(&raw_u64(1, 0xA)); // lr
        args.extend_from_slice(&raw_u64(2, 0xB)); // sp
        args.extend_from_slice(&raw_u64(3, 0xC)); // pc
        let raw = raw_buf(&ctx, &args);
        let rec = decode_perf_record(&raw).unwrap();
        match rec {
            PerfRecord::UprobeEnter(e) => {
                assert_eq!(e.point_key, 1);
                assert_eq!(e.lr, 0xA);
                assert_eq!(e.sp, 0xB);
                assert_eq!(e.pc, 0xC);
            }
            _ => panic!("expected UprobeEnter"),
        }
    }

    #[test]
    fn unknown_eventid_is_error() {
        let ctx = header(999, "x");
        let raw = raw_buf(&ctx, &[]);
        assert!(decode_perf_record(&raw).is_err());
    }

    #[test]
    fn truncated_header_is_error() {
        let raw = [0u8; 10];
        assert!(decode_perf_record(&raw).is_err());
    }

    #[test]
    fn argtype_args_remain_in_cursor() {
        // After the fixed prefix, a length-prefixed string arg (idx 4) is left
        // for the argtype layer to consume.
        let ctx = header(456, "p");
        let mut args = Vec::new();
        args.extend_from_slice(&raw_u32(0, 1));
        args.extend_from_slice(&raw_u64(1, 0));
        args.extend_from_slice(&raw_u64(2, 0));
        args.extend_from_slice(&raw_u64(3, 0));
        // idx 4 = length-prefixed string "hi"
        args.push(4);
        args.extend_from_slice(&2i32.to_le_bytes());
        args.extend_from_slice(b"hi");
        let raw = raw_buf(&ctx, &args);
        let rec = decode_perf_record(&raw).unwrap();
        match rec {
            PerfRecord::SyscallEnter(mut e) => {
                let (idx, sz, data) = e.args.next_length_prefixed().unwrap();
                assert_eq!(idx, 4);
                assert_eq!(sz, 2);
                assert_eq!(data, b"hi");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn index_mismatch_is_error() {
        // Kernel emitted sysno at index 0, but pretend we got index 9.
        let ctx = header(456, "p");
        let args = raw_u32(9, 63);
        let raw = raw_buf(&ctx, &args);
        assert!(decode_perf_record(&raw).is_err());
    }
}
