//! Dev-format event rendering (the output layer, report W7).
//!
//! One event is one line, byte-compatible with upstream `dev`'s printed output:
//!
//! - syscall enter: `[pid|tid|comm] name(args) LR:0x.. PC:0x.. SP:0x..`
//! - syscall exit:  `[pid|tid|comm] name(args)`
//! - uprobe enter:  `[pid|tid|comm] name(args) LR:0x.. PC:0x.. SP:0x..`
//!
//! Every `PointArg` starts with one 9-byte `Arg_reg` TLV `[u8 index][u64 value]`
//! (Go's `binary.Read` of `{Index uint8; Address uint64}`: no padding). The
//! value is the register value; the argtype layer then renders it and consumes
//! any type-specific payload TLVs that only exist when the arg is read at this
//! point (`PointArg::read_more`). Mirrors Go `SyscallPoint.ParseEnterPoint` /
//! `ParseExitPoint` (`user/config/config_syscall.go`) and `UprobeEvent`.

use anyhow::{anyhow, bail, Result};

use crate::argtype::parse_point_arg;
use crate::argtype::render::b2s_trim;
use crate::config::point_arg::EBPF_UPROBE_ENTER;
use crate::config::point_arg::{PointArg, UprobeArgs, EBPF_SYS_ENTER, EBPF_SYS_EXIT};
use crate::config::syscall_points::SyscallPointTable;
use crate::contract::args::ArgsCursor;
use crate::contract::decode::{PerfRecord, UprobeEnterEvent};
use crate::contract::types::EventContext;

/// The leading `Arg_reg` TLV is `[u8 index][u64 value]` — 9 bytes on the wire,
/// so the cursor's `next_raw_borrow` (which takes the payload size after the
/// index byte) is asked for 8.
const ARG_REG_VALUE_LEN: usize = 8;

/// `[pid|tid|comm]` — the dev `ContextEvent.GetUUID()`
/// (`user/event/event_context.go:110`) with dev's default flags
/// (`--showtime` / `--showuid` are off, so neither is part of the prefix).
pub fn uuid(ctx: &EventContext) -> String {
    format!("[{}|{}|{}]", ctx.pid, ctx.tid, b2s_trim(&ctx.comm))
}

/// `(name=value, ...)` — Go's `ParseEnterPoint` / `ParseExitPoint`.
///
/// Reads one leading `Arg_reg` per configured argument, then lets the argtype
/// layer parse the rest. `render_point` is `EBPF_SYS_ENTER` / `EBPF_SYS_EXIT`
/// (or `EBPF_UPROBE_ENTER`); `dump_hex` is the global `--dumphex` flag.
pub fn render_point_args(
    args: &[PointArg],
    cur: &mut ArgsCursor<'_>,
    render_point: u32,
    dump_hex: bool,
) -> Result<String> {
    let mut parts = Vec::with_capacity(args.len());
    for pa in args {
        let (_, reg) = cur.next_raw_borrow(ARG_REG_VALUE_LEN)?;
        let ptr = u64::from_le_bytes(reg.try_into().expect("Arg_reg value is 8 bytes"));
        let value = parse_point_arg(pa, ptr, cur, render_point, dump_hex)?;
        parts.push(format!("{}={}", pa.name, value));
    }
    Ok(format!("({})", parts.join(", ")))
}

/// Render one decoded perf record in dev's `SyscallEvent.String()` shape.
///
/// Takes `&mut` because the args cursor is consumed in place.
pub fn render_syscall_event(
    table: &SyscallPointTable,
    rec: &mut PerfRecord<'_>,
    dump_hex: bool,
) -> Result<String> {
    match rec {
        PerfRecord::SyscallEnter(e) => {
            let point = table
                .by_nr(e.sysno)
                .ok_or_else(|| anyhow!("unknown syscall nr:{}", e.sysno))?;
            let args = render_point_args(
                &point.enter_point_args,
                &mut e.args,
                EBPF_SYS_ENTER,
                dump_hex,
            )?;
            Ok(format!(
                "{} {}{} LR:0x{:x} PC:0x{:x} SP:0x{:x}",
                uuid(&e.context),
                point.name,
                args,
                e.lr,
                e.pc,
                e.sp
            ))
        }
        PerfRecord::SyscallExit(e) => {
            let point = table
                .by_nr(e.sysno)
                .ok_or_else(|| anyhow!("unknown syscall nr:{}", e.sysno))?;
            let args =
                render_point_args(&point.exit_point_args, &mut e.args, EBPF_SYS_EXIT, dump_hex)?;
            Ok(format!("{} {}{}", uuid(&e.context), point.name, args))
        }
        // The syscall module loads `syscall.o`, whose map only emits 456/457.
        PerfRecord::UprobeEnter(e) => bail!(
            "uprobe event in the syscall stream (point_key {})",
            e.point_key
        ),
    }
}

/// Render one `UPROBE_ENTER` record against its resolved hook point.
///
/// `dump_hex` is passed as `false`: the uprobe point parser already baked the
/// global flag into every registered argtype (`at.dump_hex`).
pub fn render_uprobe_event(e: &mut UprobeEnterEvent<'_>, point: &UprobeArgs) -> Result<String> {
    let args = render_point_args(&point.point_args, &mut e.args, EBPF_UPROBE_ENTER, false)?;
    Ok(format!(
        "{} {}{} LR:0x{:x} PC:0x{:x} SP:0x{:x}",
        uuid(&e.context),
        point.name,
        args,
        e.lr,
        e.pc,
        e.sp
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::argtype::{get_arg_type_by_name, init_argtypes};
    use crate::contract::decode::decode_perf_record;

    const DEMO_TABLE: &str = r#"{
        "type": "syscall",
        "points": [{
            "nr": 999,
            "name": "demo",
            "params": [
                {"name": "fd", "type": "int"},
                {"name": "path", "type": "str"},
                {"name": "ret", "type": "int"}
            ]
        }]
    }"#;

    fn demo_table() -> SyscallPointTable {
        init_argtypes();
        SyscallPointTable::from_json_str(DEMO_TABLE).expect("test table must parse")
    }

    fn header(eventid: u32, pid: u32, tid: u32, comm: &str) -> EventContext {
        let mut c = [0u8; 16];
        let n = comm.len().min(c.len());
        c[..n].copy_from_slice(&comm.as_bytes()[..n]);
        EventContext {
            ts: 0x1000,
            eventid,
            host_pid: pid,
            host_tid: tid,
            pid,
            tid,
            uid: 5,
            comm: c,
            argnum: 0,
            padding: [0; 7],
        }
    }

    fn record(ctx: &EventContext, args: &[u8]) -> Vec<u8> {
        let mut v = bytemuck::bytes_of(ctx).to_vec();
        v.extend_from_slice(args);
        v
    }

    fn raw_u32(idx: u8, value: u32) -> Vec<u8> {
        let mut v = vec![idx];
        v.extend_from_slice(&value.to_le_bytes());
        v
    }

    /// One leading `Arg_reg` TLV: `[idx][u64 value]`.
    fn reg(idx: u8, value: u64) -> Vec<u8> {
        let mut v = vec![idx];
        v.extend_from_slice(&value.to_le_bytes());
        v
    }

    /// A length-prefixed payload TLV: `[idx][i32 len][bytes]`.
    fn prefixed(idx: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![idx];
        v.extend_from_slice(&(payload.len() as i32).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn syscall_enter_renders_uuid_name_args_and_regs() {
        let table = demo_table();
        let ctx = header(456, 40, 30, "app");
        let mut args = Vec::new();
        args.extend_from_slice(&raw_u32(0, 999)); // sysno
        args.extend_from_slice(&reg(1, 0x4000)); // lr
        args.extend_from_slice(&reg(2, 0x5000)); // sp
        args.extend_from_slice(&reg(3, 0x6000)); // pc
        args.extend_from_slice(&reg(4, 42)); // fd
        args.extend_from_slice(&reg(5, 0xdead_0000)); // path pointer
        args.extend_from_slice(&prefixed(5, b"./x\0")); // path payload
        let raw = record(&ctx, &args);
        let mut rec = decode_perf_record(&raw).unwrap();
        let line = render_syscall_event(&table, &mut rec, false).unwrap();
        assert_eq!(
            line,
            "[40|30|app] demo(fd=42, path=0xdead0000(./x)) LR:0x4000 PC:0x6000 SP:0x5000"
        );
    }

    /// On exit, enter-only args are rendered as their bare register value (the
    /// kernel writes the leading `Arg_reg` but no payload), and `ret` last.
    #[test]
    fn syscall_exit_renders_args_and_ret() {
        let table = demo_table();
        let ctx = header(457, 40, 30, "app");
        let mut args = Vec::new();
        args.extend_from_slice(&raw_u32(0, 999)); // sysno
        args.extend_from_slice(&reg(1, 42)); // fd
        args.extend_from_slice(&reg(2, 0xdead_0000)); // path (pointer only)
        args.extend_from_slice(&reg(3, 7)); // ret (save_index)
        let raw = record(&ctx, &args);
        let mut rec = decode_perf_record(&raw).unwrap();
        let line = render_syscall_event(&table, &mut rec, false).unwrap();
        assert_eq!(line, "[40|30|app] demo(fd=42, path=0xdead0000, ret=7)");
    }

    #[test]
    fn unknown_argtype_is_an_error() {
        let table = demo_table();
        let mut args = table.by_nr(999).unwrap().enter_point_args.clone();
        args[0].type_index = u32::MAX; // never registered
        let blob = reg(4, 42);
        let mut cur = ArgsCursor::new(&blob);
        let err = render_point_args(&args[..1], &mut cur, EBPF_SYS_ENTER, false).unwrap_err();
        assert!(format!("{err:#}").contains("unknown argtype"), "{err:#}");
    }

    #[test]
    fn missing_args_are_an_underflow_error() {
        let table = demo_table();
        let args = &table.by_nr(999).unwrap().enter_point_args;
        let mut cur = ArgsCursor::new(&[]);
        let err = render_point_args(args, &mut cur, EBPF_SYS_ENTER, false).unwrap_err();
        assert!(format!("{err:#}").contains("args underflow"), "{err:#}");
    }

    #[test]
    fn unknown_syscall_number_is_an_error() {
        let table = demo_table();
        let ctx = header(456, 1, 1, "x");
        let mut args = Vec::new();
        args.extend_from_slice(&raw_u32(0, 888));
        args.extend_from_slice(&reg(1, 0));
        args.extend_from_slice(&reg(2, 0));
        args.extend_from_slice(&reg(3, 0));
        let raw = record(&ctx, &args);
        let mut rec = decode_perf_record(&raw).unwrap();
        let err = render_syscall_event(&table, &mut rec, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("unknown syscall nr:888"),
            "{err:#}"
        );
    }

    #[test]
    fn uprobe_enter_renders_point_name_and_args() {
        init_argtypes();
        let ctx = header(458, 40, 30, "app");
        let mut args = Vec::new();
        args.extend_from_slice(&raw_u32(0, 3)); // point_key
        args.extend_from_slice(&reg(1, 0xa)); // lr
        args.extend_from_slice(&reg(2, 0xb)); // sp
        args.extend_from_slice(&reg(3, 0xc)); // pc
        args.extend_from_slice(&reg(4, 42)); // arg_0
        let raw = record(&ctx, &args);
        let rec = decode_perf_record(&raw).unwrap();
        let PerfRecord::UprobeEnter(mut e) = rec else {
            panic!("expected UprobeEnter");
        };
        let mut point = UprobeArgs::new();
        point.name = "myhook".to_string();
        point.point_args.push(PointArg::new_uprobe(
            "arg_0",
            get_arg_type_by_name("int").type_index,
            0,
        ));
        let line = render_uprobe_event(&mut e, &point).unwrap();
        assert_eq!(line, "[40|30|app] myhook(arg_0=42) LR:0xa PC:0xc SP:0xb");
    }
}
