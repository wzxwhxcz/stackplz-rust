//! Integration tests asserting the cross-cutting contracts that must hold for
//! the rewrite to be byte-compatible with the upstream Go + eBPF C code.
//!
//! These are platform-independent (no libbpf-rs) and run on any host.

use stackplz::config::sconfig::parse_tid_blacklist;
use stackplz::config::{
    ProbeConfig, SConfig, StackFilter, SyscallFilter, MAX_TID_BLACKLIST_COUNT,
};
use stackplz::config::hook_json::{hex2int, HookConfig};
use stackplz::event::context::{b2s_trim, regs_to_json};
use stackplz::event::{ContextEvent, LibArg, UnwindBuf};

// ---- filter_t byte-layout contract (mirrors C `struct filter_t`) -----------

#[test]
fn stack_filter_is_exactly_32_bytes() {
    assert_eq!(std::mem::size_of::<StackFilter>(), 32);
}

#[test]
fn syscall_filter_is_exactly_36_bytes() {
    assert_eq!(std::mem::size_of::<SyscallFilter>(), 36);
}

#[test]
fn stack_filter_serializes_little_endian() {
    let f = StackFilter {
        uid: 0xDEADBEEF,
        pid: 0x11223344,
        tid_blacklist_mask: 5,
        tid_blacklist: [1, 2, 3, 4, 5],
    };
    let bytes = bytemuck::bytes_of(&f);
    assert_eq!(&bytes[0..4], 0xDEADBEEFu32.to_le_bytes());
    assert_eq!(&bytes[4..8], 0x11223344u32.to_le_bytes());
    assert_eq!(&bytes[8..12], 5u32.to_le_bytes());
    // 5 * 4 = 20 bytes of blacklist follow at offset 12.
    assert_eq!(
        &bytes[12..32],
        [1u32, 2, 3, 4, 5]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>()
    );
}

#[test]
fn syscall_filter_has_nr_at_offset_8() {
    let f = SyscallFilter {
        uid: 0,
        pid: 0,
        nr: 63,
        tid_blacklist_mask: 0,
        tid_blacklist: [0; MAX_TID_BLACKLIST_COUNT],
    };
    let bytes = bytemuck::bytes_of(&f);
    assert_eq!(&bytes[8..12], 63u32.to_le_bytes());
}

#[test]
fn lib_arg_is_288_bytes() {
    // 1 + 33 + 1 + 1 = 36 u64 fields, no padding => 288 bytes.
    assert_eq!(std::mem::size_of::<LibArg>(), 288);
}

// ---- tid blacklist mask contract (mirrors root.go:81-92) ------------------

#[test]
fn tid_blacklist_mask_is_positional_bits() {
    let (arr, mask) = parse_tid_blacklist("10,20,30,40,50").unwrap();
    assert_eq!(arr, [10, 20, 30, 40, 50]);
    assert_eq!(mask, 0b11111);
}

#[test]
fn tid_blacklist_max_five() {
    assert!(parse_tid_blacklist("1,2,3,4,5,6").is_err());
}

// ---- probe config contract (mirrors config_hook.go Check) -----------------

#[test]
fn probe_config_offset_only_fills_random_symbol() {
    let lib = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let mut p = ProbeConfig {
        sconfig: SConfig::default(),
        lib_name: String::new(),
        library: lib.into(),
        symbol: String::new(),
        offset: 0x1000,
    };
    assert!(p.check().is_ok());
    assert_eq!(p.symbol.len(), 8);
}

#[test]
fn probe_config_needs_symbol_xor_offset() {
    let lib = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let mut neither = ProbeConfig {
        sconfig: SConfig::default(),
        lib_name: String::new(),
        library: lib.into(),
        symbol: String::new(),
        offset: 0,
    };
    assert!(neither.check().is_err());
    let mut both = ProbeConfig {
        sconfig: SConfig::default(),
        lib_name: String::new(),
        library: lib.into(),
        symbol: "open".into(),
        offset: 0x100,
    };
    assert!(both.check().is_err());
}

// ---- config.json contract (mirrors cli/cmd/stack.go parseConfig) ----------

#[test]
fn parse_shipped_config_json() {
    let json = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.json")).unwrap();
    let cfg: HookConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg.libs.len(), 2);
    assert_eq!(cfg.libs[0].library, "bionic/libc.so");
    assert_eq!(cfg.libs[0].configs[0].symbols, vec!["open"]);
    assert_eq!(cfg.libs[1].configs[0].offsets, vec!["0xF37C"]);
    assert_eq!(hex2int("0xF37C"), 0xF37C);
}

// ---- event decode contract (mirrors event_context.go / ievent.go) ---------

#[test]
fn uuid_format_matches_go() {
    let mut comm = [0u8; 16];
    comm[..3].copy_from_slice(b"app");
    let evt = ContextEvent {
        sample_size: 0,
        pid: 1,
        tid: 2,
        timestamp_ns: 0,
        comm,
        unwind: None,
        regs_only: None,
    };
    assert_eq!(evt.uuid(), "[1|2|app]");
}

#[test]
fn regs_json_keys_match_go_order() {
    let mut regs = [0u64; 33];
    for (i, r) in regs.iter_mut().enumerate() {
        *r = i as u64;
    }
    let j = regs_to_json(&regs);
    // Order must be x0..x29, lr, sp, pc.
    assert!(j.contains("\"x0\":\"0x0\""));
    assert!(j.contains("\"x29\":\"0x1d\""));
    assert!(j.contains("\"lr\":\"0x1e\""));
    assert!(j.contains("\"sp\":\"0x1f\""));
    assert!(j.contains("\"pc\":\"0x20\""));
}

#[test]
fn unwind_buf_parses_little_endian() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u64.to_le_bytes()); // abi
    bytes.extend_from_slice(&[0u8; 33 * 8]); // regs
    bytes.extend_from_slice(&2u64.to_le_bytes()); // stack_size
    bytes.extend_from_slice(&[0xCA, 0xFE]); // data
    bytes.extend_from_slice(&0x100u64.to_le_bytes()); // dyn_size
    let mut pos = 0;
    let ub = UnwindBuf::parse(&bytes, &mut pos).unwrap();
    assert_eq!(ub.abi, 1);
    assert_eq!(ub.stack_size, 2);
    assert_eq!(ub.data, vec![0xCA, 0xFE]);
    assert_eq!(ub.dyn_size, 0x100);
    assert_eq!(pos, bytes.len());
}

#[test]
fn b2s_trim_matches_go_b2strim() {
    assert_eq!(b2s_trim(b"hello\x00\x00"), "hello");
    assert_eq!(b2s_trim(b"x  "), "x");
    assert_eq!(b2s_trim(b"\x00"), "");
}

// ===========================================================================
// dev-branch contract layer (src/contract/*)
//
// These assert the #[repr(C)] layout of every on-wire / in-map struct and the
// TLV/perf-record decode against the dev-branch eBPF C sources (ebpf/*.h,
// ebpf/{stack,syscall}.c). Platform-independent.
// ===========================================================================

use stackplz::contract::{
    decode_perf_record, ArgFilter, ArgFilterType, ArgsCursor, BufT, CommonFilter, ConfigEntry,
    CtxRegs, EventContext, EventId, MAX_EVENT_SIZE, MAX_OP_COUNT_STACK, MAX_OP_COUNT_SYSCALL,
    OpCode, PerfRecord, StackPointArgs, STRARR_MAGIC_LEN, SyscallPointArgs,
};

// ---- dev #[repr(C)] struct sizes (mirror ebpf/types.h) --------------------

#[test]
fn dev_event_context_is_56_bytes() {
    assert_eq!(std::mem::size_of::<EventContext>(), 56);
}

#[test]
fn dev_common_filter_is_20_bytes() {
    assert_eq!(std::mem::size_of::<CommonFilter>(), 20);
}

#[test]
fn dev_config_entry_is_8_bytes() {
    assert_eq!(std::mem::size_of::<ConfigEntry>(), 8);
}

#[test]
fn dev_arg_filter_is_272_bytes() {
    assert_eq!(std::mem::size_of::<ArgFilter>(), 272);
}

#[test]
fn dev_ctx_regs_is_272_bytes() {
    assert_eq!(std::mem::size_of::<CtxRegs>(), 272);
}

#[test]
fn dev_point_args_sizes_match_module_defines() {
    // MAX_OP_COUNT is 64 under __MODULE_STACK, 256 under __MODULE_SYSCALL.
    assert_eq!(MAX_OP_COUNT_STACK, 64);
    assert_eq!(MAX_OP_COUNT_SYSCALL, 256);
    // sizeof = 12 + 4*N.
    assert_eq!(
        std::mem::size_of::<StackPointArgs>(),
        12 + 4 * MAX_OP_COUNT_STACK
    );
    assert_eq!(
        std::mem::size_of::<SyscallPointArgs>(),
        12 + 4 * MAX_OP_COUNT_SYSCALL
    );
}

#[test]
fn dev_buf_t_is_32k() {
    assert_eq!(std::mem::size_of::<BufT>(), 32768);
}

#[test]
fn dev_max_event_size_is_header_plus_args_buf() {
    // MAX_EVENT_SIZE = sizeof(event_context_t) + ARGS_BUF_SIZE = 56 + 32000.
    assert_eq!(MAX_EVENT_SIZE, 56 + 32000);
}

// ---- dev enums (mirror ebpf/types.h enums) --------------------------------

#[test]
fn dev_event_id_values() {
    assert_eq!(EventId::SyscallEnter as u32, 456);
    assert_eq!(EventId::SyscallExit as u32, 457);
    assert_eq!(EventId::UprobeEnter as u32, 458);
}

#[test]
fn dev_op_code_numbering() {
    assert_eq!(OpCode::Skip as u32, 233);
    assert_eq!(OpCode::SaveStruct as u32, 257);
    assert_eq!(OpCode::SavePtrString16 as u32, 266);
}

#[test]
fn dev_arg_filter_type_range() {
    assert_eq!(ArgFilterType::Unknown as u32, 0);
    assert_eq!(ArgFilterType::Replace as u32, 6);
}

// ---- dev perf-record decode (mirror stack.c / syscall.c emit order) -------

fn dev_header(eventid: u32) -> EventContext {
    let mut comm = [0u8; 16];
    comm[..3].copy_from_slice(b"app");
    EventContext {
        ts: 1,
        eventid,
        host_tid: 10,
        host_pid: 20,
        tid: 30,
        pid: 40,
        uid: 50,
        comm,
        argnum: 4,
        padding: [0; 7],
    }
}

fn dev_raw_u32(idx: u8, v: u32) -> Vec<u8> {
    let mut b = vec![idx];
    b.extend_from_slice(&v.to_le_bytes());
    b
}

fn dev_raw_u64(idx: u8, v: u64) -> Vec<u8> {
    let mut b = vec![idx];
    b.extend_from_slice(&v.to_le_bytes());
    b
}

fn dev_record(ctx: &EventContext, args: &[u8]) -> Vec<u8> {
    let mut v = bytemuck::bytes_of(ctx).to_vec();
    v.extend_from_slice(args);
    v
}

#[test]
fn dev_decode_syscall_enter_prefix() {
    let ctx = dev_header(456);
    let mut args = Vec::new();
    args.extend_from_slice(&dev_raw_u32(0, 63)); // sysno
    args.extend_from_slice(&dev_raw_u64(1, 0x4000)); // lr
    args.extend_from_slice(&dev_raw_u64(2, 0x5000)); // sp
    args.extend_from_slice(&dev_raw_u64(3, 0x6000)); // pc
    let raw = dev_record(&ctx, &args);
    match decode_perf_record(&raw).unwrap() {
        PerfRecord::SyscallEnter(e) => {
            assert_eq!(e.sysno, 63);
            assert_eq!(e.lr, 0x4000);
            assert_eq!(e.sp, 0x5000);
            assert_eq!(e.pc, 0x6000);
            assert_eq!(e.context.pid, 40);
            assert!(e.args.is_empty());
        }
        _ => panic!("expected SyscallEnter"),
    }
}

#[test]
fn dev_decode_uprobe_enter_prefix() {
    let ctx = dev_header(458);
    let mut args = Vec::new();
    args.extend_from_slice(&dev_raw_u32(0, 2)); // point_key
    args.extend_from_slice(&dev_raw_u64(1, 0xA));
    args.extend_from_slice(&dev_raw_u64(2, 0xB));
    args.extend_from_slice(&dev_raw_u64(3, 0xC));
    let raw = dev_record(&ctx, &args);
    match decode_perf_record(&raw).unwrap() {
        PerfRecord::UprobeEnter(e) => {
            assert_eq!(e.point_key, 2);
            assert_eq!(e.pc, 0xC);
        }
        _ => panic!("expected UprobeEnter"),
    }
}

#[test]
fn dev_decode_syscall_exit_has_no_lr_sp_pc() {
    // sys_exit emits only sysno + args + return value (no lr/sp/pc prefix).
    let ctx = dev_header(457);
    let args = dev_raw_u32(0, 221);
    let raw = dev_record(&ctx, &args);
    match decode_perf_record(&raw).unwrap() {
        PerfRecord::SyscallExit(e) => {
            assert_eq!(e.sysno, 221);
            assert!(e.args.is_empty());
        }
        _ => panic!("expected SyscallExit"),
    }
}

#[test]
fn dev_decode_rejects_unknown_eventid() {
    let ctx = dev_header(123);
    let raw = dev_record(&ctx, &[]);
    assert!(decode_perf_record(&raw).is_err());
}

#[test]
fn dev_decode_rejects_short_record() {
    assert!(decode_perf_record(&[0u8; 10]).is_err());
}

// ---- dev TLV args cursor (mirror ebpf/common/buffer.h writers) ------------

#[test]
fn dev_tlv_length_prefixed_string() {
    // save_str_to_buf: [idx][i32 size][bytes]
    let mut blob = vec![4u8]; // index
    blob.extend_from_slice(&5i32.to_le_bytes()); // size
    blob.extend_from_slice(b"hello");
    let mut c = ArgsCursor::new(&blob);
    let (idx, sz, data) = c.next_length_prefixed().unwrap();
    assert_eq!(idx, 4);
    assert_eq!(sz, 5);
    assert_eq!(data, b"hello");
}

#[test]
fn dev_tlv_string_array_with_truncation() {
    // save_str_arr_to_buf: [idx][u8 count]{[i32 sz][str]} with a truncated
    // tail element carrying STRARR_MAGIC_LEN.
    let mut blob = vec![7u8, 3]; // index, count
    blob.extend_from_slice(&3i32.to_le_bytes());
    blob.extend_from_slice(b"abc");
    blob.extend_from_slice(&STRARR_MAGIC_LEN.to_le_bytes());
    let mut c = ArgsCursor::new(&blob);
    let (idx, elems) = c.next_string_array().unwrap();
    assert_eq!(idx, 7);
    assert_eq!(elems.len(), 2);
    assert_eq!(elems[0].bytes, b"abc");
    assert!(elems[1].truncated);
}

#[test]
fn dev_strarr_magic_value() {
    assert_eq!(STRARR_MAGIC_LEN, 0xffff_0000);
}
