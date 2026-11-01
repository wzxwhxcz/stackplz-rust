//! Regression tests for the eBPF C sources under `ebpf/`.
//!
//! The eBPF C is reused verbatim from upstream `stackplz` (see README), and it
//! is *not* compiled by `cargo build` unless `clang` + `embedded_bpf` are
//! available. That leaves the C side unguarded in normal CI runs and on
//! non-Linux hosts, so these tests assert the source-level contracts that the
//! root-cause fixes depend on. They need no kernel, no root and no device.
//!
//! Every assertion here corresponds to one entry of the fix report
//! (`stackplz-analysis/REPORT.md`): ① architecture gate, ② default-deny
//! filtering, ③ `op_ctx` memset / arm32 bit 22 / `common_list` segment stride.

use std::collections::HashMap;
use std::path::PathBuf;

fn ebpf_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ebpf")
}

fn read_ebpf(rel: &str) -> String {
    let path = ebpf_dir().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Drop `//` and `/* */` comments so assertions target code, not the rationale
/// comments that necessarily mention the removed identifiers.
fn strip_c_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

// ---- ① architecture gate (`_TIF_32BIT` / is32) ------------------------------

/// The `is32` gate used to sit at the very top of `raw_tracepoint/sys_enter` and
/// `sys_exit`, *before* any filtering and before any event submission. On arm64
/// it dropped every AArch32 (32-bit) target process silently; on arm32 it
/// dropped everything because bit 22 is always 0 there. Master has no such gate.
#[test]
fn syscall_c_has_no_arch_gate() {
    let src = strip_c_comments(&read_ebpf("syscall.c"));
    for forbidden in [
        "_TIF_32BIT",
        "is32",
        "thread_info.flags",
        "__TARGET_ARCH_arm",
    ] {
        assert!(
            !src.contains(forbidden),
            "ebpf/syscall.c must not gate on {forbidden:?}: it silently drops \
             AArch32 targets on arm64 and every target on arm32"
        );
    }
}

/// Both raw tracepoints must exist and take `should_trace()` as their first
/// filter, i.e. the removed gate was not replaced by another early exit.
#[test]
fn syscall_c_keeps_both_tracepoints_behind_should_trace() {
    let src = read_ebpf("syscall.c");
    assert_eq!(
        src.matches("SEC(\"raw_tracepoint/sys_enter\")").count(),
        1,
        "sys_enter program missing"
    );
    assert_eq!(
        src.matches("SEC(\"raw_tracepoint/sys_exit\")").count(),
        1,
        "sys_exit program missing"
    );
    // One should_trace() call per raw tracepoint program.
    assert_eq!(
        src.matches("if (!should_trace(&p))").count(),
        2,
        "each tracepoint must call should_trace()"
    );
    // No early `return 0` may precede init_program_data() in either program.
    for body in ["raw_syscalls_sys_enter", "raw_syscalls_sys_exit"] {
        let start = src
            .find(body)
            .unwrap_or_else(|| panic!("{body} not found in ebpf/syscall.c"));
        let rest = &src[start..];
        let init = rest
            .find("init_program_data(&p, ctx)")
            .unwrap_or_else(|| panic!("{body} does not call init_program_data"));
        assert!(
            !rest[..init].contains("return 0;"),
            "{body} returns before init_program_data(); a pre-filter early exit is \
             exactly what broke the dev branch"
        );
    }
}

// ---- ③a `op_ctx` must be fully zeroed --------------------------------------

/// `sizeof(op_ctx)` on a pointer is 8, so only the eight `u8` flags were cleared
/// and `post_code` (offset 20) kept the previous event's value, making
/// `read_args()` spin an extra loop with the wrong op. `op_ctx_t` is 72 bytes.
#[test]
fn op_ctx_is_zeroed_with_the_full_structure_size() {
    let expected = "sizeof(*op_ctx)";

    for (file, occurrences) in [("syscall.c", 2usize), ("stack.c", 1usize)] {
        let src = read_ebpf(file);
        // The buggy pointer-sized form; `sizeof(*op_ctx)` must not match it.
        let bare = src.matches("sizeof(op_ctx)").count();
        assert_eq!(
            bare, 0,
            "ebpf/{file} still zeroes op_ctx with sizeof(pointer) (8 bytes instead of 72)"
        );
        assert_eq!(
            src.matches(expected).count(),
            occurrences,
            "ebpf/{file} should zero op_ctx with {expected} in all {occurrences} place(s)"
        );
    }
}

/// 72 bytes = 8 x u8 + 6 x u32 + 5 x u64, which is what `sizeof(*op_ctx)` must
/// evaluate to on the eBPF side. Mirrors `contract::types::OpCtx`.
#[test]
fn op_ctx_struct_is_72_bytes_on_both_sides() {
    use stackplz::contract::types::OpCtx;
    assert_eq!(std::mem::size_of::<OpCtx>(), 72);
    assert_eq!(
        std::mem::size_of::<OpCtx>(),
        8 + 6 * 4 + 5 * 8,
        "u8 x8 + u32 x6 + u64 x5"
    );
}

// ---- ② default-deny fallback in `should_trace()` ----------------------------

/// `should_trace()` ends in an unconditional `return 0`. With no uid/pid/tid/
/// thread filter configured that means zero events, whereas master's
/// `filter->uid != 0 && ...` semantics meant "0 = no filtering". The fallback
/// must sit *after* the negative filters (self-exclusion + blacklists) and
/// return 1.
#[test]
fn should_trace_has_permissive_fallback_after_negative_filters() {
    let src = read_ebpf("common/filtering.h");

    let fallback = src
        .find("no_filter_allow == 1")
        .expect("should_trace() lost its no_filter_allow fallback");
    assert!(
        src[fallback..].contains("return 1;"),
        "the no_filter_allow branch must allow the event (return 1)"
    );

    // Negative filters must still be evaluated before the fallback.
    for negative in [
        "config->stackplz_pid == context->pid",
        "TID_BLACKLIST_START + context->tid",
        "PID_BLACKLIST_START + context->pid",
        "UID_BLACKLIST_START + context->uid",
    ] {
        let pos = src
            .find(negative)
            .unwrap_or_else(|| panic!("negative filter {negative:?} is gone"));
        assert!(
            pos < fallback,
            "negative filter {negative:?} must run before the permissive fallback"
        );
    }

    // And the default deny must still exist for the filtered case.
    let allow = fallback
        + src[fallback..]
            .find("return 1;")
            .expect("the no_filter_allow branch must return 1");
    assert!(
        src[allow..].contains("return 0;"),
        "should_trace() must keep the default deny after the permissive fallback"
    );
}

// ---- ③b/③c `common_list` segment stride ------------------------------------

/// Parse `#define NAME expr` from a C header into a name -> expression map.
fn parse_defines(src: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in src.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("#define ") else {
            continue;
        };
        let mut parts = rest.splitn(2, char::is_whitespace);
        let name = parts.next().unwrap_or("").trim().to_string();
        let expr = parts.next().unwrap_or("").trim().to_string();
        if !name.is_empty() && !expr.is_empty() {
            out.insert(name, expr);
        }
    }
    out
}

/// Evaluate a `#define` expression made only of `+`, parentheses, hex/decimal
/// literals and previously defined identifiers.
fn eval_define(name: &str, defs: &HashMap<String, String>, depth: usize) -> u64 {
    assert!(depth < 16, "define recursion too deep at {name}");
    let expr = defs
        .get(name)
        .unwrap_or_else(|| panic!("{name} is not defined in the header"));
    // Parentheses only group additions here, so flattening them is safe.
    let flat = expr.replace(['(', ')'], " ");
    let mut total = 0u64;
    for term in flat.split('+') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        let value = if let Some(hex) = term.strip_prefix("0x").or_else(|| term.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("bad hex {term:?}"))
        } else if term.chars().all(|c| c.is_ascii_digit()) {
            term.parse::<u64>()
                .unwrap_or_else(|_| panic!("bad number {term:?}"))
        } else {
            eval_define(term, defs, depth + 1)
        };
        total += value;
    }
    total
}

/// The Rust constants in `contract::consts` must resolve to exactly the same
/// numbers as the C `#define` chain — they are the map keys the user side writes
/// and the kernel side looks up.
#[test]
fn common_list_offsets_match_the_c_header() {
    use stackplz::contract::consts as c;

    let header = parse_defines(&read_ebpf("common/consts.h"));
    let from_c = [
        ("SYS_WHITELIST_START", c::SYS_WHITELIST_START),
        ("SYS_BLACKLIST_START", c::SYS_BLACKLIST_START),
        ("UID_WHITELIST_START", c::UID_WHITELIST_START),
        ("UID_BLACKLIST_START", c::UID_BLACKLIST_START),
        ("PID_WHITELIST_START", c::PID_WHITELIST_START),
        ("PID_BLACKLIST_START", c::PID_BLACKLIST_START),
        ("TID_WHITELIST_START", c::TID_WHITELIST_START),
        ("TID_BLACKLIST_START", c::TID_BLACKLIST_START),
    ];
    for (name, rust_value) in from_c {
        assert_eq!(
            eval_define(name, &header, 0) as u32,
            rust_value,
            "{name} differs between ebpf/common/consts.h and contract::consts"
        );
    }
    assert_eq!(
        eval_define("COMMON_LIST_SEGMENT_STRIDE", &header, 0) as u32,
        c::COMMON_LIST_SEGMENT_STRIDE
    );
}

/// Regression for the 0x400 collision: the segment window must be wide enough
/// for real pid/tid/uid values, so that `PID_WHITELIST_START + pid` can never
/// land on `TID_WHITELIST_START + tid`. `0x400` (1024) was far too small.
#[test]
fn common_list_segments_are_wide_enough_for_real_pids_and_uids() {
    use stackplz::contract::consts as c;

    const PID_MAX_LIMIT: u32 = 4 * 1024 * 1024;
    // Compile-time guards, so shrinking the window is a build failure rather
    // than a silent cross-segment collision on a device.
    const _: () = assert!(c::COMMON_LIST_SEGMENT_STRIDE >= PID_MAX_LIMIT);
    // Android uids: 2000 (shell), 0..19999 (apps), 99000..99999 (isolated).
    const _: () = assert!(c::COMMON_LIST_SEGMENT_STRIDE > 99_999);

    // Concrete collision that used to happen with the 0x400 stride: with a
    // 1024-wide window, PID_WHITELIST_START(0x1400) + 20001 == 0x6221 landed
    // inside the TID whitelist window and collided with TID 19025.
    const LEGACY_STRIDE: u32 = 0x400;
    let legacy_pid_whitelist_start = LEGACY_STRIDE * 5;
    let legacy_tid_whitelist_start = LEGACY_STRIDE * 7;
    let pid = 20_001u32;
    let tid = 17_953u32;
    assert_eq!(
        legacy_pid_whitelist_start + pid,
        legacy_tid_whitelist_start + tid,
        "sanity: the legacy layout did collide for this pid/tid pair"
    );

    // With the fixed layout the two keys must stay inside their own segments.
    let pid_key = c::PID_WHITELIST_START + pid;
    let tid_key = c::TID_WHITELIST_START + tid;
    assert_ne!(pid_key, tid_key);
    assert!(pid_key < c::PID_BLACKLIST_START);
    assert!(tid_key >= c::TID_WHITELIST_START);
}

// ---- ② `common_filter_t` field order ---------------------------------------

/// Extract the ordered field names of `typedef struct common_filter { ... }`.
fn parse_struct_fields(src: &str, struct_name: &str) -> Vec<String> {
    let marker = format!("typedef struct {struct_name} {{");
    let start = src
        .find(&marker)
        .unwrap_or_else(|| panic!("struct {struct_name} not found"));
    let body_start = start + marker.len();
    let end = src[body_start..]
        .find('}')
        .map(|i| body_start + i)
        .unwrap_or_else(|| panic!("unterminated struct {struct_name}"));
    let mut fields = Vec::new();
    for line in src[body_start..end].lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        if line.is_empty() || !line.ends_with(';') {
            continue;
        }
        let decl = line.trim_end_matches(';').trim();
        let name = decl.split_whitespace().last().unwrap_or("");
        if !name.is_empty() {
            fields.push(name.to_string());
        }
    }
    fields
}

/// The eBPF side reads `common_filter_t` by fixed offsets, so the C field order
/// (`no_filter_allow` last) must be exactly the Rust `CommonFilter` order.
#[test]
fn common_filter_field_order_matches_the_c_header() {
    let src = read_ebpf("types.h");
    let fields = parse_struct_fields(&src, "common_filter");
    assert_eq!(
        fields,
        vec![
            "is_32bit",
            "trace_mode",
            "trace_uid_group",
            "signal",
            "tsignal",
            "no_filter_allow",
        ],
        "common_filter_t field order changed"
    );
    // 6 x u32.
    assert_eq!(
        fields.len() * 4,
        std::mem::size_of::<stackplz::contract::types::CommonFilter>()
    );
}
