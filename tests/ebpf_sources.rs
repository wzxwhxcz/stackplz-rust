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

/// Evaluate a `#define` expression made of `+`, `<<`, parentheses, hex/decimal
/// literals and previously defined identifiers.
fn eval_define(name: &str, defs: &HashMap<String, String>, depth: usize) -> u64 {
    assert!(depth < 16, "define recursion too deep at {name}");
    let expr = defs
        .get(name)
        .unwrap_or_else(|| panic!("{name} is not defined in the header"));
    eval_sum(expr, defs, depth)
}

/// `+` is the lowest-precedence operator used by these headers, so it is split
/// first; parentheses only group sums and shifts here, so flattening is safe.
fn eval_sum(expr: &str, defs: &HashMap<String, String>, depth: usize) -> u64 {
    let flat = expr.replace(['(', ')'], " ");
    let mut total = 0u64;
    for term in flat.split('+') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        total += eval_shift(term, defs, depth);
    }
    total
}

/// Left-associative `<<` chain, e.g. `1 << 22` (`_TIF_32BIT`).
fn eval_shift(term: &str, defs: &HashMap<String, String>, depth: usize) -> u64 {
    let mut parts = term.split("<<");
    let mut acc = eval_atom(parts.next().unwrap_or_default().trim(), defs, depth);
    for part in parts {
        acc = acc.wrapping_shl(eval_atom(part.trim(), defs, depth) as u32);
    }
    acc
}

/// A single literal or a previously defined identifier.
fn eval_atom(term: &str, defs: &HashMap<String, String>, depth: usize) -> u64 {
    if let Some(hex) = term.strip_prefix("0x").or_else(|| term.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("bad hex {term:?}"))
    } else if !term.is_empty() && term.chars().all(|c| c.is_ascii_digit()) {
        term.parse::<u64>()
            .unwrap_or_else(|_| panic!("bad number {term:?}"))
    } else {
        eval_define(term, defs, depth + 1)
    }
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

// ---- ③ lr/sp register source must follow the *target* task's ABI -----------

/// Locate the first brace-delimited block following `needle` (searched from byte
/// `from`) and return `(needle_pos, block_body, closing_brace_pos)`.
///
/// None of the sources under test has a brace inside a string literal, so plain
/// brace counting is exact for them.
fn find_block<'a>(src: &'a str, needle: &str, from: usize) -> (usize, &'a str, usize) {
    let needle_pos = from
        + src[from..]
            .find(needle)
            .unwrap_or_else(|| panic!("{needle:?} not found"));
    let open = needle_pos
        + src[needle_pos..]
            .find('{')
            .unwrap_or_else(|| panic!("no `{{` after {needle:?}"));
    let mut depth = 0usize;
    for (offset, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return (needle_pos, &src[open + 1..open + offset], open + offset);
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces after {needle:?}");
}

/// The `if` that picks the lr/sp register source (AArch32 vs AArch64).
const COMPAT32_CALL: &str = "if (is_current_task_compat32())";

/// `filter->is_32bit` was written by the user side from the architecture of the
/// stackplz *host binary*, which says nothing about the traced process. The
/// registers lr/sp must be read from the layout of the *target task*'s ABI, so
/// the predicate must be `is_current_task_compat32()` and both register
/// branches must survive untouched.
///
/// This is the test that catches the old defect: with `filter->is_32bit` in
/// place it fails on the very first assertion.
#[test]
fn lr_sp_registers_follow_the_target_task_not_the_host_binary() {
    // file, program, aarch32 lr, aarch32 sp, aarch64 lr, aarch64 sp
    let cases = [
        (
            "syscall.c",
            "raw_syscalls_sys_enter",
            "&regs->regs[14]",
            "&regs->regs[13]",
            "&regs->regs[30]",
            "&regs->sp",
        ),
        (
            "stack.c",
            "probe_stack_warp",
            "&ctx->regs[14]",
            "&ctx->regs[13]",
            "&ctx->regs[30]",
            "&ctx->sp",
        ),
    ];

    for (file, program, lr32, sp32, lr64, sp64) in cases {
        let src = strip_c_comments(&read_ebpf(file));
        assert!(
            !src.contains("is_32bit"),
            "ebpf/{file} still derives the lr/sp registers from the host binary's \
             architecture (filter->is_32bit) instead of the target task's ABI"
        );
        assert_eq!(
            src.matches(COMPAT32_CALL).count(),
            1,
            "ebpf/{file} must call is_current_task_compat32() exactly once ({program})"
        );

        let (_, aarch32, call_end) = find_block(&src, COMPAT32_CALL, 0);
        let (else_pos, aarch64, _) = find_block(&src, "else", call_end);
        assert!(
            src[call_end + 1..else_pos].trim().is_empty(),
            "the compat32 branch in ebpf/{file} must be followed directly by its else"
        );

        assert!(
            aarch32.contains(lr32) && aarch32.contains(sp32),
            "ebpf/{file}: the compat32 branch must read lr/sp from {lr32}/{sp32}"
        );
        assert!(
            aarch64.contains(lr64) && aarch64.contains(sp64),
            "ebpf/{file}: the 64-bit branch must read lr/sp from {lr64}/{sp64}"
        );

        // Only the register source differs; both branches must still emit lr
        // (slot 1) and sp (slot 2) for the event.
        for (name, block) in [("compat32", aarch32), ("64-bit", aarch64)] {
            assert!(
                block.contains("save_to_submit_buf")
                    && block.contains("sizeof(u64), 1)")
                    && block.contains("sizeof(u64), 2)"),
                "ebpf/{file}: the {name} branch must keep submitting lr and sp"
            );
        }
    }
}

/// The fix must not resurrect the removed architecture *gate*: that one did
/// `return 0` before any filtering, which silently dropped every AArch32 target
/// on arm64 and every target on arm32. The new predicate may only choose
/// registers, so (a) it must run *after* `should_trace()` and (b) neither of its
/// branches may return.
#[test]
fn compat32_predicate_selects_registers_but_never_drops_events() {
    for (file, program) in [
        ("syscall.c", "raw_syscalls_sys_enter"),
        ("stack.c", "probe_stack_warp"),
    ] {
        let src = strip_c_comments(&read_ebpf(file));
        let program_start = src
            .find(program)
            .unwrap_or_else(|| panic!("{program} not found in ebpf/{file}"));

        let (call, then_block, call_end) = find_block(&src, COMPAT32_CALL, program_start);
        let (_, else_block, _) = find_block(&src, "else", call_end);

        let filed = program_start
            + src[program_start..]
                .find("if (!should_trace(&p))")
                .unwrap_or_else(|| panic!("{program} lost its should_trace() call"));
        assert!(
            filed < call,
            "{program} must filter with should_trace() before it picks registers, \
             otherwise the register selector is being used as a filter"
        );

        for (branch, block) in [("compat32", then_block), ("64-bit", else_block)] {
            assert!(
                !block.contains("return"),
                "{program}: the {branch} branch must not return — returning here is \
                 the architecture gate that was removed because it caused zero events"
            );
            assert!(
                !block.contains("should_trace") && !block.contains("bpf_map_lookup_elem"),
                "{program}: the {branch} branch must only touch registers, never filter"
            );
        }
    }
}

/// `is_current_task_compat32()` has to live in `ebpf/common/task.h`: keeping it
/// there is what allows `ebpf/syscall.c` to stay free of `_TIF_32BIT` /
/// `thread_info.flags` / `__TARGET_ARCH_arm` (see `syscall_c_has_no_arch_gate`).
/// It must also stay a pure register selector.
#[test]
fn task_h_exposes_a_compat32_register_selector_not_a_filter() {
    let src = strip_c_comments(&read_ebpf("common/task.h"));
    let signature = "static __always_inline bool is_current_task_compat32(void)";
    let (_, body, _) = find_block(&src, signature, 0);

    // arm build: every target is 32-bit, so it answers without touching flags.
    let arm_if = "#if defined(__TARGET_ARCH_arm)";
    let arm_start = body
        .find(arm_if)
        .unwrap_or_else(|| panic!("task.h helper lost its {arm_if} branch"));
    let arm_else = body.find("#else").expect("task.h helper lost its #else");
    let arm_endif = body.find("#endif").expect("task.h helper lost its #endif");
    let arm_branch = &body[arm_start + arm_if.len()..arm_else];
    assert!(
        arm_branch.contains("return true;"),
        "on arm every target is 32-bit, the helper must return true"
    );
    assert!(
        !arm_branch.contains("flags"),
        "on arm the helper must not read thread_info.flags (bit 22 is always 0 there)"
    );

    // other builds: the *target task*'s own ABI decides, not the host binary.
    let compat_branch = &body[arm_else..arm_endif];
    for needle in [
        "bpf_get_current_task()",
        "thread_info.flags",
        "_TIF_32BIT",
        "return false;",
    ] {
        assert!(
            compat_branch.contains(needle),
            "the non-arm branch must read the target's ABI via {needle:?}"
        );
    }

    for forbidden in ["bpf_map_lookup_elem", "should_trace", "return 0"] {
        assert!(
            !body.contains(forbidden),
            "is_current_task_compat32() must stay a register selector: found {forbidden:?}"
        );
    }

    // Both eBPF programs reach the helper through the shared context header.
    let context_header = strip_c_comments(&read_ebpf("common/context.h"));
    assert!(
        context_header.contains("common/task.h"),
        "ebpf/common/context.h must keep including common/task.h, otherwise \
         syscall.c/stack.c cannot see the helper"
    );
}

/// `_TIF_32BIT` is the map/flag contract between the C predicate and the Rust
/// side (`contract::consts::_TIF_32BIT`); `thread_info.flags` bit numbering must
/// match or the predicate silently reads a different bit.
#[test]
fn tif_32bit_define_matches_the_rust_contract() {
    use stackplz::contract::consts as c;

    let header = parse_defines(&read_ebpf("common/consts.h"));
    let expr = header
        .get("_TIF_32BIT")
        .unwrap_or_else(|| panic!("ebpf/common/consts.h lost its _TIF_32BIT define"));
    assert!(
        expr.contains("<<"),
        "_TIF_32BIT must remain a shift expression (bit 22), got {expr:?}"
    );
    assert_eq!(
        eval_define("_TIF_32BIT", &header, 0),
        u64::from(c::_TIF_32BIT),
        "_TIF_32BIT differs between ebpf/common/consts.h and contract::consts"
    );
    assert_eq!(c::_TIF_32BIT, 1 << 22, "arm64 thread_info.flags bit 22");
}
