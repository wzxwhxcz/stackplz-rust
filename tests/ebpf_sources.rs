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

// ===========================================================================
// Round 3 — C↔Rust contract cross-locks (brief item 7 / report §5.3)
//
// Report §5.4 mutations M4/M5/M7/M8 showed that *C-side* drift in the event
// ids, `TRACE_COMMON`/`TRACE_ALL`, the `op_ctx_t` size and the
// `common_filter_t` field widths left all 243 tests green, because only the
// Rust side was asserted. Each test below parses the C header as text (the
// sandbox and CI have no clang for the eBPF objects) and locks the parsed
// value against the Rust `contract` layer, so a C mutation fails the build.
// ===========================================================================

/// Parse a C enum body into `(name, value)` pairs, honouring the implicit
/// `NAME` = previous + 1 form used by `event_id_e`.
fn parse_c_enum(src: &str, enum_name: &str) -> Vec<(String, u64)> {
    let src = strip_c_comments(src);
    let marker = format!("enum {enum_name}");
    let start = src
        .find(&marker)
        .unwrap_or_else(|| panic!("enum {enum_name} not found"));
    let open = start
        + src[start..]
            .find('{')
            .unwrap_or_else(|| panic!("no `{{` after enum {enum_name}"));
    let close = open
        + src[open..]
            .find('}')
            .unwrap_or_else(|| panic!("unterminated enum {enum_name}"));
    let body = &src[open + 1..close];

    let mut out = Vec::new();
    let mut next = 0u64;
    for item in body.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (name, value) = match item.split_once('=') {
            Some((name, value)) => {
                let value = value.trim();
                let value = value.parse::<u64>().unwrap_or_else(|_| {
                    panic!(
                        "{enum_name} member {value:?} is not a plain integer; \
                         extend parse_c_enum before changing the header"
                    )
                });
                (name.trim(), value)
            }
            None => (item, next),
        };
        assert!(!name.is_empty(), "bad member {item:?} in enum {enum_name}");
        out.push((name.to_string(), value));
        next = value + 1;
    }
    assert!(!out.is_empty(), "enum {enum_name} parsed as empty");
    out
}

/// A single C struct field: `type name;` or `type name[N];`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CField {
    ty: String,
    name: String,
    count: usize,
}

/// Parse `typedef struct NAME { ... }` into ordered typed fields.
fn parse_struct_fields_typed(src: &str, struct_name: &str) -> Vec<CField> {
    let src = strip_c_comments(src);
    let marker = format!("typedef struct {struct_name} {{");
    let start = src
        .find(&marker)
        .unwrap_or_else(|| panic!("struct {struct_name} not found"));
    let body_start = start + marker.len();
    let end = body_start
        + src[body_start..]
            .find('}')
            .unwrap_or_else(|| panic!("unterminated struct {struct_name}"));

    let mut out = Vec::new();
    for line in src[body_start..end].lines() {
        let decl = line.trim();
        if decl.is_empty() {
            continue;
        }
        let decl = decl
            .strip_suffix(';')
            .unwrap_or_else(|| panic!("field without `;` in struct {struct_name}: {decl:?}"))
            .trim();

        let (base, count) = match decl.split_once('[') {
            Some((base, arr)) => {
                let inner = arr
                    .strip_suffix(']')
                    .unwrap_or_else(|| panic!("bad array field {decl:?}"));
                let count = inner.trim().parse::<usize>().unwrap_or_else(|_| {
                    panic!("array field {decl:?} must have a literal length in {struct_name}")
                });
                (base.trim(), count)
            }
            None => (decl, 1),
        };
        let tokens: Vec<&str> = base.split_whitespace().collect();
        assert_eq!(
            tokens.len(),
            2,
            "unexpected field declaration {decl:?} in struct {struct_name}"
        );
        out.push(CField {
            ty: tokens[0].to_string(),
            name: tokens[1].to_string(),
            count,
        });
    }
    assert!(!out.is_empty(), "struct {struct_name} parsed as empty");
    out
}

/// `(size, alignment)` of the plain C integer types used by the contract
/// structs. Anything else must be added deliberately.
fn c_type_size_align(ty: &str) -> (usize, usize) {
    match ty {
        "u8" | "char" | "bool" => (1, 1),
        "u16" => (2, 2),
        "u32" => (4, 4),
        "u64" => (8, 8),
        other => panic!("unhandled C type {other:?}; extend c_type_size_align"),
    }
}

/// Compute the field offsets and total size of a C struct under the natural
/// alignment (System V) rules the eBPF C compiler applies: no `__packed`, and
/// the struct size is rounded up to its largest member alignment.
fn c_struct_layout(fields: &[CField]) -> (Vec<usize>, usize) {
    let mut offsets = Vec::with_capacity(fields.len());
    let mut offset = 0usize;
    let mut align = 1usize;
    for field in fields {
        let (size, field_align) = c_type_size_align(&field.ty);
        align = align.max(field_align);
        offset = offset.div_ceil(field_align) * field_align;
        offsets.push(offset);
        offset += size * field.count;
    }
    let size = offset.div_ceil(align) * align;
    (offsets, size)
}

/// Build `[(field, rust offsetof)]` for a `#[repr(C)]` Rust struct, so the C
/// and Rust field tables can be compared entry by entry.
macro_rules! rust_offsets {
    ($t:ty; $($field:ident),+ $(,)?) => {
        vec![$( (stringify!($field), std::mem::offset_of!($t, $field)) ),+]
    };
}

/// `enum event_id_e` is the wire tag in `event_context_t.eventid`, and 456/457/
/// 458 are also what the Go userlands and the Rust decoder key on. Report
/// mutation M4 changed the C id to 460 and every test stayed green.
#[test]
fn event_id_enum_matches_the_rust_contract() {
    use stackplz::contract::enums::EventId;

    let members = parse_c_enum(&read_ebpf("types.h"), "event_id_e");
    let c_value = |name: &str| -> u64 {
        members
            .iter()
            .find(|(member, _)| member.as_str() == name)
            .unwrap_or_else(|| panic!("ebpf/types.h enum event_id_e lost {name}"))
            .1
    };

    let expected = [
        ("SYSCALL_ENTER", 456u64, EventId::SyscallEnter as u64),
        ("SYSCALL_EXIT", 457, EventId::SyscallExit as u64),
        ("UPROBE_ENTER", 458, EventId::UprobeEnter as u64),
    ];
    for (name, wire, rust) in expected {
        assert_eq!(
            c_value(name),
            wire,
            "event id {name} in ebpf/types.h must stay {wire} for wire compatibility"
        );
        assert_eq!(
            wire, rust,
            "contract::enums::EventId must mirror ebpf/types.h ({name} = {wire})"
        );
    }
    assert_eq!(
        members.len(),
        3,
        "event_id_e should hold exactly the three emitted event types, got {members:?}"
    );
}

/// Report mutation M5 changed the C `TRACE_COMMON` to 2 and nothing failed.
/// The only C consumer compares against `TRACE_COMMON`, and the user side
/// writes the value into `common_filter_t.trace_mode`.
#[test]
fn trace_mode_values_match_the_rust_contract() {
    use stackplz::contract::consts as c;

    let header = parse_defines(&strip_c_comments(&read_ebpf("common/consts.h")));
    let trace_common = eval_define("TRACE_COMMON", &header, 0);
    let trace_all = eval_define("TRACE_ALL", &header, 0);

    assert_eq!(
        trace_common,
        u64::from(c::TRACE_COMMON),
        "TRACE_COMMON differs between ebpf/common/consts.h and contract::consts"
    );
    assert_eq!(
        trace_all,
        u64::from(c::TRACE_ALL),
        "TRACE_ALL differs between ebpf/common/consts.h and contract::consts"
    );
    // The values themselves are the contract: the C side treats
    // `trace_mode != TRACE_COMMON` as "trace all", so they must stay 0/1.
    assert_eq!(trace_common, 0, "TRACE_COMMON must stay 0");
    assert_eq!(trace_all, 1, "TRACE_ALL must stay 1");
}

/// Report mutation M7 appended a field to the C `op_ctx_t` (72 -> 80 bytes) and
/// all tests stayed green, even though `sizeof(*op_ctx)` is what the three
/// memsets clear and the Rust `OpCtx` map value must stay 72 bytes.
#[test]
fn op_ctx_c_layout_matches_the_rust_contract() {
    use stackplz::contract::types::OpCtx;

    let fields = parse_struct_fields_typed(&read_ebpf("types.h"), "op_ctx");
    let (offsets, size) = c_struct_layout(&fields);

    assert_eq!(
        size, 72,
        "op_ctx_t in ebpf/types.h is {size} bytes; the C memsets and the Rust \
         OpCtx map value both require 72"
    );
    assert_eq!(
        size,
        std::mem::size_of::<OpCtx>(),
        "C op_ctx_t is {size}B but Rust OpCtx is {}B",
        std::mem::size_of::<OpCtx>()
    );

    let rust = rust_offsets!(
        OpCtx;
        save_index,
        reg_index,
        loop_count,
        break_count,
        apply_filter,
        skip_flag,
        match_whitelist,
        match_blacklist,
        loop_index,
        op_key_index,
        op_code,
        post_code,
        str_len,
        read_len,
        read_addr,
        reg_value,
        pointer_value,
        tmp_value,
        reg_0,
    );
    let c: Vec<(&str, usize)> = fields
        .iter()
        .zip(&offsets)
        .map(|(field, &offset)| (field.name.as_str(), offset))
        .collect();
    assert_eq!(
        c, rust,
        "op_ctx_t field order/offsets in ebpf/types.h drifted from Rust OpCtx"
    );

    // The 8 x u8 + 6 x u32 + 5 x u64 decomposition is what makes 72 the size,
    // and `sizeof(*op_ctx)` (not `sizeof(op_ctx)`) must be what the three
    // memsets use: 2 in syscall.c + 1 in stack.c.
    let u8_fields = fields.iter().filter(|f| f.ty == "u8").count();
    let u32_fields = fields.iter().filter(|f| f.ty == "u32").count();
    let u64_fields = fields.iter().filter(|f| f.ty == "u64").count();
    assert_eq!(
        (u8_fields, u32_fields, u64_fields),
        (8, 6, 5),
        "op_ctx_t must stay 8 x u8 + 6 x u32 + 5 x u64"
    );
    let memsets: usize = ["syscall.c", "stack.c"]
        .iter()
        .map(|file| read_ebpf(file).matches("sizeof(*op_ctx)").count())
        .sum();
    assert_eq!(
        memsets, 3,
        "sizeof(*op_ctx) must clear all 72 bytes in exactly 3 places \
         (syscall.c x2 + stack.c x1), found {memsets}"
    );
}

/// Report mutation M8 widened a C `common_filter_t` field to `u64` and all
/// tests stayed green. The C side reads this struct by fixed offsets, so both
/// the field order/widths and the resulting 24-byte size must match Rust.
#[test]
fn common_filter_c_layout_matches_the_rust_contract() {
    use stackplz::contract::types::CommonFilter;

    let fields = parse_struct_fields_typed(&read_ebpf("types.h"), "common_filter");
    assert_eq!(
        fields.len(),
        6,
        "common_filter_t must hold exactly 6 u32 fields, got {fields:?}"
    );
    let expected = [
        "is_32bit",
        "trace_mode",
        "trace_uid_group",
        "signal",
        "tsignal",
        "no_filter_allow",
    ];
    for (field, want) in fields.iter().zip(expected) {
        assert_eq!(
            field.ty, "u32",
            "common_filter_t.{} must stay 32-bit: the C side reads it by offset",
            field.name
        );
        assert_eq!(
            field.name, want,
            "common_filter_t field order changed (expected {expected:?})"
        );
    }

    let (offsets, size) = c_struct_layout(&fields);
    assert_eq!(offsets, vec![0, 4, 8, 12, 16, 20], "C offsets");
    assert_eq!(size, 24, "common_filter_t must stay 24 bytes (5 + 1 u32)");
    assert_eq!(
        size,
        std::mem::size_of::<CommonFilter>(),
        "C common_filter_t is {size}B but Rust CommonFilter is {}B",
        std::mem::size_of::<CommonFilter>()
    );

    let rust = rust_offsets!(
        CommonFilter;
        is_32bit,
        trace_mode,
        trace_uid_group,
        signal,
        tsignal,
        no_filter_allow,
    );
    let c: Vec<(&str, usize)> = fields
        .iter()
        .zip(&offsets)
        .map(|(field, &offset)| (field.name.as_str(), offset))
        .collect();
    assert_eq!(
        c, rust,
        "common_filter_t offsets in ebpf/types.h drifted from Rust CommonFilter"
    );
}

// ---- 12 IDENTICAL C files: upstream hash lock -----------------------------

/// `(path relative to ebpf/, sha256 hex)` for the 12 eBPF C sources that are
/// byte-identical to upstream dev `62fc9e8` (report §1.1).
///
/// The other 7 files (`common/arch.h`, `common/consts.h`,
/// `common/filtering.h`, `common/task.h`, `stack.c`, `syscall.c`, `types.h`)
/// carry the two earlier intentional fix rounds plus the `arch.h`
/// dead-macro cleanup, so they are deliberately absent here: a value that
/// starts matching upstream again means a fix was rolled back.
///
/// Before this lock only `common/context.h` was ever read by a test (report
/// §5.3): the remaining 11 IDENTICAL files had no regression protection at all.
const IDENTICAL_EBPF_SOURCES: [(&str, &str); 12] = [
    (
        "bpf/bpf_helper_defs.h",
        "8623a80ea648cd774c87d551763800479a9d7a9ee0c577bbf076718bb554f8af",
    ),
    (
        "bpf/bpf_helpers.h",
        "54e6f02d187bea05950b333f90c04b713c008d117579950395f028491df0798c",
    ),
    (
        "bpf/bpf_tracing.h",
        "eb93a7e4268a28d37c962216d553fb84fca2c13c7f3df9f02a2ff84202185648",
    ),
    (
        "common/arguments.h",
        "52e6d197969ed0bf7c4c8c716b352ce7a8730de4bb06fc142a633d3fea548866",
    ),
    (
        "common/buffer.h",
        "a6cbc561a4cd604e728cfdf05d6af273f108faa0de43b476366e352c82b7d4fb",
    ),
    (
        "common/common.h",
        "9c0c52f41e45bc724a91d785ffb58a70895241df7dc570a0ff6a629e6f31068f",
    ),
    (
        "common/context.h",
        "ca55a7500e705600af20d02c635b2dd3013f5a9f381737b21efcffeca3cfb876",
    ),
    (
        "maps.h",
        "b709771a5d5fd077d546b6a4cb33ffdf2b361a5d383a46b5488883095fa56174",
    ),
    (
        "memory.h",
        "4eae6c9be6400f1f691a014fab667890c41f37dab41c0a7325d7a3377b4f237d",
    ),
    (
        "perf_mmap.c",
        "20642779898bc005482fb66b0a9e32b7e22ec77a1ff32ab2d5debfd9fa962cf9",
    ),
    (
        "utils.h",
        "eeaf95419b765b832ef113c3dd1934dc057a44a0987120a9010b5fd335233c73",
    ),
    (
        "vmlinux_510.h",
        "c27ddf128af22a8e9cb3add03ddb211be6f20e7ab14ea8c96ecdf08d45552a6e",
    ),
];

/// Minimal SHA-256 (FIPS 180-4).
///
/// `[dev-dependencies]` has no `sha2`, and this round may not edit
/// `Cargo.toml`, so the test carries its own implementation. It is
/// self-checked against the published FIPS vectors below before it is trusted
/// for the manifest.
fn sha256_hex(bytes: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut message = bytes.to_vec();
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    // The padding above guarantees a multiple of 64 bytes, so the remainder is
    // always empty.
    let (chunks, rest) = message.as_chunks::<64>();
    assert!(rest.is_empty(), "SHA-256 padding left {} bytes", rest.len());
    for chunk in chunks {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    state.iter().map(|word| format!("{word:08x}")).collect()
}

/// The 12 files report §1.1 marks IDENTICAL were only guaranteed by a manual
/// `diff`; 11 of them were never read by any test. This lock hashes each local
/// `ebpf/<path>` and compares it to the upstream `62fc9e8` digest, so an
/// accidental edit (or a "harmless reformat") fails CI by file name.
#[test]
fn identical_ebpf_sources_match_the_upstream_hash_lock() {
    // Self-check the in-test SHA-256 against the FIPS 180-4 vectors first, so a
    // broken hash implementation cannot make every file pass by accident.
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"The quick brown fox jumps over the lazy dog"),
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    );

    for (rel, expected) in IDENTICAL_EBPF_SOURCES {
        let path = ebpf_dir().join(rel);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("cannot read ebpf/{rel} (upstream-locked): {e}"));
        let actual = sha256_hex(&bytes);
        assert_eq!(
            actual, expected,
            "ebpf/{rel} no longer matches upstream dev 62fc9e8:\n  expected {expected}\n  actual   {actual}\n\
             This file is one of the 12 IDENTICAL sources. Restore it byte-for-byte; if the \
             change is intentional, update IDENTICAL_EBPF_SOURCES and the README 12/7 split \
             together with a note in DONE.md"
        );
    }

    // Exactly 12 unique, existing entries.
    let mut seen = std::collections::HashSet::new();
    for (rel, _) in IDENTICAL_EBPF_SOURCES {
        assert!(seen.insert(rel), "duplicate hash-lock entry {rel}");
        assert!(
            ebpf_dir().join(rel).is_file(),
            "ebpf/{rel} vanished from the tree"
        );
    }
    assert_eq!(
        seen.len(),
        12,
        "the IDENTICAL manifest must stay at 12 entries (report §1.1)"
    );

    // The 7 DIFFERS files carry the two fix rounds + the arch.h cleanup. They
    // must not be locked to upstream, and they must still exist.
    const DIFFERS: [&str; 7] = [
        "common/arch.h",
        "common/consts.h",
        "common/filtering.h",
        "common/task.h",
        "stack.c",
        "syscall.c",
        "types.h",
    ];
    for rel in DIFFERS {
        assert!(
            !seen.contains(rel),
            "ebpf/{rel} is one of the 7 DIFFERS files (intentional deviation) and must not \
             be hash-locked as IDENTICAL"
        );
        assert!(ebpf_dir().join(rel).is_file(), "ebpf/{rel} vanished");
    }
}

// ===========================================================================
// D-S1 — the arm64-only eBPF side vs. the README / CI x86_64 build claim
//
// The eBPF C implements *only* arm64/arm register semantics (`_TIF_32BIT` is an
// arm64-only thread_info flag bit and every lr/sp read is an AArch64 register
// index). An x86_64 build still compiles and CI runs it, so nothing fails
// loudly — it just emits plausible, wrong lr/sp. The honest contract is: arm64/
// arm is the supported target, x86_64 is build-only. These assertions pin that
// contract in the C comments and in the README so it cannot drift back into an
// unconditional "x86_64 supported" claim.
// ===========================================================================

/// `ebpf/common/task.h` and `ebpf/common/arch.h` are where a reader looks to
/// learn which architectures the eBPF side actually implements. Both must name
/// x86_64 as build-only and say the lr/sp data is untrustworthy there.
#[test]
fn ebpf_headers_state_x86_64_is_build_only() {
    for file in ["common/task.h", "common/arch.h"] {
        let src = read_ebpf(file);
        assert!(
            src.contains("x86_64"),
            "ebpf/{file} must state the x86_64 contract (it is build-only), \
             otherwise the arm64-only register code reads as portable"
        );
        for needle in ["x86_64", "arm64"] {
            assert!(
                src.contains(needle),
                "ebpf/{file} must name {needle:?} when describing the supported targets"
            );
        }
        // The claim must be the honest one: build-only, not supported.
        assert!(
            src.contains("不可信") || src.contains("build-only") || src.contains("仅编译"),
            "ebpf/{file} must say x86_64 lr/sp is unusable/build-only, not supported"
        );
        assert!(
            src.contains("shortcut:"),
            "ebpf/{file}: a knowingly-limited architecture claim needs a \
             `shortcut: <limit>, <when to upgrade>` comment"
        );
    }
}

/// No eBPF source outside the vendored `bpf/` headers may carry an x86_64
/// *implementation* branch: there is none, so adding one (or restoring
/// upstream's) without also fixing `syscall.c`/`stack.c` and this test would
/// silently advertise x86_64 support again.
#[test]
fn no_ebpf_source_claims_an_x86_register_path() {
    for file in [
        "common/arch.h",
        "common/consts.h",
        "common/task.h",
        "stack.c",
        "syscall.c",
    ] {
        let src = strip_c_comments(&read_ebpf(file));
        assert!(
            !src.contains("__TARGET_ARCH_x86"),
            "ebpf/{file} has an x86_64 code path; the port only implements \
             arm64/arm registers. Either implement x86_64 in syscall.c/stack.c \
             and update the README + ebpf_headers_state_x86_64_is_build_only, \
             or keep the claim build-only"
        );
    }
}

/// The README is the user-facing support claim that started this: it must not
/// present the x86_64 build as a supported tracing target.
#[test]
fn readme_marks_x86_64_as_build_only() {
    let readme =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md"))
            .expect("cannot read README.md");

    assert!(
        readme.contains("架构限制"),
        "README must keep an architecture-limitations note: the eBPF side is \
         arm64/arm only, so an x86_64 build does not produce trustworthy lr/sp"
    );
    assert!(
        readme.contains("不可信") || readme.contains("build-only") || readme.contains("仅编译"),
        "README must say the x86_64 build is build-only / its lr/sp is unusable"
    );

    // The support line may not claim x86_64 as a plain supported build, i.e. the
    // x86_64 bullet must carry the build-only qualifier on the same line.
    for line in readme.lines().filter(|line| line.contains("x86_64")) {
        assert!(
            line.contains("仅编译") || line.contains("build-only") || line.contains("不可信"),
            "README line claims x86_64 without the build-only qualifier: {line:?}"
        );
    }
}

/// Review F6: `StackProbeModule` binds hook point `i` to program
/// `probe_stack_<i>`, and `MAX_UPROBE_PROGRAMS` bounds the point count to the
/// number of programs `ebpf/stack.c` defines. If the C side ever changes that
/// count, the Rust constant silently becomes a wrong bound (too low = spurious
/// rejections, too high = "program not found" at attach time), so pin the two
/// together here.
#[test]
fn stack_c_probe_stack_program_count_matches_rust_bound() {
    let src = strip_c_comments(&read_ebpf("stack.c"));

    let mut defined = 0usize;
    if src.contains("int probe_stack_0(struct pt_regs* ctx)") {
        defined += 1;
    }
    // `PROBE_STACK(n)` expands into `int probe_stack_##n(...)`.
    defined += src.matches("PROBE_STACK(").count() - 1; // -1 for the macro definition itself

    assert_eq!(
        defined,
        stackplz::config::stack::MAX_UPROBE_PROGRAMS,
        "ebpf/stack.c defines {defined} probe_stack_<i> programs but \
         MAX_UPROBE_PROGRAMS says {}; the point cap in \
         cli::stack_cmd::build_probes depends on these agreeing",
        stackplz::config::stack::MAX_UPROBE_PROGRAMS
    );
}
