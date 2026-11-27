//! `-w/--point` string parser. Mirrors `user/config/config_module.go`
//! `ParseArgType` (lines 42-259) and `Parse_HookPoint` (lines 336-431).
//!
//! Parses strings like `write[int,buf:128,int]` into [`UprobeArgs`] with
//! configured [`PointArg`]s.

use super::base0::parse_base0_u64;
use super::filter::get_filter_by_name;
use super::point_arg::*;
use super::stack::MAX_UPROBE_PROGRAMS;
use crate::argtype::{
    self, add_read_move_reg, consts::*, opc_add_offset, opc_add_reg, opc_move_pointer_value,
    opc_read_pointer, opc_save_addr, opc_sub_offset, opc_sub_reg, r_num_array,
};
use anyhow::{anyhow, bail, Result};

/// arm64 register name → index. Mirrors `common/const_forarm64.go:GetRegIndex`.
/// aarch64 register names → sample index. Mirrors `RegsNameMap`
/// (`user/common/const.go:107-140`): x0..x29 = 0..29, lr = 30, sp = 31, pc = 32.
/// Go looks names up exactly, so `"x01"` is not a name (unlike `"x1"`).
fn aarch64_reg_index(name: &str) -> Option<u32> {
    let index = match name {
        "lr" => 30,
        "sp" => 31,
        "pc" => 32,
        _ => {
            let rest = name.strip_prefix('x')?;
            if rest.len() > 1 && rest.starts_with('0') {
                return None;
            }
            let index: u32 = rest.parse().ok()?;
            if index > 29 {
                return None;
            }
            index
        }
    };
    Some(index)
}

/// arm32 register names → sample index. Mirrors `RegsArmNameMap`
/// (`user/common/const.go:51-67`): r0..r10 = 0..10, fp = 11, ip = 12,
/// sp = 13, lr = 14, pc = 15.
fn arm_reg_index(name: &str) -> Option<u32> {
    let index = match name {
        "fp" => 11,
        "ip" => 12,
        "sp" => 13,
        "lr" => 14,
        "pc" => 15,
        _ => {
            let rest = name.strip_prefix('r')?;
            if rest.len() > 1 && rest.starts_with('0') {
                return None;
            }
            let index: u32 = rest.parse().ok()?;
            if index > 10 {
                return None;
            }
            index
        }
    };
    Some(index)
}

/// Resolve a register name, arch-selected like upstream's build tags:
/// `GetRegIndex` uses `RegsNameMap` on arm64 and `RegsArmNameMap` on arm
/// (`user/common/const_forarm64.go:8` / `const_forarm.go:8`).
///
/// The 64-bit fallback is restricted to the numbered arm registers
/// (`r0`..`r10`, H14): the embedded aarch32 table's buf/iovec sizes
/// reference them (`"size": "r2"` on read/write/readv/writev/vmsplice/
/// preadv/pwritev/process_vm_readv/process_vm_writev), so those names must
/// resolve on a 64-bit host too. The aliases `fp`/`ip` are NOT accepted
/// there: arm `fp` is r11 while the aarch64 frame pointer is x29, and
/// aarch64 has no `ip` — accepting them would silently read the wrong
/// register (Go/arm64 rejects both). `sp`/`lr`/`pc` never reach the
/// fallback — the aarch64 table matches them first.
fn get_reg_index(name: &str) -> Result<u32> {
    let resolved = if cfg!(target_pointer_width = "32") {
        arm_reg_index(name).or_else(|| aarch64_reg_index(name))
    } else {
        aarch64_reg_index(name).or_else(|| arm_reg_index_64(name))
    };
    // A bad register name is user input, not a bug: report it, don't panic.
    resolved.ok_or_else(|| anyhow!("ParseAsReg failed =>{name}<="))
}

/// Numbered arm registers only (`r0`..`r10` → 0..10), for the 64-bit
/// fallback in [`get_reg_index`]. No `fp`/`ip`/`sp`/`lr`/`pc` aliases —
/// see the note there.
fn arm_reg_index_64(name: &str) -> Option<u32> {
    let rest = name.strip_prefix('r')?;
    if rest.len() > 1 && rest.starts_with('0') {
        return None;
    }
    let index: u32 = rest.parse().ok()?;
    if index > 10 {
        return None;
    }
    Some(index)
}

/// `ParseArgType(arg_str, point_arg)` — parse a single arg type string.
///
/// Mirrors `config_module.go:42-259`.
pub fn parse_arg_type(arg_str: &str, point_arg: &mut PointArg, dump_hex: bool) -> Result<()> {
    let mut to_ptr = false;
    let mut type_name;
    let mut read_op_str;

    // Step 1: pointer prefix `*`
    let working = if let Some(stripped) = arg_str.strip_prefix('*') {
        to_ptr = true;
        stripped
    } else {
        arg_str
    };

    // Step 2: split type from read_op on first `:`
    if let Some(pos) = working.find(':') {
        type_name = &working[..pos];
        read_op_str = &working[pos + 1..];
    } else {
        type_name = working;
        read_op_str = "";
    }

    // Step 3: filter suffix `.f0.f1`
    if let Some(pos) = type_name.find('.') {
        let filter_part = &type_name[pos + 1..];
        type_name = &type_name[..pos];
        for fname in filter_part.split('.') {
            if !fname.is_empty() {
                // H21: Go `config_module.go:74-83` resolves the suffix by
                // name (`GetFilterIndex("f0")` — by name, like H20). A suffix
                // with no registered filter is a typo in a user-supplied
                // `-w`, so report it instead of silently losing the filter.
                // (The old stub parsed the suffix as a bare u32, which
                // accepted `.0` — not a legal Go filter name — and rejected
                // every real `.f0`.)
                let filter = get_filter_by_name(fname)
                    .ok_or_else(|| anyhow!("bad filter index {fname} in arg_str:{arg_str}"))?;
                point_arg.add_filter_index(filter.filter_index);
            }
        }
    }

    // Step 4: hex suffix `x`
    let to_hex = type_name.ends_with('x') && type_name.len() > 1;
    if to_hex {
        type_name = &type_name[..type_name.len() - 1];
    }

    // Step 5: type switch
    match type_name {
        "int" => point_arg.set_type_index(INT),
        "uint" => point_arg.set_type_index(UINT),
        "int8" => point_arg.set_type_index(INT8),
        "uint8" => point_arg.set_type_index(UINT8),
        "int16" => point_arg.set_type_index(INT16),
        "uint16" => point_arg.set_type_index(UINT16),
        "int32" => point_arg.set_type_index(INT32),
        "uint32" => point_arg.set_type_index(UINT32),
        "int64" => point_arg.set_type_index(INT64),
        "uint64" => point_arg.set_type_index(UINT64),
        "str" => {
            point_arg.set_type_index(STRING);
            point_arg.set_group_type(EBPF_UPROBE_ENTER);
        }
        "std" => {
            point_arg.set_type_index(STD_STRING);
            point_arg.set_group_type(EBPF_UPROBE_ENTER);
        }
        "str16" => {
            point_arg.set_type_index(STRING16);
            point_arg.set_group_type(EBPF_UPROBE_ENTER);
        }
        "il2cpp_string" => {
            point_arg.set_type_index(IL2CPP_STRING);
            point_arg.set_group_type(EBPF_UPROBE_ENTER);
        }
        "ptr" => {
            point_arg.set_type_index(POINTER);
        }
        "ptr_arr" | "uint_arr" | "int_arr" => {
            // Array: split read_op_str on `:` to get count_str and remaining read_op.
            // Go `config_module.go:137` parses the count with `ParseUint(..., 0, 32)`
            // (base-0 — H13).
            let (count_str, remaining) = split_first_colon(read_op_str);
            read_op_str = remaining;
            let size = parse_base0_u64(count_str)
                .ok()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| anyhow!("parse {type_name} arg_str:{arg_str} failed"))?;
            let base = match type_name {
                "int_arr" => r_num_array(INT, size),
                "uint_arr" => r_num_array(UINT, size),
                _ => r_num_array(UINT64, size),
            };
            point_arg.set_type_index(base);
            point_arg.set_group_type(EBPF_UPROBE_ENTER);
        }
        "buf" => {
            // Buffer: default 256, or :size or :reg or :size:read_op. Go
            // `config_module.go:166` parses the size with `ParseUint(..., 0, 32)`
            // (base-0); a non-numeric size falls through to the register branch.
            // A valid base-0 number that overflows u32 is a size error — Go
            // misreports it as `ParseAsReg failed`, we say `too large` (I3).
            let (size_str, remaining) = split_first_colon(read_op_str);
            read_op_str = remaining;
            let type_idx = if size_str.is_empty() {
                argtype::r_buffer_len(256)
            } else if let Ok(size) = parse_base0_u64(size_str) {
                match u32::try_from(size) {
                    Ok(size) => argtype::r_buffer_len(size),
                    Err(_) => bail!("buf size too large: {size_str}"),
                }
            } else {
                // Register-based length (non-numeric size)
                let reg = get_reg_index(size_str)?;
                argtype::r_buffer_reg(reg)
            };
            // Set dump_hex on the registered type
            crate::argtype::with_type(type_idx, |at| {
                at.dump_hex = dump_hex;
            });
            point_arg.set_type_index(type_idx);
            point_arg.set_group_type(EBPF_UPROBE_ENTER);
        }
        _ => {
            // Default: look up by name in the registry. A typo in a user `-w`
            // is a usage error, not a crash.
            point_arg.try_set_type_by_name(type_name)?;
            point_arg.set_group_type(EBPF_UPROBE_ENTER);
        }
    }

    // Step 6: apply hex format
    if to_hex {
        point_arg.set_hex_format();
    }

    // Step 7: apply pointer wrapping
    if to_ptr {
        point_arg.to_pointer_type();
        point_arg.set_group_type(EBPF_UPROBE_ENTER);
    }

    // Step 8: read-op expression compiler (address computation)
    if !read_op_str.is_empty() {
        compile_read_op(read_op_str, point_arg)?;
    }

    Ok(())
}

/// Split a string on the first `:`, returning (before, after).
/// If no `:`, returns (input, "").
fn split_first_colon(s: &str) -> (&str, &str) {
    match s.find(':') {
        Some(pos) => (&s[..pos], &s[pos + 1..]),
        None => (s, ""),
    }
}

/// Compile a read-op expression like `sp+0x20-0x8.+8.-4+0x16` into ops.
///
/// Mirrors `config_module.go:207-257`.
fn compile_read_op(read_op_str: &str, point_arg: &mut PointArg) -> Result<()> {
    let mut has_first_op = false;

    for (ptr_idx, hop) in read_op_str.split('.').enumerate() {
        if ptr_idx > 0 {
            point_arg.add_extra_op(opc_read_pointer());
            point_arg.add_extra_op(opc_move_pointer_value());
        }
        if hop.is_empty() {
            continue;
        }

        // Parse the hop: a sequence of +/- separated tokens
        let v = format!("{hop}+");
        let mut last_op = "";
        let chars: Vec<char> = v.chars().collect();
        let mut start = 0usize;
        let mut i = 0usize;

        while i < chars.len() {
            if chars[i] == '+' || chars[i] == '-' {
                let op = chars[i];
                let token = &v[start..i];
                if !token.is_empty() {
                    if let Ok(value) = parse_base0_u64(token) {
                        if !has_first_op {
                            return Err(anyhow!("first op must be reg"));
                        }
                        if last_op == "-" {
                            let op = crate::argtype::get_op(opc_sub_offset());
                            point_arg.add_extra_op(op.new_value(value));
                        } else {
                            let op = crate::argtype::get_op(opc_add_offset());
                            point_arg.add_extra_op(op.new_value(value));
                        }
                    } else {
                        // Register name
                        let reg_index = get_reg_index(token)?;
                        point_arg.add_extra_op(add_read_move_reg(u64::from(reg_index)));
                        if has_first_op {
                            if last_op == "-" {
                                point_arg.add_extra_op(opc_sub_reg());
                            } else {
                                point_arg.add_extra_op(opc_add_reg());
                            }
                        }
                        if !has_first_op {
                            has_first_op = true;
                        }
                    }
                }
                last_op = if op == '-' { "-" } else { "+" };
                start = i + 1;
            }
            i += 1;
        }
    }
    point_arg.add_extra_op(opc_save_addr());
    Ok(())
}

/// `Parse_HookPoint(configs)` — parse a list of `-w` strings into `UprobeArgs`.
///
/// Mirrors `config_module.go:336-431`.
pub fn parse_hook_point(
    configs: &[String],
    lib_path: &str,
    dump_hex: bool,
) -> Result<Vec<UprobeArgs>> {
    if lib_path.is_empty() {
        return Err(anyhow!("library is empty, plz set with -l/--lib"));
    }
    if configs.len() > MAX_UPROBE_PROGRAMS {
        return Err(anyhow!(
            "max uprobe hook point count is {MAX_UPROBE_PROGRAMS}"
        ));
    }

    let mut points = Vec::new();

    for (point_index, config_str) in configs.iter().enumerate() {
        let mut config_str = config_str.clone();
        let mut exit_read = false;
        let mut bind_syscall = false;

        // Suffix-based flags
        if config_str.ends_with("]ss") {
            config_str = config_str[..config_str.len() - 2].to_string();
            exit_read = true;
            bind_syscall = true;
        } else if config_str.ends_with("]s") {
            config_str = config_str[..config_str.len() - 1].to_string();
            bind_syscall = true;
        }

        // Exit offset after `]`
        let mut exit_offset: u64 = 0;
        if let Some(pos) = config_str.rfind(']') {
            let after = &config_str[pos + 1..];
            if !after.is_empty() {
                exit_read = true;
                // NOTE: a garbage offset after `]` is silently kept as 0
                // (H22, out of scope for this round — Go panics here).
                if let Ok(n) = parse_base0_u64(after) {
                    exit_offset = n;
                }
            }
        }

        // Regex: (\w+)(\+0x[hex]+)?(\[...\])?
        // We do a manual parse since the regex is simple.
        let (symbol_or_off, offset_suffix, args_str) = parse_point_regex(&config_str)?;

        let mut hook_point = UprobeArgs::new();
        hook_point.bind_syscall = bind_syscall;
        hook_point.exit_read = exit_read;
        hook_point.exit_offset = exit_offset;
        hook_point.index = point_index as u32;
        hook_point.offset = 0;
        hook_point.lib_path = lib_path.to_string();
        hook_point.name = symbol_or_off.clone();

        if let Some(rest) = symbol_or_off
            .strip_prefix("0x")
            .or_else(|| symbol_or_off.strip_prefix("0X"))
        {
            hook_point.offset = u64::from_str_radix(rest, 16)
                .map_err(|e| anyhow!("parse offset {symbol_or_off} failed: {e}"))?;
            hook_point.symbol = String::new();
        } else {
            hook_point.symbol = symbol_or_off.clone();
        }

        // Additional +0xNN offset suffix
        if let Some(off_str) = offset_suffix {
            if let Some(rest) = off_str
                .strip_prefix("+0x")
                .or_else(|| off_str.strip_prefix("+0X"))
            {
                hook_point.offset = u64::from_str_radix(rest, 16)
                    .map_err(|e| anyhow!("parse offset suffix {off_str} failed: {e}"))?;
            }
        }

        // Parse args
        if let Some(args) = args_str {
            hook_point.args_str = args.clone();
            for (arg_index, arg_str) in args.split(',').enumerate() {
                let arg_name = format!("arg_{arg_index}");
                let mut pa = PointArg::new_uprobe(&arg_name, POINTER, arg_index as u32);
                parse_arg_type(arg_str, &mut pa, dump_hex)?;
                hook_point.point_args.push(pa);
            }
        }

        points.push(hook_point);
    }

    // Clone exit points. Each clone needs its own `probe_stack_<i>` program and
    // `ebpf/stack.c` defines only `MAX_UPROBE_PROGRAMS` of them, so the expansion
    // is what the limit has to bound (the input cap above does not: 6 inputs can
    // become 12 points).
    let point_count = points.len();
    for point_idx in 0..point_count {
        if points[point_idx].exit_offset != 0 {
            let exit_idx = points.len();
            if exit_idx >= MAX_UPROBE_PROGRAMS {
                bail!(
                    "hook point {exit_idx} (after exit-point expansion) exceeds the \
                     {MAX_UPROBE_PROGRAMS} uprobe programs in the BPF object"
                );
            }
            let exit_point = points[point_idx].get_exit_point(exit_idx);
            // Mark the original's enter_key
            points[point_idx].enter_key = points[point_idx].index + 1;
            points.push(exit_point);
        }
    }

    Ok(points)
}

/// Manual implementation of the regex `(\w+)(\+0x[[:xdigit:]]+)?(\[.+?\])?`.
/// Returns (symbol, optional_offset_suffix, optional_args).
fn parse_point_regex(s: &str) -> Result<(String, Option<String>, Option<String>)> {
    let chars: Vec<char> = s.chars().collect();
    let mut pos = 0;

    // Group 1: \w+ (word chars: alphanumeric + underscore)
    let start = pos;
    while pos < chars.len() && (chars[pos].is_alphanumeric() || chars[pos] == '_') {
        pos += 1;
    }
    if pos == start {
        return Err(anyhow!("parse for {s} failed: no symbol match"));
    }
    let symbol: String = chars[start..pos].iter().collect();

    // Group 2: optional +0x[hex]+
    let offset_suffix = if pos + 3 < chars.len()
        && chars[pos] == '+'
        && chars[pos + 1] == '0'
        && (chars[pos + 2] == 'x' || chars[pos + 2] == 'X')
    {
        let off_start = pos;
        pos += 3; // skip +0x
        while pos < chars.len() && chars[pos].is_ascii_hexdigit() {
            pos += 1;
        }
        Some(chars[off_start..pos].iter().collect())
    } else {
        None
    };

    // Group 3: optional [...] (non-greedy to the last ])
    let args = if pos < chars.len() && chars[pos] == '[' {
        // Find the matching ]
        if let Some(end) = chars[pos..].iter().position(|&c| c == ']') {
            let inner: String = chars[pos + 1..pos + end].iter().collect();
            pos = pos + end + 1;
            Some(inner)
        } else {
            None
        }
    } else {
        None
    };

    // Allow trailing content (exit offset etc.) — we already parsed it above.
    let _ = pos;

    Ok((symbol, offset_suffix, args))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_init() {
        crate::argtype::init_argtypes();
    }

    /// Test helper: parse a single hook point with default flags.
    fn hp(cfg: &str) -> Vec<super::UprobeArgs> {
        parse_hook_point(&[cfg.to_string()], "/lib/libc.so", false).unwrap()
    }

    #[test]
    fn parse_simple_int_args() {
        ensure_init();
        let points = hp("write[int,int,int]");
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].symbol, "write");
        assert_eq!(points[0].point_args.len(), 3);
        assert_eq!(points[0].point_args[0].type_index, INT);
        assert_eq!(points[0].point_args[1].type_index, INT);
    }

    #[test]
    fn parse_buf_with_size() {
        ensure_init();
        let points = hp("write[int,buf:128,int]");
        assert_eq!(points[0].point_args.len(), 3);
        // arg_0 = int
        assert_eq!(points[0].point_args[0].type_index, INT);
        // arg_1 = buffer(128) — should have buffer parent
        assert!(points[0].point_args[1].is_buffer());
        let buf_at = crate::argtype::get_arg_type(points[0].point_args[1].type_index);
        assert_eq!(buf_at.size, 128);
        // arg_2 = int
        assert_eq!(points[0].point_args[2].type_index, INT);
    }

    /// H13: `-w` buf size is base-0 — `"010"` is 8 bytes, not 10;
    /// `"0x100"` is 256; plain `"10"` stays 10.
    #[test]
    fn parse_buf_size_base0() {
        ensure_init();
        for (size, expected) in [("010", 8), ("0x100", 256), ("10", 10)] {
            let points = hp(&format!("write[int,buf:{size},int]"));
            let buf_at = crate::argtype::get_arg_type(points[0].point_args[1].type_index);
            assert_eq!(buf_at.size, expected, "size={size}");
        }
    }

    /// I3: a valid base-0 buf size that overflows u32 is reported as a size
    /// error (`too large`), not misdiagnosed as a bad register name. Go
    /// (`config_module.go:170-177`) falls through to the register branch on
    /// overflow and reports `ParseAsReg failed`; we divert only the overflow
    /// case to a truthful message.
    #[test]
    fn buf_size_overflow_reports_too_large_not_reg() {
        ensure_init();
        let err = parse_hook_point(
            &["write[int,buf:0x100000000,int]".to_string()],
            "/lib/libc.so",
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
        assert!(!err.to_string().contains("ParseAsReg"), "{err}");
    }

    /// I3: a non-numeric size (`sp`) still takes the register branch — the
    /// register-based buffer type has size 0 and its length op comes from the
    /// register, unchanged from before.
    #[test]
    fn buf_size_register_name_still_uses_register_branch() {
        ensure_init();
        let points = hp("write[int,buf:sp,int]");
        let pa = &points[0].point_args[1];
        assert!(pa.is_buffer());
        let at = crate::argtype::get_arg_type(pa.type_index);
        assert_eq!(at.size, 0, "register-based buffer has no fixed size");
    }

    /// H13: `-w` array count is base-0 too — `"0x4"` is 4.
    #[test]
    fn parse_array_count_base0() {
        ensure_init();
        let points = hp("test[int_arr:0x4]");
        let pa = &points[0].point_args[0];
        let at = crate::argtype::get_arg_type(pa.type_index);
        assert_eq!(at.array_len, 4);
    }

    /// H13: a read-op offset token accepts Go base-0 literals — `0b101`
    /// parses as 5 (the old hex-or-decimal `parse_num` rejected it and the
    /// token fell through to a register lookup that failed).
    #[test]
    fn parse_read_op_offset_base0() {
        ensure_init();
        let points = hp("test[int:sp+0b101]");
        let pa = &points[0].point_args[0];
        let offset = pa
            .extra_op_list
            .iter()
            .map(|&idx| crate::argtype::get_op(idx))
            .find(|op| op.code == crate::contract::enums::OpCode::AddOffset)
            .expect("an AddOffset op for the 0b101 token");
        assert_eq!(offset.value, 5);
    }

    /// H21: a filter suffix resolves by name against the registered
    /// filters (`int.f0` → the index of `--filter eq:100`, like Go's
    /// `GetFilterIndex("f0")`). The index is read back from `add_filter`
    /// rather than hard-coded, because the global helper is shared with
    /// other tests running in parallel.
    #[test]
    fn parse_filter_suffix_by_name() {
        ensure_init();
        let idx = crate::config::filter::add_filter("eq:100").unwrap();
        let points = hp(&format!("write[int.f{},int]", idx - 1));
        assert_eq!(points[0].point_args[0].filter_index_list, vec![idx]);
    }

    /// H21: an unregistered filter name, and a bare numeric suffix (`.0`,
    /// which the old stub accepted but Go rejects — it is not a filter
    /// name), both fail instead of silently losing the filter.
    #[test]
    fn parse_filter_suffix_unknown_name_errors() {
        ensure_init();
        assert!(parse_hook_point(&["write[int.f99]".to_string()], "/lib/libc.so", false).is_err());
        assert!(parse_hook_point(&["write[int.0]".to_string()], "/lib/libc.so", false).is_err());
    }

    /// H14: same arch-selected register table as `file_parser` — on 64-bit
    /// the aarch64 table wins and the arm fallback accepts only the numbered
    /// registers (`"r2"` for the aarch32 table's buf sizes); `"fp"`/`"ip"`
    /// are rejected.
    #[test]
    fn reg_index_is_arch_selected_like_go_build_tags() {
        if cfg!(target_pointer_width = "64") {
            assert_eq!(get_reg_index("x29").unwrap(), 29);
            assert_eq!(get_reg_index("sp").unwrap(), 31);
            assert_eq!(get_reg_index("r2").unwrap(), 2);
            assert!(get_reg_index("fp").is_err());
            assert!(get_reg_index("ip").is_err());
        } else {
            assert_eq!(get_reg_index("fp").unwrap(), 11);
            assert_eq!(get_reg_index("x2").unwrap(), 2);
        }
    }

    #[test]
    fn parse_string_type() {
        ensure_init();
        let points = hp("open[str]");
        assert_eq!(points[0].point_args[0].type_index, STRING);
    }

    #[test]
    fn parse_hex_offset_symbol() {
        ensure_init();
        let points = hp("0x5B950[int]");
        assert_eq!(points[0].offset, 0x5B950);
        assert_eq!(points[0].symbol, "");
    }

    #[test]
    fn parse_symbol_with_offset() {
        ensure_init();
        let points = hp("strstr+0x10[str,str]");
        assert_eq!(points[0].symbol, "strstr");
        assert_eq!(points[0].offset, 0x10);
    }

    #[test]
    fn parse_pointer_prefix() {
        ensure_init();
        let points = hp("test[*int]");
        let pa = &points[0].point_args[0];
        // *int wraps INT in a pointer
        let at = crate::argtype::get_arg_type(pa.type_index);
        assert_eq!(at.base_type, TYPE_POINTER);
        assert!(at.is_num);
    }

    #[test]
    fn parse_hex_format_suffix() {
        ensure_init();
        let points = hp("test[intx]");
        let pa = &points[0].point_args[0];
        let at = crate::argtype::get_arg_type(pa.type_index);
        assert_eq!(at.format_type, FORMAT_HEX);
    }

    #[test]
    fn parse_array_type() {
        ensure_init();
        let points = hp("test[int_arr:4]");
        let pa = &points[0].point_args[0];
        let at = crate::argtype::get_arg_type(pa.type_index);
        assert_eq!(at.array_len, 4);
    }

    #[test]
    fn parse_struct_by_name() {
        ensure_init();
        let points = hp("test[timespec]");
        let pa = &points[0].point_args[0];
        let at = crate::argtype::get_arg_type(pa.type_index);
        assert_eq!(at.size, SIZEOF_TIMESPEC);
    }

    #[test]
    fn parse_with_read_op() {
        ensure_init();
        let points = hp("test[int:x1]");
        let pa = &points[0].point_args[0];
        // x1 read_op should generate extra_op_list ending with SAVE_ADDR
        assert!(!pa.extra_op_list.is_empty());
        // Last op should be SAVE_ADDR
        let last_op = pa.extra_op_list.last().copied().unwrap();
        let op = crate::argtype::get_op(last_op);
        assert_eq!(op.code, crate::contract::enums::OpCode::SaveAddr);
    }

    #[test]
    fn parse_max_six_points() {
        ensure_init();
        let configs: Vec<String> = (0..7).map(|i| format!("sym{i}[int]")).collect();
        let result = parse_hook_point(&configs, "/lib/libc.so", false);
        assert!(result.is_err());
    }

    #[test]
    fn empty_lib_errors() {
        let result = parse_hook_point(&["test[int]".to_string()], "", false);
        assert!(result.is_err());
    }

    #[test]
    fn exit_point_cloning() {
        ensure_init();
        // `]0x40` suffix means exit_read with offset 0x40
        let points = hp("write[int]0x40");
        // Original + exit point = 2
        assert_eq!(points.len(), 2);
        assert_eq!(points[1].offset, 0x40);
    }
}
