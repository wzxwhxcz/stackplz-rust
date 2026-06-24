//! `-w/--point` string parser. Mirrors `user/config/config_module.go`
//! `ParseArgType` (lines 42-259) and `Parse_HookPoint` (lines 336-431).
//!
//! Parses strings like `write[int,buf:128,int]` into [`UprobeArgs`] with
//! configured [`PointArg`]s.

use super::point_arg::*;
use crate::argtype::{
    self, add_read_move_reg, consts::*, opc_add_offset, opc_add_reg, opc_move_pointer_value,
    opc_read_pointer, opc_save_addr, opc_sub_offset, opc_sub_reg, r_num_array,
};
use anyhow::{anyhow, Result};

/// arm64 register name → index. Mirrors `common/const_forarm64.go:GetRegIndex`.
fn get_reg_index(name: &str) -> u32 {
    match name {
        "x0" => 0,
        "x1" => 1,
        "x2" => 2,
        "x3" => 3,
        "x4" => 4,
        "x5" => 5,
        "x6" => 6,
        "x7" => 7,
        "x8" => 8,
        "x9" => 9,
        "x10" => 10,
        "x11" => 11,
        "x12" => 12,
        "x13" => 13,
        "x14" => 14,
        "x15" => 15,
        "x16" => 16,
        "x17" => 17,
        "x18" => 18,
        "x19" => 19,
        "x20" => 20,
        "x21" => 21,
        "x22" => 22,
        "x23" => 23,
        "x24" => 24,
        "x25" => 25,
        "x26" => 26,
        "x27" => 27,
        "x28" => 28,
        "x29" => 29,
        "lr" => 30,
        "sp" => 31,
        "pc" => 32,
        _ => panic!("ParseAsReg failed =>{name}<="),
    }
}

/// Parse a number string that may be hex (0x-prefixed) or decimal.
fn parse_num(s: &str) -> Option<u64> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// `ParseArgType(arg_str, point_arg)` — parse a single arg type string.
///
/// Mirrors `config_module.go:42-259`.
pub fn parse_arg_type(
    arg_str: &str,
    point_arg: &mut PointArg,
    dump_hex: bool,
    color: bool,
) -> Result<()> {
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
                // Phase 2 stub: filter index lookup not yet implemented.
                // For now, parse as u32 directly.
                if let Ok(idx) = fname.parse::<u32>() {
                    point_arg.add_filter_index(idx);
                }
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
            let (count_str, remaining) = split_first_colon(read_op_str);
            read_op_str = remaining;
            let size = count_str
                .parse::<u32>()
                .map_err(|_| anyhow!("parse {type_name} arg_str:{arg_str} failed"))?;
            let base = match type_name {
                "int_arr" => r_num_array(INT, size),
                "uint_arr" => r_num_array(UINT, size),
                _ => r_num_array(UINT64, size),
            };
            point_arg.set_type_index(base);
            point_arg.set_group_type(EBPF_UPROBE_ENTER);
        }
        "buf" => {
            // Buffer: default 256, or :size or :reg or :size:read_op
            let (size_str, remaining) = split_first_colon(read_op_str);
            read_op_str = remaining;
            let type_idx = if size_str.is_empty() {
                argtype::r_buffer_len(256)
            } else if let Ok(size) = size_str.parse::<u32>() {
                argtype::r_buffer_len(size)
            } else {
                // Register-based length
                let reg = get_reg_index(size_str);
                argtype::r_buffer_reg(reg)
            };
            // Set dump_hex/color on the registered type
            crate::argtype::with_type(type_idx, |at| {
                at.dump_hex = dump_hex;
                at.color = color;
            });
            point_arg.set_type_index(type_idx);
            point_arg.set_group_type(EBPF_UPROBE_ENTER);
        }
        _ => {
            // Default: look up by name in the registry
            point_arg.set_type_by_name(type_name);
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
                    if let Some(value) = parse_num(token) {
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
                        let reg_index = get_reg_index(token);
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
    color: bool,
) -> Result<Vec<UprobeArgs>> {
    if lib_path.is_empty() {
        return Err(anyhow!("library is empty, plz set with -l/--lib"));
    }
    if configs.len() > 6 {
        return Err(anyhow!("max uprobe hook point count is 6"));
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
                if let Some(n) = parse_num(after) {
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
                parse_arg_type(arg_str, &mut pa, dump_hex, color)?;
                hook_point.point_args.push(pa);
            }
        }

        points.push(hook_point);
    }

    // Clone exit points
    let point_count = points.len();
    for point_idx in 0..point_count {
        if points[point_idx].exit_offset != 0 {
            let exit_idx = points.len();
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

    #[test]
    fn parse_simple_int_args() {
        ensure_init();
        let points = parse_hook_point(&["write[int,int,int]".to_string()], "/lib/libc.so", false, false).unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].symbol, "write");
        assert_eq!(points[0].point_args.len(), 3);
        assert_eq!(points[0].point_args[0].type_index, INT);
        assert_eq!(points[0].point_args[1].type_index, INT);
    }

    #[test]
    fn parse_buf_with_size() {
        ensure_init();
        let points =
            parse_hook_point(&["write[int,buf:128,int]".to_string()], "/lib/libc.so", false, false).unwrap();
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

    #[test]
    fn parse_string_type() {
        ensure_init();
        let points = parse_hook_point(&["open[str]".to_string()], "/lib/libc.so", false, false).unwrap();
        assert_eq!(points[0].point_args[0].type_index, STRING);
    }

    #[test]
    fn parse_hex_offset_symbol() {
        ensure_init();
        let points = parse_hook_point(&["0x5B950[int]".to_string()], "/lib/libc.so", false, false).unwrap();
        assert_eq!(points[0].offset, 0x5B950);
        assert_eq!(points[0].symbol, "");
    }

    #[test]
    fn parse_symbol_with_offset() {
        ensure_init();
        let points =
            parse_hook_point(&["strstr+0x10[str,str]".to_string()], "/lib/libc.so", false, false).unwrap();
        assert_eq!(points[0].symbol, "strstr");
        assert_eq!(points[0].offset, 0x10);
    }

    #[test]
    fn parse_pointer_prefix() {
        ensure_init();
        let points = parse_hook_point(&["test[*int]".to_string()], "/lib/libc.so", false, false).unwrap();
        let pa = &points[0].point_args[0];
        // *int wraps INT in a pointer
        let at = crate::argtype::get_arg_type(pa.type_index);
        assert_eq!(at.base_type, TYPE_POINTER);
        assert!(at.is_num);
    }

    #[test]
    fn parse_hex_format_suffix() {
        ensure_init();
        let points = parse_hook_point(&["test[intx]".to_string()], "/lib/libc.so", false, false).unwrap();
        let pa = &points[0].point_args[0];
        let at = crate::argtype::get_arg_type(pa.type_index);
        assert_eq!(at.format_type, FORMAT_HEX);
    }

    #[test]
    fn parse_array_type() {
        ensure_init();
        let points = parse_hook_point(&["test[int_arr:4]".to_string()], "/lib/libc.so", false, false).unwrap();
        let pa = &points[0].point_args[0];
        let at = crate::argtype::get_arg_type(pa.type_index);
        assert_eq!(at.array_len, 4);
    }

    #[test]
    fn parse_struct_by_name() {
        ensure_init();
        let points = parse_hook_point(&["test[timespec]".to_string()], "/lib/libc.so", false, false).unwrap();
        let pa = &points[0].point_args[0];
        let at = crate::argtype::get_arg_type(pa.type_index);
        assert_eq!(at.size, SIZEOF_TIMESPEC);
    }

    #[test]
    fn parse_with_read_op() {
        ensure_init();
        let points = parse_hook_point(&["test[int:x1]".to_string()], "/lib/libc.so", false, false).unwrap();
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
        let result = parse_hook_point(&configs, "/lib/libc.so", false, false);
        assert!(result.is_err());
    }

    #[test]
    fn empty_lib_errors() {
        let result = parse_hook_point(&["test[int]".to_string()], "", false, false);
        assert!(result.is_err());
    }

    #[test]
    fn exit_point_cloning() {
        ensure_init();
        // `]0x40` suffix means exit_read with offset 0x40
        let points = parse_hook_point(&["write[int]0x40".to_string()], "/lib/libc.so", false, false).unwrap();
        // Original + exit point = 2
        assert_eq!(points.len(), 2);
        assert_eq!(points[1].offset, 0x40);
    }
}
