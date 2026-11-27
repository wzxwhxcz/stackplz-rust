//! Configuration file parser for YAML/JSON syscall and uprobe configs.
//!
//! Mirrors `user/config/config_file.go` (221 lines) to support loading hook
//! configurations from structured files instead of command-line strings.
//!
//! ## File Format Example (syscall.yaml)
//! ```yaml
//! type: syscall
//! points:
//!   - nr: 1
//!     name: write
//!     signal: enter
//!     params:
//!       - name: fd
//!         type: int
//!       - name: buf
//!         type: buf
//!         size: "256"
//!       - name: count
//!         type: uint
//! ```

use anyhow::{anyhow, Result};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt;

use super::base0::parse_base0_u64;
use super::point_arg::{PointArg, EBPF_SYS_ALL, EBPF_SYS_ENTER, EBPF_SYS_EXIT, EBPF_UPROBE_ENTER};
use crate::argtype::consts::{INT, POINTER, UINT, UINT64};

/// Parameter configuration in a point definition.
/// Mirrors `ParamConfig` in config_file.go:11-20.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamConfig {
    /// Parameter name (optional, defaults to "a0", "a1", etc.)
    #[serde(default)]
    pub name: String,

    /// Type name: "int", "uint", "str", "buf", "ptr", struct names, etc.
    #[serde(rename = "type")]
    pub type_name: String,

    /// Format hint: "hex", "hexdump", "inotify_flags", "access_flags", etc.
    #[serde(default)]
    pub format: String,

    /// Size for arrays/buffers: numeric string or register name
    #[serde(default)]
    pub size: String,

    /// Additional config (reserved for future use)
    #[serde(default)]
    pub more: String,

    /// Filter expressions (e.g., ["==1234", ">100"])
    #[serde(default)]
    pub filter: Vec<String>,

    /// Register name override (e.g., "x3" instead of default arg_index)
    #[serde(default)]
    pub reg: String,

    /// Read-op expression (e.g., "sp+0x20-0x8.+8")
    #[serde(default)]
    pub read_op: String,
}

/// Hook point configuration.
/// Mirrors `PointConfig` in config_file.go:22-26.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointConfig {
    /// Symbol or function name
    pub name: String,

    /// Kill signal sent when this point fires, e.g. "SIGSTOP" (Go config_module.go:297-298);
    /// empty means none. The enter/exit/all vocabulary belongs to ParamConfig.more, not to this field.
    #[serde(default)]
    pub signal: String,

    /// Parameter list
    #[serde(default)]
    pub params: Vec<ParamConfig>,
}

/// Syscall-specific point with syscall number.
/// Mirrors `SyscallPointConfig` in config_file.go:28-31.
///
/// Round 11 / N2: `Deserialize` is hand-written, not derived. The struct
/// used to carry `#[serde(flatten)]` on `point`, and serde silently drops
/// unknown keys that arrive through a flatten boundary — `deny_unknown_fields`
/// on the inner `PointConfig` does not fire there (J1's protection had a
/// hole: `{"nr":1,"name":"write","nrr":9}` parsed as `Ok`). The manual impl
/// rejects any key outside `nr`/`name`/`signal`/`params`, for JSON and YAML
/// alike (it is `MapAccess`-based, not JSON-specific).
#[derive(Debug, Clone, Serialize)]
pub struct SyscallPointConfig {
    /// Syscall number
    pub nr: u32,

    pub point: PointConfig,
}

impl<'de> serde::de::Deserialize<'de> for SyscallPointConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Nr,
            Name,
            Signal,
            Params,
        }

        struct SyscallPointConfigVisitor;

        impl<'de> Visitor<'de> for SyscallPointConfigVisitor {
            type Value = SyscallPointConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct SyscallPointConfig")
            }

            fn visit_map<V>(self, mut map: V) -> Result<SyscallPointConfig, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut nr = None;
                let mut name = None;
                let mut signal = None;
                let mut params = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Nr => {
                            if nr.is_some() {
                                return Err(de::Error::duplicate_field("nr"));
                            }
                            nr = Some(map.next_value()?);
                        }
                        Field::Name => {
                            if name.is_some() {
                                return Err(de::Error::duplicate_field("name"));
                            }
                            name = Some(map.next_value()?);
                        }
                        Field::Signal => {
                            if signal.is_some() {
                                return Err(de::Error::duplicate_field("signal"));
                            }
                            signal = Some(map.next_value()?);
                        }
                        Field::Params => {
                            if params.is_some() {
                                return Err(de::Error::duplicate_field("params"));
                            }
                            params = Some(map.next_value()?);
                        }
                    }
                }
                let nr = nr.ok_or_else(|| de::Error::missing_field("nr"))?;
                let name = name.ok_or_else(|| de::Error::missing_field("name"))?;
                let signal = signal.unwrap_or_default();
                let params = params.unwrap_or_default();
                Ok(SyscallPointConfig {
                    nr,
                    point: PointConfig {
                        name,
                        signal,
                        params,
                    },
                })
            }
        }

        const FIELDS: &[&str] = &["nr", "name", "signal", "params"];
        deserializer.deserialize_struct("SyscallPointConfig", FIELDS, SyscallPointConfigVisitor)
    }
}

/// File configuration base trait.
/// Mirrors `IFileConfig` + `FileConfig` in config_file.go:33-43.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Config type: "syscall" or "uprobe"
    #[serde(rename = "type")]
    pub config_type: String,
}

/// Uprobe configuration file.
/// Mirrors `UprobeFileConfig` in config_file.go:212-216.
///
/// Round 11 / N2: `Deserialize` is hand-written for the same reason as
/// [`SyscallPointConfig`]: the old `#[serde(flatten)]` on `base` let unknown
/// top-level keys (e.g. `bogus_top`) through silently. Only
/// `type`/`library`/`points` are accepted now.
#[derive(Debug, Clone, Serialize)]
pub struct UprobeFileConfig {
    pub base: FileConfig,

    /// Library path
    pub library: String,

    /// Hook points
    #[serde(default)]
    pub points: Vec<PointConfig>,
}

impl<'de> serde::de::Deserialize<'de> for UprobeFileConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Type,
            Library,
            Points,
        }

        struct UprobeFileConfigVisitor;

        impl<'de> Visitor<'de> for UprobeFileConfigVisitor {
            type Value = UprobeFileConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct UprobeFileConfig")
            }

            fn visit_map<V>(self, mut map: V) -> Result<UprobeFileConfig, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut config_type = None;
                let mut library = None;
                let mut points = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Type => {
                            if config_type.is_some() {
                                return Err(de::Error::duplicate_field("type"));
                            }
                            config_type = Some(map.next_value()?);
                        }
                        Field::Library => {
                            if library.is_some() {
                                return Err(de::Error::duplicate_field("library"));
                            }
                            library = Some(map.next_value()?);
                        }
                        Field::Points => {
                            if points.is_some() {
                                return Err(de::Error::duplicate_field("points"));
                            }
                            points = Some(map.next_value()?);
                        }
                    }
                }
                let config_type = config_type.ok_or_else(|| de::Error::missing_field("type"))?;
                let library = library.ok_or_else(|| de::Error::missing_field("library"))?;
                let points = points.unwrap_or_default();
                Ok(UprobeFileConfig {
                    base: FileConfig { config_type },
                    library,
                    points,
                })
            }
        }

        const FIELDS: &[&str] = &["type", "library", "points"];
        deserializer.deserialize_struct("UprobeFileConfig", FIELDS, UprobeFileConfigVisitor)
    }
}

/// Syscall configuration file.
/// Mirrors `SyscallFileConfig` in config_file.go:218-221.
///
/// Round 11 / N2: `Deserialize` is hand-written for the same reason as
/// [`SyscallPointConfig`]: the old `#[serde(flatten)]` on `base` let unknown
/// top-level keys through silently. Only `type`/`points` are accepted now.
#[derive(Debug, Clone, Serialize)]
pub struct SyscallFileConfig {
    pub base: FileConfig,

    /// Syscall hook points
    #[serde(default)]
    pub points: Vec<SyscallPointConfig>,
}

impl<'de> serde::de::Deserialize<'de> for SyscallFileConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Type,
            Points,
        }

        struct SyscallFileConfigVisitor;

        impl<'de> Visitor<'de> for SyscallFileConfigVisitor {
            type Value = SyscallFileConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct SyscallFileConfig")
            }

            fn visit_map<V>(self, mut map: V) -> Result<SyscallFileConfig, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut config_type = None;
                let mut points = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Type => {
                            if config_type.is_some() {
                                return Err(de::Error::duplicate_field("type"));
                            }
                            config_type = Some(map.next_value()?);
                        }
                        Field::Points => {
                            if points.is_some() {
                                return Err(de::Error::duplicate_field("points"));
                            }
                            points = Some(map.next_value()?);
                        }
                    }
                }
                let config_type = config_type.ok_or_else(|| de::Error::missing_field("type"))?;
                let points = points.unwrap_or_default();
                Ok(SyscallFileConfig {
                    base: FileConfig { config_type },
                    points,
                })
            }
        }

        const FIELDS: &[&str] = &["type", "points"];
        deserializer.deserialize_struct("SyscallFileConfig", FIELDS, SyscallFileConfigVisitor)
    }
}

impl ParamConfig {
    /// Convert ParamConfig to PointArg.
    /// Mirrors `ParamConfig.GetPointArg()` in config_file.go:45-210.
    pub fn get_point_arg(&self, arg_index: u32, point_type: u32) -> Result<PointArg> {
        // Default parameter name: a0, a1, a2, ...
        let arg_name = if self.name.is_empty() {
            format!("a{}", arg_index)
        } else {
            self.name.clone()
        };

        // Default register index = arg_index, unless explicitly specified
        let reg_index = if self.reg.is_empty() {
            arg_index
        } else {
            get_reg_index(&self.reg)?
        };

        // Create base PointArg
        let mut point_arg = match point_type {
            EBPF_SYS_ENTER | EBPF_SYS_EXIT | EBPF_SYS_ALL => {
                // For syscalls, use new() with point_type and set reg_index manually
                let mut pa = PointArg::new(&arg_name, POINTER, point_type);
                pa.reg_index = reg_index;
                pa
            }
            EBPF_UPROBE_ENTER => PointArg::new_uprobe(&arg_name, POINTER, reg_index),
            _ => return Err(anyhow!("unsupported point_type: {}", point_type)),
        };

        // Parse type with optional pointer prefix
        let mut to_ptr = false;
        let mut type_name = self.type_name.as_str();
        if let Some(stripped) = type_name.strip_prefix('*') {
            to_ptr = true;
            type_name = stripped;
        }

        // Type-specific processing
        match type_name {
            "buf" => {
                // Buffer with size from config or register. Go
                // `config_file.go:82-88` parses the size with
                // `ParseUint(this.Size, 0, 32)` (base-0); an over-wide or
                // non-numeric size falls through to the register branch (H13).
                let type_idx = if self.size.is_empty() {
                    crate::argtype::r_buffer_len(256)
                } else if let Some(size) = parse_base0_u64(&self.size)
                    .ok()
                    .and_then(|v| u32::try_from(v).ok())
                {
                    crate::argtype::r_buffer_len(size)
                } else {
                    // Size from register
                    let reg = get_reg_index(&self.size)?;
                    crate::argtype::r_buffer_reg(reg)
                };
                point_arg.set_type_index(type_idx);
                point_arg.set_group_type(EBPF_UPROBE_ENTER);
            }

            "iovec" => {
                // `R_IOVEC_REG(this.Size)`: `size` is the register holding the
                // iovec count (upstream `GetRegIndex`, panic on a bad name).
                let type_idx = crate::argtype::r_iovec_reg(get_reg_index(&self.size)?);
                point_arg.set_type_index(type_idx);
                point_arg.set_group_type(EBPF_UPROBE_ENTER);
            }

            "int_arr" | "uint_arr" | "ptr_arr" => {
                // Array with required size (Go `ParseUint(this.Size, 0, 32)`,
                // base-0 — H13).
                let size = parse_base0_u64(&self.size)
                    .ok()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| anyhow!("parse {} array size failed", type_name))?;
                let base_type = match type_name {
                    "int_arr" => INT,
                    "uint_arr" => UINT,
                    _ => UINT64,
                };
                // `R_NUM_ARRAY_FMT(base, size, this.Format)`: only `hex` changes
                // the element format; everything else stays decimal.
                let type_idx = crate::argtype::r_num_array_fmt(base_type, size, &self.format);
                point_arg.set_type_index(type_idx);
                point_arg.set_group_type(EBPF_UPROBE_ENTER);
            }

            "str" | "std" | "str16" | "il2cpp_string" => {
                // String types
                point_arg.try_set_type_by_name(type_name)?;
                point_arg.set_group_type(EBPF_UPROBE_ENTER);
            }

            "int" | "uint" | "int8" | "uint8" | "int16" | "uint16" | "int32" | "uint32"
            | "int64" | "uint64" => {
                // Numeric types
                point_arg.try_set_type_by_name(type_name)?;
            }

            _ => {
                // Struct types registered in argtype
                point_arg.try_set_type_by_name(type_name)?;
            }
        }

        // Apply pointer wrapping if needed
        if to_ptr {
            point_arg.to_pointer_type();
            point_arg.set_group_type(EBPF_UPROBE_ENTER);
        }

        // Apply format flags
        match self.format.as_str() {
            "hex" | "hexdump" => {
                point_arg.set_hex_format();
            }
            "inotify_flags" | "access_flags" | "mmap_flags" | "mremap_flags" | "file_flags"
            | "prot_flags" | "fcntl_flags" | "statx_flags" | "unlink_flags" | "socket_flags"
            | "perm_flags" | "msg_flags" => {
                // H15: Go implements these for real (`config_file.go:135` calls
                // `SetFlagsFormat`, backed by per-format tables in
                // `argtype_flags.go`); this crate has no flags tables (an R2
                // "not ported" scope decision), so the value renders as a bare
                // integer. That used to happen silently; warn once per format
                // instead (the G9 lesson). Rejecting is NOT an option: the
                // shipped syscall tables themselves carry these formats (25
                // params in the aarch64 table, 2 in aarch32), so an error here
                // would make the embedded table unloadable (verified: a reject
                // breaks 20 table tests).
                warn_flags_format_once(&self.format);
            }
            "" => {
                // No format specified
            }
            _ => {
                return Err(anyhow!("unsupported format type: {}", self.format));
            }
        }

        // Apply filters
        for filter_expr in &self.filter {
            let filter_index = crate::config::filter::add_filter(filter_expr)
                .map_err(|e| anyhow!("add filter failed: {}", e))?;
            point_arg.add_filter_index(filter_index);
        }

        // Compile read_op expression
        if !self.read_op.is_empty() {
            compile_read_op(&self.read_op, &mut point_arg)?;
        }

        Ok(point_arg)
    }
}

/// Compile read_op expression into extra_op_list.
/// Mirrors the read_op parsing logic in config_file.go:158-208.
///
/// Example: "sp+0x20-0x8.+8.-4+0x16"
/// - Read sp+0x20-0x8, dereference pointer
/// - Add 8, dereference pointer  
/// - Subtract 4, add 0x16
/// - Use result as final address
fn compile_read_op(read_op_str: &str, point_arg: &mut PointArg) -> Result<()> {
    use crate::argtype::{
        add_read_move_reg, get_op, opc_add_offset, opc_add_reg, opc_move_pointer_value,
        opc_read_pointer, opc_save_addr, opc_sub_offset, opc_sub_reg,
    };

    let mut has_first_op = false;

    // Split by '.' for pointer dereferences
    for (ptr_idx, hop) in read_op_str.split('.').enumerate() {
        // Insert pointer read ops between hops
        if ptr_idx > 0 {
            point_arg.add_extra_op(opc_read_pointer());
            point_arg.add_extra_op(opc_move_pointer_value());
        }

        if hop.is_empty() {
            continue;
        }

        // Parse arithmetic expression within this hop
        let v = format!("{}+", hop);
        let mut last_op = "";
        let chars: Vec<char> = v.chars().collect();
        let mut start = 0;

        for i in 0..chars.len() {
            if chars[i] == '+' || chars[i] == '-' {
                let op = chars[i];
                let token: String = chars[start..i].iter().collect();

                if !token.is_empty() {
                    // Try parsing as numeric constant
                    if let Ok(value) = parse_num(&token) {
                        if !has_first_op {
                            return Err(anyhow!("first op must be reg, got: {}", token));
                        }
                        if last_op == "-" {
                            let op_obj = get_op(opc_sub_offset());
                            point_arg.add_extra_op(op_obj.new_value(value));
                        } else {
                            let op_obj = get_op(opc_add_offset());
                            point_arg.add_extra_op(op_obj.new_value(value));
                        }
                    } else {
                        // Register name
                        let reg_index = get_reg_index(&token)?;
                        point_arg.add_extra_op(add_read_move_reg(reg_index as u64));

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
        }
    }

    // Save final computed address
    point_arg.add_extra_op(opc_save_addr());
    Ok(())
}

/// Warn that a flags format renders as a plain integer (H15), once per
/// format per process. Returns true when this call actually warned (false
/// when the format was already warned about).
fn warn_flags_format_once(format: &str) -> bool {
    use std::sync::Mutex;
    static WARNED_FORMATS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut warned = WARNED_FORMATS.lock().unwrap_or_else(|e| e.into_inner());
    if warned.iter().any(|f| f == format) {
        return false;
    }
    warned.push(format.to_string());
    eprintln!("warning: flags format '{format}' is not implemented, rendering as integer");
    true
}

/// Parse a numeric string like Go `strconv.ParseUint(s, 0, 64)` (H13): the
/// shared base-0 parser accepts `0x` hex, `0b` binary, `0o`/leading-`0`
/// octal, decimal, and Go-style underscores.
fn parse_num(s: &str) -> Result<u64> {
    parse_base0_u64(s).map_err(|e| anyhow!("{e}"))
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_num() {
        assert_eq!(parse_num("0x100").unwrap(), 256);
        assert_eq!(parse_num("0X1a").unwrap(), 26);
    }

    #[test]
    fn parse_octal_num() {
        assert_eq!(parse_num("0777").unwrap(), 511);
        assert_eq!(parse_num("010").unwrap(), 8);
    }

    #[test]
    fn parse_decimal_num() {
        assert_eq!(parse_num("1234").unwrap(), 1234);
        assert_eq!(parse_num("0").unwrap(), 0);
    }

    /// H13: read-op tokens go through the shared base-0 parser, so Go's
    /// `0b`/`0o`/underscore literals parse and `"08"` (illegal octal under
    /// Go base-0) still errors.
    #[test]
    fn parse_base0_num() {
        assert_eq!(parse_num("0b101").unwrap(), 5);
        assert_eq!(parse_num("0o17").unwrap(), 15);
        assert_eq!(parse_num("1_000").unwrap(), 1000);
        assert_eq!(parse_num("0x_100").unwrap(), 256);
        assert_eq!(parse_num("0x100").unwrap(), 256);
        assert_eq!(parse_num("010").unwrap(), 8);
        assert!(parse_num("08").is_err());
        assert!(parse_num("0x10000000000000000").is_err());
    }

    fn ensure_init() {
        crate::argtype::init_argtypes();
    }

    fn param(type_name: &str, size: &str, format: &str) -> ParamConfig {
        ParamConfig {
            name: String::new(),
            type_name: type_name.to_string(),
            format: format.to_string(),
            size: size.to_string(),
            more: String::new(),
            filter: Vec::new(),
            reg: String::new(),
            read_op: String::new(),
        }
    }

    /// H13: buf size is base-0 — `"010"` is 8 bytes, not 10; `"0x100"` is
    /// 256; plain `"10"` stays 10.
    #[test]
    fn buf_size_parses_base0() {
        ensure_init();
        for (size, expected) in [("010", 8), ("0x100", 256), ("10", 10)] {
            let pa = param("buf", size, "")
                .get_point_arg(1, EBPF_SYS_ENTER)
                .unwrap();
            assert_eq!(
                crate::argtype::get_arg_type(pa.type_index).size,
                expected,
                "size={size}"
            );
        }
    }

    /// H13: array size is base-0 too — `"0x4"` is 4, `"010"` is 8.
    #[test]
    fn array_size_parses_base0() {
        ensure_init();
        for (size, expected) in [("0x4", 4), ("010", 8)] {
            let pa = param("int_arr", size, "")
                .get_point_arg(0, EBPF_SYS_ENTER)
                .unwrap();
            assert_eq!(
                crate::argtype::get_arg_type(pa.type_index).array_len,
                expected,
                "size={size}"
            );
        }
    }

    /// H15: a flags format warns (once per format per process) but still
    /// loads as a plain integer — the shipped syscall tables carry these
    /// formats, so rejecting would make the embedded table unloadable.
    /// The warn-once flag is process-global (`WARNED_FORMATS`), and tests
    /// that build point args from the embedded table (which carries
    /// `access_flags`) can warn first — so the mechanism is probed with a
    /// format no other test uses, instead of asserting first-call ownership
    /// of the shared `access_flags` entry (round 10: flaky in full runs).
    #[test]
    fn flags_format_warns_once_and_still_loads_as_integer() {
        ensure_init();
        assert!(warn_flags_format_once("access_flags_probe_only"));
        assert!(!warn_flags_format_once("access_flags_probe_only"));
        let pa = param("int", "", "inotify_flags")
            .get_point_arg(0, EBPF_SYS_ENTER)
            .unwrap();
        assert_eq!(pa.type_index, INT);
    }

    /// H14: register names are arch-selected like Go's build tags — on
    /// 64-bit the aarch64 table wins, and the arm fallback accepts only the
    /// numbered registers (`"r0"`..`"r10"`), which the embedded aarch32
    /// table needs for its `"size": "r2"` buf lengths. The aliases are
    /// rejected: `"fp"` would silently resolve to arm r11 instead of the
    /// aarch64 frame pointer x29, and aarch64 has no `"ip"`. On 32-bit the
    /// full arm table applies.
    #[test]
    fn reg_index_is_arch_selected_like_go_build_tags() {
        if cfg!(target_pointer_width = "64") {
            assert_eq!(get_reg_index("x0").unwrap(), 0);
            assert_eq!(get_reg_index("x29").unwrap(), 29);
            assert_eq!(get_reg_index("lr").unwrap(), 30);
            assert_eq!(get_reg_index("sp").unwrap(), 31);
            assert_eq!(get_reg_index("pc").unwrap(), 32);
            assert_eq!(get_reg_index("r2").unwrap(), 2);
            assert!(get_reg_index("fp").is_err());
            assert!(get_reg_index("ip").is_err());
            assert!(get_reg_index("r11").is_err());
            assert!(get_reg_index("x30").is_err());
            assert!(get_reg_index("x01").is_err());
        } else {
            assert_eq!(get_reg_index("r0").unwrap(), 0);
            assert_eq!(get_reg_index("fp").unwrap(), 11);
            assert_eq!(get_reg_index("ip").unwrap(), 12);
            assert_eq!(get_reg_index("sp").unwrap(), 13);
            assert_eq!(get_reg_index("lr").unwrap(), 14);
            assert_eq!(get_reg_index("pc").unwrap(), 15);
            // The aarch64 fallback stays on 32-bit: the embedded aarch64
            // table's buf sizes reference `"size": "x2"`.
            assert_eq!(get_reg_index("x2").unwrap(), 2);
            assert!(get_reg_index("x30").is_err());
        }
    }

    #[test]
    fn parse_syscall_yaml() {
        let yaml = r#"
type: syscall
points:
  - nr: 1
    name: write
    signal: enter
    params:
      - name: fd
        type: int
      - name: buf
        type: buf
        size: "256"
      - name: count
        type: uint
"#;
        let config: SyscallFileConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.base.config_type, "syscall");
        assert_eq!(config.points.len(), 1);
        assert_eq!(config.points[0].nr, 1);
        assert_eq!(config.points[0].point.name, "write");
        assert_eq!(config.points[0].point.params.len(), 3);
        assert_eq!(config.points[0].point.params[0].name, "fd");
        assert_eq!(config.points[0].point.params[0].type_name, "int");
    }

    /// J1: unknown keys in the three non-flattening DTOs are rejected instead
    /// of silently dropped — a typo like `regg` used to load fine and run with
    /// defaults. The error text names the offending key.
    #[test]
    fn unknown_fields_rejected_in_param_point_file_configs() {
        let err = serde_yaml::from_str::<ParamConfig>("name: x\ntype: int\nregg: x3").unwrap_err();
        assert!(err.to_string().contains("regg"), "{err}");
        let err = serde_json::from_str::<PointConfig>(
            r#"{"name":"n","signal":"enter","params":[],"nrr":1}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("nrr"), "{err}");
        let err =
            serde_json::from_str::<FileConfig>(r#"{"type":"syscall","extra":1}"#).unwrap_err();
        assert!(err.to_string().contains("extra"), "{err}");
    }

    /// Round 11 / N2: J1's deny did not survive the flatten boundary —
    /// `{"nr":1,"name":"write","nrr":9}` and `{"type":"syscall","points":[],
    /// "bogus_top":1}` used to parse as `Ok` with the unknown key silently
    /// dropped. The hand-written `Deserialize` impls reject them now, and the
    /// error text names the offending key.
    #[test]
    fn unknown_fields_rejected_through_flatten_configs() {
        let err = serde_json::from_str::<SyscallPointConfig>(r#"{"nr":1,"name":"write","nrr":9}"#)
            .unwrap_err();
        assert!(err.to_string().contains("nrr"), "{err}");
        let err = serde_json::from_str::<SyscallFileConfig>(
            r#"{"type":"syscall","points":[],"bogus_top":1}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("bogus_top"), "{err}");
        let err = serde_json::from_str::<UprobeFileConfig>(
            r#"{"type":"uprobe","library":"libc.so","points":[],"bogus_top":1}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("bogus_top"), "{err}");
        // YAML takes the same path (the manual impls are `MapAccess`-based,
        // not JSON-specific).
        let err =
            serde_yaml::from_str::<SyscallPointConfig>("nr: 1\nname: write\nnrr: 9\n").unwrap_err();
        assert!(err.to_string().contains("nrr"), "{err}");
    }

    /// J1: the shipped syscall tables only use known keys (top level
    /// `points`/`type`, point `name`/`nr`/`params`, param
    /// `name`/`type`/`more`/`format`/`size`), so they still load under
    /// `deny_unknown_fields`.
    #[test]
    fn shipped_syscall_tables_load_with_deny_unknown_fields() {
        use crate::config::syscall_points::{SYSCALL_CONFIG_AARCH32, SYSCALL_CONFIG_AARCH64};
        for text in [SYSCALL_CONFIG_AARCH64, SYSCALL_CONFIG_AARCH32] {
            let file: SyscallFileConfig = serde_json::from_str(text)
                .unwrap_or_else(|e| panic!("shipped table failed to parse: {e}"));
            assert_eq!(file.base.config_type, "syscall");
            assert!(!file.points.is_empty());
        }
    }

    /// J1: the shipped uprobe file shape (top level `type`/`library`/
    /// `points`, point `name`/`signal`/`params`, param `type`/`filter`/
    /// `reg`/`more`/`format`/`size`/`read_op`) loads under
    /// `deny_unknown_fields` — the key sets match the upstream Go test
    /// fixtures (`tests/config_uprobe_test*.json`, audited 2026-11-27).
    /// Round 11 / N2: the three formerly-flatten structs now reject unknown
    /// keys too (hand-written `Deserialize`); see
    /// `unknown_fields_rejected_through_flatten_configs`.
    #[test]
    fn shipped_uprobe_shape_loads_with_deny_unknown_fields() {
        let file: UprobeFileConfig = serde_json::from_str(
            r#"{"type":"uprobe","library":"libc.so","points":[
                {"name":"open","signal":"enter","params":[
                    {"type":"str","filter":["==/etc/passwd"]},
                    {"type":"int","reg":"x3","more":"all"}
                ]}
            ]}"#,
        )
        .expect("uprobe file shape must parse");
        assert_eq!(file.base.config_type, "uprobe");
        assert_eq!(file.library, "libc.so");
        assert_eq!(file.points.len(), 1);
        assert_eq!(file.points[0].params.len(), 2);
    }
}
