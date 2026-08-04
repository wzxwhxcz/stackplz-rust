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
use serde::{Deserialize, Serialize};
use std::fs;

use super::point_arg::{PointArg, EBPF_SYS_ALL, EBPF_SYS_ENTER, EBPF_SYS_EXIT, EBPF_UPROBE_ENTER};
use crate::argtype::consts::{INT, POINTER, UINT, UINT64};

/// Parameter configuration in a point definition.
/// Mirrors `ParamConfig` in config_file.go:11-20.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct PointConfig {
    /// Symbol or function name
    pub name: String,

    /// Signal type: "enter", "exit", "all" (for syscalls)
    #[serde(default)]
    pub signal: String,

    /// Parameter list
    #[serde(default)]
    pub params: Vec<ParamConfig>,
}

/// Syscall-specific point with syscall number.
/// Mirrors `SyscallPointConfig` in config_file.go:28-31.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallPointConfig {
    /// Syscall number
    pub nr: u32,

    #[serde(flatten)]
    pub point: PointConfig,
}

/// File configuration base trait.
/// Mirrors `IFileConfig` + `FileConfig` in config_file.go:33-43.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileConfig {
    /// Config type: "syscall" or "uprobe"
    #[serde(rename = "type")]
    pub config_type: String,
}

/// Uprobe configuration file.
/// Mirrors `UprobeFileConfig` in config_file.go:212-216.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UprobeFileConfig {
    #[serde(flatten)]
    pub base: FileConfig,

    /// Library path
    pub library: String,

    /// Hook points
    #[serde(default)]
    pub points: Vec<PointConfig>,
}

/// Syscall configuration file.
/// Mirrors `SyscallFileConfig` in config_file.go:218-221.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallFileConfig {
    #[serde(flatten)]
    pub base: FileConfig,

    /// Syscall hook points
    #[serde(default)]
    pub points: Vec<SyscallPointConfig>,
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
            get_reg_index(&self.reg)
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
                // Buffer with size from config or register
                let type_idx = if self.size.is_empty() {
                    crate::argtype::r_buffer_len(256)
                } else if let Ok(size) = self.size.parse::<u32>() {
                    crate::argtype::r_buffer_len(size)
                } else {
                    // Size from register
                    let reg = get_reg_index(&self.size);
                    crate::argtype::r_buffer_reg(reg)
                };
                point_arg.set_type_index(type_idx);
                point_arg.set_group_type(EBPF_UPROBE_ENTER);
            }

            "iovec" => {
                // TODO: implement r_iovec_reg for dynamic iovec reading
                // For now, treat as a pointer type
                point_arg.set_type_by_name("iovec");
                point_arg.set_group_type(EBPF_UPROBE_ENTER);
            }

            "int_arr" | "uint_arr" | "ptr_arr" => {
                // Array with required size
                let size = self
                    .size
                    .parse::<u32>()
                    .map_err(|_| anyhow!("parse {} array size failed", type_name))?;
                let base_type = match type_name {
                    "int_arr" => INT,
                    "uint_arr" => UINT,
                    _ => UINT64,
                };
                // TODO: implement r_num_array_fmt for format-aware arrays
                // For now, use basic r_num_array
                let type_idx = crate::argtype::r_num_array(base_type, size);
                point_arg.set_type_index(type_idx);
                point_arg.set_group_type(EBPF_UPROBE_ENTER);
            }

            "str" | "std" | "str16" | "il2cpp_string" => {
                // String types
                point_arg.set_type_by_name(type_name);
                point_arg.set_group_type(EBPF_UPROBE_ENTER);
            }

            "int" | "uint" | "int8" | "uint8" | "int16" | "uint16" | "int32" | "uint32"
            | "int64" | "uint64" => {
                // Numeric types
                point_arg.set_type_by_name(type_name);
            }

            _ => {
                // Struct types registered in argtype
                point_arg.set_type_by_name(type_name);
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
                // TODO: implement set_flags_format(&self.format) for custom flag mappings
                // For now, treat as basic integer
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
                        let reg_index = get_reg_index(&token);
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

/// Parse numeric string (hex with 0x prefix, octal with 0 prefix, or decimal).
fn parse_num(s: &str) -> Result<u64> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).map_err(|e| anyhow!("parse hex failed: {}", e))
    } else if s.starts_with('0') && s.len() > 1 && s.chars().all(|c| c.is_ascii_digit()) {
        u64::from_str_radix(&s[1..], 8).map_err(|e| anyhow!("parse octal failed: {}", e))
    } else {
        s.parse::<u64>()
            .map_err(|e| anyhow!("parse decimal failed: {}", e))
    }
}

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

/// Load syscall configuration from file.
pub fn load_syscall_config(path: &str) -> Result<SyscallFileConfig> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow!("failed to read config file {}: {}", path, e))?;

    if path.ends_with(".yaml") || path.ends_with(".yml") {
        serde_yaml::from_str(&content).map_err(|e| anyhow!("failed to parse YAML: {}", e))
    } else {
        serde_json::from_str(&content).map_err(|e| anyhow!("failed to parse JSON: {}", e))
    }
}

/// Load uprobe configuration from file.
pub fn load_uprobe_config(path: &str) -> Result<UprobeFileConfig> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow!("failed to read config file {}: {}", path, e))?;

    if path.ends_with(".yaml") || path.ends_with(".yml") {
        serde_yaml::from_str(&content).map_err(|e| anyhow!("failed to parse YAML: {}", e))
    } else {
        serde_json::from_str(&content).map_err(|e| anyhow!("failed to parse JSON: {}", e))
    }
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
}
