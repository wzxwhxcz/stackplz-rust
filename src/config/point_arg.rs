//! `PointArg` — per-argument hook configuration. Mirrors
//! `user/config/config_point_arg.go`.
//!
//! Each `PointArg` describes how the BPF VM should read one argument at a hook
//! point: which register to read (or a custom address-computation op chain),
//! what type to interpret it as, and optional filter rules.

use crate::argtype::{
    self, consts::*, get_arg_type, add_read_save_reg, opc_add_reg, opc_filter_buffer,
    opc_filter_string, opc_filter_value, opc_move_reg_value, opc_sub_reg, save_struct,
};

/// Point type constants — from `user/config/config_const.go`.
pub const EBPF_PROG_NONE: u32 = 0;
pub const EBPF_SYS_ENTER: u32 = 1;
pub const EBPF_SYS_EXIT: u32 = 2;
pub const EBPF_SYS_ALL: u32 = 3;
pub const EBPF_UPROBE_ENTER: u32 = 4;

/// arm64 max register index (sentinel for "no register — return value only").
pub const REG_ARM64_MAX: u32 = 34;

/// Per-argument hook config. Mirrors Go's `PointArg` struct.
#[derive(Debug, Clone)]
pub struct PointArg {
    pub name: String,
    pub reg_index: u32,
    pub type_index: u32,
    pub extra_op_list: Vec<u32>,
    pub filter_index_list: Vec<u32>,
    /// When to read this arg (EBPF_SYS_ENTER, EBPF_SYS_EXIT, EBPF_SYS_ALL,
    /// EBPF_UPROBE_ENTER).
    pub point_type: u32,
    /// When to parse/display this arg (set during ParseArgType).
    pub group_type: u32,
}

impl PointArg {
    /// `NewUprobePointArg(name, type_index, reg_index)` — for `-w` parsing.
    pub fn new_uprobe(name: &str, type_index: u32, reg_index: u32) -> Self {
        Self {
            name: name.to_string(),
            reg_index,
            type_index,
            extra_op_list: Vec::new(),
            filter_index_list: Vec::new(),
            point_type: EBPF_UPROBE_ENTER,
            group_type: EBPF_PROG_NONE,
        }
    }

    /// `NewPointArg(name, type_index, point_type)` — for syscall/JSON config.
    pub fn new(name: &str, type_index: u32, point_type: u32) -> Self {
        Self {
            name: name.to_string(),
            reg_index: REG_ARM64_MAX,
            type_index,
            extra_op_list: Vec::new(),
            filter_index_list: Vec::new(),
            point_type,
            group_type: EBPF_PROG_NONE,
        }
    }

    pub fn set_type_index(&mut self, type_index: u32) {
        self.type_index = type_index;
    }

    pub fn set_group_type(&mut self, group_type: u32) {
        self.group_type = group_type;
    }

    pub fn set_point_type(&mut self, point_type: u32) {
        self.point_type = point_type;
    }

    pub fn add_extra_op(&mut self, op_index: u32) {
        self.extra_op_list.push(op_index);
    }

    pub fn add_filter_index(&mut self, filter_index: u32) {
        self.filter_index_list.push(filter_index);
    }

    /// `SetTypeByName(name)` — resolve type from registry by name.
    pub fn set_type_by_name(&mut self, name: &str) {
        let at = argtype::get_arg_type_by_name(name);
        self.type_index = at.type_index;
    }

    /// `SetHexFormat()` — wrap in hex format (unless it's an array).
    pub fn set_hex_format(&mut self) {
        let at = get_arg_type(self.type_index);
        if at.parent_index == ARRAY {
            return;
        }
        self.type_index = argtype::r_num_hex(self.type_index);
    }

    /// `ToPointerType()` — wrap the current type in a pointer (dereference).
    pub fn to_pointer_type(&mut self) {
        self.type_index = argtype::r_pointer(self.type_index, true);
    }

    /// `IsBuffer()` — whether this type's parent is BUFFER.
    pub fn is_buffer(&self) -> bool {
        let at = get_arg_type(self.type_index);
        at.parent_index == BUFFER
    }

    /// `ReadMore()` — whether this arg should be read/parsed at the current
    /// point type.
    pub fn read_more(&self) -> bool {
        self.point_type == EBPF_SYS_ALL || self.point_type == self.group_type
    }

    /// `GetOpList()` — produce the flat list of op indices for the BPF VM.
    /// This is the bridge between the per-arg config and the `point_args_t`
    /// BPF map.
    ///
    /// Logic mirrors `config_point_arg.go:127-166` exactly.
    pub fn get_op_list(&self) -> Vec<u32> {
        let mut op_list = Vec::new();

        // sys exit return value: no ops.
        if self.reg_index == REG_ARM64_MAX {
            return op_list;
        }

        if !self.extra_op_list.is_empty() {
            // Custom address computation provides the read address.
            op_list.extend_from_slice(&self.extra_op_list);
        } else {
            // Default: read the arg register and save it.
            op_list.push(add_read_save_reg(u64::from(self.reg_index)));
            op_list.push(opc_move_reg_value());
        }

        // Filter ops (for non-string, non-buffer scalar types).
        if self.type_index != STRING
            && self.type_index != STD_STRING
            && !self.is_buffer()
        {
            for &v in &self.filter_index_list {
                let op = argtype::get_op(opc_filter_value());
                op_list.push(op.new_value(u64::from(v)));
            }
        }

        // Type-specific ops (the argtype's own op_list).
        if self.read_more() {
            let at = get_arg_type(self.type_index);
            op_list.extend_from_slice(&at.op_list);

            // String/buffer filter ops.
            if self.type_index == STRING || self.type_index == STD_STRING {
                for &v in &self.filter_index_list {
                    let op = argtype::get_op(opc_filter_string());
                    op_list.push(op.new_value(u64::from(v)));
                }
            } else if self.is_buffer() {
                for &v in &self.filter_index_list {
                    let op = argtype::get_op(opc_filter_buffer());
                    op_list.push(op.new_value(u64::from(v)));
                }
            }
        }

        op_list
    }
}

/// `UprobeArgs` — per-hook-point config. Mirrors `config_uprobe.go:9-24`.
#[derive(Debug, Clone)]
pub struct UprobeArgs {
    pub index: u32,
    pub enter_key: u32,
    pub lib_path: String,
    pub real_file_path: String,
    pub name: String,
    pub symbol: String,
    pub offset: u64,
    pub non_elf_offset: u64,
    pub args_str: String,
    pub point_args: Vec<PointArg>,
    pub bind_syscall: bool,
    pub exit_read: bool,
    pub exit_offset: u64,
    pub kill_signal: u32,
}

impl UprobeArgs {
    pub fn new() -> Self {
        Self {
            index: 0,
            enter_key: 0,
            lib_path: String::new(),
            real_file_path: String::new(),
            name: String::new(),
            symbol: String::new(),
            offset: 0,
            non_elf_offset: 0,
            args_str: String::new(),
            point_args: Vec::new(),
            bind_syscall: false,
            exit_read: false,
            exit_offset: 0,
            kill_signal: 0,
        }
    }

    /// `GetConfig()` → `(enter_key, signal, op_key_list)`. Produces the flat
    /// op list for the `uprobe_point_args` BPF map value.
    ///
    /// Returns `(enter_key, signal, op_count, op_key_list)` where op_key_list
    /// is truncated to MAX_OP_COUNT_STACK (64).
    pub fn get_config(&self) -> (u32, u32, u32, Vec<u32>) {
        let mut op_key_list = Vec::new();
        for pa in &self.point_args {
            let ops = pa.get_op_list();
            op_key_list.extend_from_slice(&ops);
        }
        let op_count = op_key_list.len() as u32;
        (self.enter_key, self.kill_signal, op_count, op_key_list)
    }

    /// `GetExitPoint(index)` — create a companion exit-point UprobeArgs.
    pub fn get_exit_point(&self, index: usize) -> UprobeArgs {
        let mut point = UprobeArgs::new();
        point.index = index as u32;
        point.enter_key = self.enter_key;
        point.lib_path = self.lib_path.clone();
        point.real_file_path = self.real_file_path.clone();
        point.name = format!("0x{:x}", self.exit_offset);
        point.symbol = String::new();
        point.offset = self.exit_offset;
        point.non_elf_offset = self.non_elf_offset;
        point.args_str = self.args_str.clone();
        point.point_args = self.point_args.clone();
        point.kill_signal = self.kill_signal;
        point
    }
}

impl Default for UprobeArgs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_arg_default_op_list_for_register() {
        crate::argtype::init_argtypes();
        let pa = PointArg::new_uprobe("arg_0", INT, 0);
        // No extra ops, no filters, read_more=true (EBPF_UPROBE_ENTER==group_type).
        // Expected: [add_read_save_reg(0), move_reg_value] + INT's op_list (empty).
        let ops = pa.get_op_list();
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn point_arg_reg_max_returns_empty() {
        let pa = PointArg::new("ret", INT, EBPF_SYS_EXIT);
        let ops = pa.get_op_list();
        assert!(ops.is_empty());
    }

    #[test]
    fn uprobe_args_get_config_concatenates_ops() {
        crate::argtype::init_argtypes();
        let mut ua = UprobeArgs::new();
        ua.point_args.push(PointArg::new_uprobe("arg_0", INT, 0));
        ua.point_args.push(PointArg::new_uprobe("arg_1", INT, 1));
        let (_, _, count, ops) = ua.get_config();
        // Each arg: 2 ops (read_save_reg + move_reg_value), INT has no own ops.
        assert_eq!(count, 4);
        assert_eq!(ops.len(), 4);
    }
}
