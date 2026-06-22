//! Argtype subsystem — faithful port of Go's `user/argtype/` package.
//!
//! This is the *parameter type* system: it defines how each traced argument is
//! read from traced-process memory by the eBPF bytecode VM.
//!
//! # Modules
//!
//! - [`op`] — op manager (Phase 1a): 34 op singletons + dedup registry.
//! - [`consts`] — type index constants and struct sizes.
//! - [`registry`] — `ArgType` struct + global registry.
//! - [`base_types`] — base type registrations (ptr, int, buffer, string, ...).
//! - [`complex_types`] — extended types (arrays, structs, iovec, msghdr, ...).

pub mod base_types;
pub mod complex_types;
pub mod consts;
pub mod op;
pub mod registry;

// Re-export op helpers.
pub use op::{
    add_offset, add_op, add_read_move_reg, add_read_save_reg, build_read_ptr_addr,
    build_read_ptr_break_count, build_read_ptr_len, build_read_reg_break_count, build_read_reg_len,
    count, get_all_op_list, get_op, get_op_info, rat, rsat, save_struct, set_break_count,
    set_read_len, set_read_len_save_struct, OpArgType, OpConfig,
};

// Re-export registry API.
pub use registry::{
    get_arg_type, get_arg_type_by_name, is_registered, next_type_index, register, register_alias,
    register_alias_type, register_new, register_pre, registry_count, try_get_arg_type_by_name,
    update_arg_type, with_type, ArgType,
};

// Re-export complex type builders (for Phase 2 -w parser).
pub use complex_types::{
    new_num_format, r_array, r_buffer_len, r_buffer_reg, r_num_array, r_num_hex, r_pointer,
    r_struct, register_alias_types,
};

// Re-export the 34 singleton index accessors.
pub use op::{
    opc_add_offset, opc_add_reg, opc_filter_buffer, opc_filter_string, opc_filter_value,
    opc_for_break, opc_move_pointer_value, opc_move_reg_value, opc_move_tmp_value,
    opc_read_il2cpp_string, opc_read_pointer, opc_read_reg, opc_read_std_string, opc_reset_ctx,
    opc_save_addr, opc_save_pointer, opc_save_ptr_string, opc_save_ptr_string16, opc_save_reg,
    opc_save_string, opc_save_string16, opc_save_struct, opc_set_break_count,
    opc_set_break_count_pointer_value, opc_set_break_count_reg_value, opc_set_read_count,
    opc_set_read_len, opc_set_read_len_pointer_value, opc_set_read_len_reg_value,
    opc_set_reg_index, opc_set_tmp_value, opc_skip, opc_sub_offset, opc_sub_reg,
};

/// Initialize the entire argtype subsystem. Must be called once before any
/// argtype lookup. Mirrors the combined `init()` of `argtype_base.go` +
/// `argtype_complex.go::PreRegister()`.
///
/// Idempotent: uses [`OnceLock`] so repeated calls are no-ops (important for
/// parallel tests that share the global registry).
///
/// Order: base types → extended types → alias types.
pub fn init_argtypes() {
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        base_types::init_base_types();
        complex_types::pre_register();
        complex_types::register_alias_types();
    });
}
