//! Argtype subsystem — faithful port of Go's `user/argtype/` package.
//!
//! This is the *parameter type* system: it defines how each traced argument is
//! read from traced-process memory by the eBPF bytecode VM. Phase 1a ships the
//! op manager ([`op`]); Phase 1b will add the type registry (`ArgType` table).

pub mod op;

pub use op::{
    add_op, add_read_move_reg, add_read_save_reg, build_read_ptr_addr, build_read_ptr_break_count,
    build_read_ptr_len, build_read_reg_break_count, build_read_reg_len, count, get_all_op_list,
    get_op, get_op_info, rat, rsat, save_struct, OpArgType, OpConfig,
};

// Re-export the 34 singleton index accessors for ergonomic `argtype::opc_skip()` use.
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
