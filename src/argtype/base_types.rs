//! Base type registrations — faithful port of `user/argtype/argtype_base.go`
//! `init()` function.
//!
//! Registers the fundamental arg types (ptr, int, uint, int8-64, uint8-64,
//! buffer, string, string16, il2cpp_string, struct, array) plus their aliases
//! (socklen_t, size_t, ssize_t, buf, str, str16).
//!
//! Must be called before [`super::complex_types::pre_register`].

use super::consts::*;
use super::op::*;
use super::registry::*;

/// Register all base types. Mirrors `argtype_base.go:init()`.
/// Idempotent: safe to call multiple times (second call panics on duplicate —
/// same as Go, so call once during init).
pub fn init_base_types() {
    // ---- Numeric types (sizes are arm64) ----
    register("ptr", TYPE_POINTER, POINTER, 8);
    register("int", TYPE_INT, INT, 4);
    register("uint", TYPE_UINT, UINT, 4);
    register("int8", TYPE_INT8, INT8, 1);
    register("int16", TYPE_INT16, INT16, 2);
    register("int32", TYPE_INT32, INT32, 4);
    register("int64", TYPE_INT64, INT64, 8);
    register("uint8", TYPE_UINT8, UINT8, 1);
    register("uint16", TYPE_UINT16, UINT16, 2);
    register("uint32", TYPE_UINT32, UINT32, 4);
    register("uint64", TYPE_UINT64, UINT64, 8);

    // ---- Aliases for arch-dependent typedefs (arm64 values) ----
    register_alias("socklen_t", "uint32"); // aarch64: uint32
    register_alias("size_t", "uint64"); // aarch64: uint64
    register_alias("ssize_t", "int64"); // aarch64: int64

    // ---- Buffer type ----
    register("buffer", TYPE_BUFFER, BUFFER, 0);
    init_buffer();
    register_alias("buf", "buffer");

    // ---- String types ----
    register("string", TYPE_STRING, STRING, 0);
    init_string();

    register("string16", TYPE_STRING, STRING16, 0);
    init_string16();

    register("il2cpp_string", TYPE_STRING, IL2CPP_STRING, 0);
    init_il2cpp_string();

    register_alias("str", "string");
    register_alias("str16", "string16");

    // ---- Aggregate types ----
    register("struct", TYPE_STRUCT, STRUCT, 0);
    register("array", TYPE_ARRAY, ARRAY, 0);
}

/// `init_BUFFER()` — adds `SaveStruct(MAX_BUF_READ_SIZE)`.
fn init_buffer() {
    with_type(BUFFER, |at| {
        at.add_op(save_struct(u64::from(MAX_BUF_READ_SIZE)));
    });
}

/// `init_STRING()` — adds `OPC_SAVE_STRING`.
fn init_string() {
    with_type(STRING, |at| {
        at.add_op(opc_save_string());
    });
}

/// `init_STRING16()` — adds `OPC_SAVE_STRING16`.
fn init_string16() {
    with_type(STRING16, |at| {
        at.add_op(opc_save_string16());
    });
}

/// `init_IL2CPP_STRING()` — adds `OPC_READ_IL2CPP_STRING` then `OPC_SAVE_STRING16`.
fn init_il2cpp_string() {
    with_type(IL2CPP_STRING, |at| {
        at.add_op(opc_read_il2cpp_string());
        at.add_op(opc_save_string16());
    });
}

#[cfg(test)]
mod tests {
    use super::super::consts::*;
    use super::super::init_argtypes;
    use super::super::op;
    use super::super::registry::*;

    fn ensure_init() {
        init_argtypes();
    }

    #[test]
    fn base_types_have_correct_sizes() {
        ensure_init();
        assert_eq!(get_arg_type(INT).size, 4);
        assert_eq!(get_arg_type(INT64).size, 8);
        assert_eq!(get_arg_type(UINT8).size, 1);
        assert_eq!(get_arg_type(POINTER).size, 8);
    }

    #[test]
    fn buffer_has_max_read_size_op() {
        ensure_init();
        let at = get_arg_type(BUFFER);
        assert!(!at.op_list.is_empty());
        // The op should be a SaveStruct with value=4096.
        let op2 = op::get_op(at.op_list[0]);
        assert_eq!(op2.code, crate::contract::enums::OpCode::SetReadLen);
        assert_eq!(op2.value, u64::from(MAX_BUF_READ_SIZE));
    }

    #[test]
    fn string_has_save_string_op() {
        ensure_init();
        let at = get_arg_type(STRING);
        let op2 = op::get_op(at.op_list[0]);
        assert_eq!(op2.code, crate::contract::enums::OpCode::SaveString);
    }

    #[test]
    fn il2cpp_has_two_ops() {
        ensure_init();
        let at = get_arg_type(IL2CPP_STRING);
        assert_eq!(at.op_list.len(), 2);
        let op0 = op::get_op(at.op_list[0]);
        assert_eq!(op0.code, crate::contract::enums::OpCode::ReadIl2cppString);
    }

    #[test]
    fn aliases_resolve() {
        ensure_init();
        let buf = get_arg_type_by_name("buf");
        assert_eq!(buf.base_type, TYPE_BUFFER);
        assert_eq!(buf.name, "buffer");
        let socklen = get_arg_type_by_name("socklen_t");
        assert_eq!(socklen.name, "uint32");
    }
}
