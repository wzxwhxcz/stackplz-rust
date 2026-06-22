//! Complex/extended type registrations — faithful port of
//! `user/argtype/argtype_complex.go` `PreRegister()` + builder functions.
//!
//! Registers all built-in extended types (arrays, strings, structs, iovec,
//! msghdr, etc.) by composing ops from the op manager. Also provides the
//! dynamic builder functions used during `-w` parsing (Phase 2).

use super::consts::*;
use super::op::*;
use super::registry::*;

/// `PreRegister()` — register all built-in extended types.
/// Must be called after [`super::base_types::init_base_types`].
pub fn pre_register() {
    // ---- Arrays ----
    r_pre_array(INT, INT_ARRAY_1, 1);
    r_pre_array(INT, INT_ARRAY_2, 2);
    r_pre_array(UINT, UINT_ARRAY_1, 1);

    // ---- Pointers ----
    r_pointer(INT, true);
    r_pointer(UINT, true);

    // ---- Strings ----
    r_std_string();
    r_string_array();
    r_string16_array();

    // ---- Struct types ----
    r_stack_t();
    pre_r_struct("timespec", TIMESPEC, SIZEOF_TIMESPEC);
    r_sigset();
    r_siginfo();
    pre_r_struct("sigaction", SIGACTION, SIZEOF_SIGACTION);
    r_epoll_event();
    r_pollfd();
    r_dirent();
    r_ittmerspec();
    r_rusage();
    r_utsname();
    r_timeval();
    r_timezone();
    r_sysinfo();
    r_stat();
    r_statfs();

    // ---- Composite types ----
    r_iovec();
    r_iovec_x2();
    r_msghdr();
    r_sockaddr();
    r_buffer_x2();
}

/// Alias type registrations — run after `pre_register()`.
/// Mirrors the tail of `argtype_base.go:init()`.
pub fn register_alias_types() {
    register_alias_type(SOCKLEN_T, UINT32);
    register_alias_type(SIZE_T, UINT64);
    register_alias_type(SSIZE_T, INT64);
    register_alias_type(SIGINFO_V2, INT_ARRAY_1);
}

// ---- Builder functions (used by PreRegister + Phase 2 -w parser) -----------

/// `R_POINTER(p, is_num)` — create a pointer type to a child type.
/// If is_num, saves 8 bytes (pointer-sized value) then runs the child's ops.
pub fn r_pointer(child_type_index: u32, is_num: bool) -> u32 {
    let child = get_arg_type(child_type_index);
    let child_ops = child.op_list.clone();
    let name = format!("ptr_{}", child.name);
    let idx = register_new(&name, POINTER);
    with_type(idx, |at| {
        at.is_num = is_num;
        at.ptr_type_index = Some(child_type_index);
        if is_num {
            at.add_op(save_struct(8));
        }
        at.op_list.extend_from_slice(&child_ops);
    });
    idx
}

/// `r_PRE_ARRAY(elem, type_index, array_len)` — built-in array with fixed index.
fn r_pre_array(elem_type_index: u32, type_index: u32, array_len: u32) -> u32 {
    let elem = get_arg_type(elem_type_index);
    let name = format!("array_{}_{}", elem.name, array_len);
    register_pre(&name, type_index, ARRAY);
    with_type(type_index, |at| {
        at.array_len = array_len;
        at.array_type_index = Some(elem_type_index);
        at.size = elem.size * array_len;
        at.add_op(save_struct(u64::from(at.size)));
    });
    type_index
}

/// `r_ARRAY(elem, array_len)` — dynamic array registration.
pub fn r_array(elem_type_index: u32, array_len: u32) -> u32 {
    let elem = get_arg_type(elem_type_index);
    let name = format!("array_{}_{}", elem.name, array_len);
    let idx = register_new(&name, ARRAY);
    let elem_size = elem.size;
    with_type(idx, |at| {
        at.array_len = array_len;
        at.array_type_index = Some(elem_type_index);
        at.size = elem_size * array_len;
        at.add_op(save_struct(u64::from(at.size)));
    });
    idx
}

/// `r_STD_STRING()` — `std::string` via `READ_STD_STRING` + `SAVE_STRING`.
fn r_std_string() {
    register_pre("std", STD_STRING, STRUCT);
    with_type(STD_STRING, |at| {
        at.add_op(opc_read_std_string());
        at.add_op(opc_save_string());
    });
}

/// `r_STRING_ARRAY()` — NULL-terminated string pointer array.
fn r_string_array() {
    let idx = register_new("string_array", STRUCT);
    with_type(idx, |at| {
        at.add_op(set_break_count(u64::from(MAX_LOOP_COUNT)));
        at.add_op(opc_for_break());
        at.add_op(opc_save_ptr_string());
        at.add_op(add_offset(8)); // sizeof pointer
        at.add_op(opc_for_break());
    });
}

/// `r_STRING16_ARRAY()` — NULL-terminated UTF16 string pointer array.
fn r_string16_array() {
    let idx = register_new("string16_array", STRUCT);
    with_type(idx, |at| {
        at.add_op(set_break_count(u64::from(MAX_LOOP_COUNT)));
        at.add_op(opc_for_break());
        at.add_op(opc_save_ptr_string16());
        at.add_op(add_offset(8));
        at.add_op(opc_for_break());
    });
}

/// `PRE_R_STRUCT(name, type_index, parse_impl)` — pre-registered struct.
fn pre_r_struct(name: &str, type_index: u32, size: u32) {
    register_pre(name, type_index, STRUCT);
    with_type(type_index, |at| {
        at.size = size;
        at.add_op(set_read_len(u64::from(size)));
        at.add_op(opc_save_struct());
    });
}

fn r_stack_t() {
    let idx = register_new("stack_t", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_STACK_T;
        at.add_op(set_read_len(u64::from(SIZEOF_STACK_T)));
        at.add_op(opc_save_struct());
    });
}

fn r_siginfo() {
    let idx = register_new("siginfo", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_SIGINFO;
        at.add_op(set_read_len(u64::from(SIZEOF_SIGINFO)));
        at.add_op(opc_save_struct());
    });
}

fn r_epoll_event() {
    let idx = register_new("epoll_event", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_EPOLL_EVENT;
        at.add_op(set_read_len(u64::from(SIZEOF_EPOLL_EVENT)));
        at.add_op(opc_save_struct());
    });
}

fn r_pollfd() {
    let idx = register_new("pollfd", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_POLLFD;
        at.add_op(set_read_len(u64::from(SIZEOF_POLLFD)));
        at.add_op(opc_save_struct());
    });
}

fn r_dirent() {
    let idx = register_new("dirent", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_DIRENT;
        at.add_op(set_read_len(u64::from(SIZEOF_DIRENT)));
        at.add_op(opc_save_struct());
    });
}

fn r_ittmerspec() {
    let idx = register_new("ittmerspec", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_ITTMERSPEC;
        at.add_op(set_read_len(u64::from(SIZEOF_ITTMERSPEC)));
        at.add_op(opc_save_struct());
    });
}

fn r_rusage() {
    let idx = register_new("rusage", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_RUSAGE;
        at.add_op(set_read_len(u64::from(SIZEOF_RUSAGE)));
        at.add_op(opc_save_struct());
    });
}

fn r_utsname() {
    let idx = register_new("utsname", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_UTSNAME;
        at.add_op(set_read_len(u64::from(SIZEOF_UTSNAME)));
        at.add_op(opc_save_struct());
    });
}

fn r_timeval() {
    let idx = register_new("timeval", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_TIMEVAL;
        at.add_op(set_read_len(u64::from(SIZEOF_TIMEVAL)));
        at.add_op(opc_save_struct());
    });
}

fn r_timezone() {
    let idx = register_new("timezone", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_TIMEZONE;
        at.add_op(set_read_len(u64::from(SIZEOF_TIMEZONE)));
        at.add_op(opc_save_struct());
    });
}

fn r_sysinfo() {
    let idx = register_new("sysinfo", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_SYSINFO_T;
        at.add_op(set_read_len(u64::from(SIZEOF_SYSINFO_T)));
        at.add_op(opc_save_struct());
    });
}

fn r_stat() {
    let idx = register_new("stat", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_STAT_T;
        at.add_op(set_read_len(u64::from(SIZEOF_STAT_T)));
        at.add_op(opc_save_struct());
    });
}

fn r_statfs() {
    let idx = register_new("statfs", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_STATFS_T;
        at.add_op(set_read_len(u64::from(SIZEOF_STATFS_T)));
        at.add_op(opc_save_struct());
    });
}

fn r_sockaddr() {
    let idx = register_new("sockaddr", STRUCT);
    with_type(idx, |at| {
        at.size = SIZEOF_SOCKADDR_UN;
        at.add_op(set_read_len(u64::from(SIZEOF_SOCKADDR_UN)));
        at.add_op(opc_save_struct());
    });
}

/// `r_SIGSET()` — sigset is a uint32[1] with HEX format.
fn r_sigset() {
    let p = new_num_format(UINT, FORMAT_HEX);
    r_array(p, 1);
}

/// `r_BUFFER_X2()` — buffer whose length comes from reg 2.
fn r_buffer_x2() {
    let idx = register_new("buffer_x2", BUFFER);
    with_type(idx, |at| {
        at.clean_op_list();
        at.add_op(set_read_len(u64::from(MAX_BUF_READ_SIZE)));
        at.add_op(build_read_reg_len(2));
        at.add_op(opc_save_struct());
    });
}

/// `R_BUFFER_LEN(length)` — buffer with fixed length.
pub fn r_buffer_len(length: u32) -> u32 {
    if length > MAX_BUF_READ_SIZE {
        panic!("max buf read size:{MAX_BUF_READ_SIZE}, provided:{length}");
    }
    let name = format!("buffer_len_{length}");
    let idx = register_new(&name, BUFFER);
    with_type(idx, |at| {
        at.clean_op_list();
        at.size = length;
        at.add_op(set_read_len(u64::from(length)));
        at.add_op(opc_save_struct());
    });
    idx
}

/// `R_BUFFER_REG(reg_index)` — buffer whose length comes from a register.
pub fn r_buffer_reg(reg_index: u32) -> u32 {
    let name = format!("buffer_reg_{reg_index}");
    let idx = register_new(&name, BUFFER);
    with_type(idx, |at| {
        at.clean_op_list();
        at.add_op(set_read_len(u64::from(MAX_BUF_READ_SIZE)));
        at.add_op(build_read_reg_len(u64::from(reg_index)));
        at.add_op(opc_save_struct());
    });
    idx
}

/// `r_IOVEC()` — iovec struct: save the struct, then read the pointer
/// at offset 8 (iov_len), dereference it, and save the pointed-to buffer.
fn r_iovec() {
    register_pre("iovec", IOVEC, STRUCT);
    with_type(IOVEC, |at| {
        at.size = SIZEOF_IOVEC;
        at.add_op(set_read_len(u64::from(SIZEOF_IOVEC)));
        at.add_op(opc_save_struct());
        at.add_op(set_read_len(u64::from(MAX_BUF_READ_SIZE)));
        at.add_op(build_read_ptr_len(OFFSET_IOVEC_LEN));
        at.add_op(opc_read_pointer());
        at.add_op(opc_move_pointer_value());
        at.add_op(opc_save_struct());
    });
}

/// `r_IOVEC_X2()` — array of up to 2 iovecs, with count from reg 2.
fn r_iovec_x2() {
    let idx = register_new("iovec_x2", STRUCT);
    let break_idx = build_read_reg_break_count(2);
    let iovec_ops = get_arg_type(IOVEC).op_list.clone();
    let iovec_size = get_arg_type(IOVEC).size;
    with_type(idx, |at| {
        at.add_op(break_idx);
        at.add_op(opc_save_reg());
        at.add_op(opc_for_break());
        at.add_op(opc_set_tmp_value());
        at.op_list.extend_from_slice(&iovec_ops);
        at.add_op(opc_move_tmp_value());
        at.add_op(add_offset(u64::from(iovec_size)));
        at.add_op(opc_for_break());
    });
}

/// `r_MSGHDR()` — msghdr: save struct, read control buffer, then iterate
/// iov array.
fn r_msghdr() {
    register_pre("msghdr", MSGHDR, STRUCT);
    let iovec_ops = get_arg_type(IOVEC).op_list.clone();
    let iovec_size = get_arg_type(IOVEC).size;
    with_type(MSGHDR, |at| {
        at.size = SIZEOF_MSGHDR;
        at.add_op(set_read_len(u64::from(SIZEOF_MSGHDR)));
        at.add_op(opc_save_struct());
        at.add_op(opc_set_tmp_value());
        at.add_op(set_read_len(u64::from(MAX_BUF_READ_SIZE)));
        at.add_op(build_read_ptr_len(OFFSET_MSGHDR_CONTROLLEN));
        at.add_op(build_read_ptr_addr(OFFSET_MSGHDR_CONTROL));
        at.add_op(opc_save_struct());
        at.add_op(opc_move_tmp_value());
        at.add_op(build_read_ptr_break_count(OFFSET_MSGHDR_IOVLEN));
        at.add_op(build_read_ptr_addr(OFFSET_MSGHDR_IOV));
        at.add_op(opc_for_break());
        at.add_op(opc_set_tmp_value());
        at.op_list.extend_from_slice(&iovec_ops);
        at.add_op(opc_move_tmp_value());
        at.add_op(add_offset(u64::from(iovec_size)));
        at.add_op(opc_for_break());
    });
}

/// `NewNumFormat(parent, format_type)` — clone a num type with a new format.
pub fn new_num_format(parent_type_index: u32, format_type: u32) -> u32 {
    let parent = get_arg_type(parent_type_index);
    let name = format!("{}_fmt_{}", parent.name, format_type);
    let idx = register_new(&name, parent_type_index);
    with_type(idx, |at| at.format_type = format_type);
    idx
}

/// `R_NUM_HEX(type_index)` — clone a num type with HEX format.
pub fn r_num_hex(type_index: u32) -> u32 {
    new_num_format(type_index, FORMAT_HEX)
}

/// `R_NUM_ARRAY(type_index, length)` — array of formatted nums.
pub fn r_num_array(type_index: u32, length: u32) -> u32 {
    let p = new_num_format(type_index, FORMAT_HEX);
    r_array(p, length)
}

/// `R_STRUCT(name)` — dynamically register a new struct type.
/// Phase 3 will add the parse_impl; for now just the ops.
pub fn r_struct(name: &str, size: u32) -> u32 {
    let idx = register_new(name, STRUCT);
    with_type(idx, |at| {
        at.size = size;
        at.add_op(set_read_len(u64::from(size)));
        at.add_op(opc_save_struct());
    });
    idx
}

// (OpCode is used implicitly via op helpers — no direct reference needed.)

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::consts::*;
    use super::super::op;
    use super::super::registry::*;

    fn ensure_init() {
        super::super::init_argtypes();
    }

    #[test]
    fn pre_register_creates_extended_types() {
        ensure_init();
        assert!(is_registered(INT_ARRAY_1));
        assert!(is_registered(INT_ARRAY_2));
        assert!(is_registered(UINT_ARRAY_1));
        assert!(is_registered(STD_STRING));
        assert!(is_registered(IOVEC));
        assert!(is_registered(MSGHDR));
        assert!(is_registered(TIMESPEC));
    }

    #[test]
    fn timespec_has_correct_ops() {
        ensure_init();
        let at = get_arg_type(TIMESPEC);
        assert_eq!(at.size, SIZEOF_TIMESPEC);
        assert_eq!(at.op_list.len(), 2); // SET_READ_LEN + SAVE_STRUCT
    }

    #[test]
    fn iovec_has_correct_op_count() {
        ensure_init();
        let at = get_arg_type(IOVEC);
        // 2 (save struct) + 4 (read ptr + deref + save) + ... = 8 ops
        // set_read_len, save_struct, set_read_len, build_read_ptr_len,
        // read_pointer, move_pointer_value, save_struct = 7 ops
        assert_eq!(at.op_list.len(), 7);
        assert_eq!(at.size, SIZEOF_IOVEC);
    }

    #[test]
    fn msghdr_has_complex_op_chain() {
        ensure_init();
        let at = get_arg_type(MSGHDR);
        // 2 (save struct) + set_tmp + 4 (control buf) + move_tmp +
        // 3 (iov setup) + for_break + set_tmp + iovec_ops(7) +
        // move_tmp + add_offset + for_break
        let expected = 2 + 1 + 4 + 1 + 3 + 1 + 1 + 7 + 1 + 1 + 1;
        assert_eq!(at.op_list.len(), expected);
    }

    #[test]
    fn r_pointer_int_has_save_struct() {
        ensure_init();
        let ptr_int = get_arg_type_by_name("ptr_int");
        assert!(ptr_int.is_num);
        assert_eq!(ptr_int.ptr_type_index, Some(INT));
        // SaveStruct(8) = 1 op, INT has no ops
        assert_eq!(ptr_int.op_list.len(), 1);
    }

    #[test]
    fn r_buffer_len_creates_custom_buffer() {
        ensure_init();
        let idx = r_buffer_len(128);
        let at = get_arg_type(idx);
        assert_eq!(at.size, 128);
        // CleanOpList removed inherited buffer op, then 2 new ops
        assert_eq!(at.op_list.len(), 2);
    }

    #[test]
    fn string_array_has_loop_pattern() {
        ensure_init();
        let at = get_arg_type_by_name("string_array");
        // set_break_count, for_break, save_ptr_string, add_offset, for_break
        assert_eq!(at.op_list.len(), 5);
    }

    #[test]
    fn sigset_is_uint_array_of_1() {
        ensure_init();
        let at = get_arg_type_by_name("array_uint_fmt_2_1");
        assert_eq!(at.array_len, 1);
        assert_eq!(at.size, 4); // 1 * sizeof(uint32) = 4
    }

    #[test]
    fn alias_types_resolve_correctly() {
        ensure_init();
        let sl = get_arg_type(SOCKLEN_T);
        assert_eq!(sl.name, "uint32");
        let si = get_arg_type(SIGINFO_V2);
        // SIGINFO_V2 → INT_ARRAY_1
        assert_eq!(si.type_index, INT_ARRAY_1);
    }
}
