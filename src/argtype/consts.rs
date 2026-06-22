//! Type index constants — faithful port of `user/common/const.go` (lines 179-238)
//! and `user/argtype/const.go`.
//!
//! These are the *registry indices* used by the userspace argtype registry to
//! look up `ArgType` instances. They are distinct from the C wire enum
//! `arg_type_e` (in `contract::enums::ArgType`) which is the on-the-wire type
//! tag. The registry indices start at 0 (`CONST_ARGTYPE_START`) and go through
//! `CONST_ARGTYPE_END`; dynamically-registered types (from `-w` parsing) get
//! indices starting at `CONST_ARGTYPE_END + 1`.

// ---- FORMAT_* — output formatting modes (from argtype/const.go) ------------
pub const FORMAT_NUM: u32 = 0;
pub const FORMAT_HEX_PURE: u32 = 1;
pub const FORMAT_HEX: u32 = 2;
pub const FORMAT_DEC: u32 = 3;
pub const FORMAT_OCT: u32 = 4;
pub const FORMAT_BIN: u32 = 5;

// ---- TYPE_* — base type categories (from argtype/const.go) -----------------
pub const TYPE_NONE: u32 = 0;
pub const TYPE_INT: u32 = 1;
pub const TYPE_UINT: u32 = 2;
pub const TYPE_INT8: u32 = 3;
pub const TYPE_INT16: u32 = 4;
pub const TYPE_INT32: u32 = 5;
pub const TYPE_INT64: u32 = 6;
pub const TYPE_UINT8: u32 = 7;
pub const TYPE_UINT16: u32 = 8;
pub const TYPE_UINT32: u32 = 9;
pub const TYPE_UINT64: u32 = 10;
pub const TYPE_POINTER: u32 = 11;
pub const TYPE_STRING: u32 = 12;
pub const TYPE_STRING_ARR: u32 = 13;
pub const TYPE_BUFFER: u32 = 14;
pub const TYPE_STRUCT: u32 = 15;
pub const TYPE_ARRAY: u32 = 16;
pub const TYPE_IOVEC: u32 = 17;
pub const TYPE_MSGHDR: u32 = 18;
pub const TYPE_SOCKADDR: u32 = 19;
pub const TYPE_DIRENT: u32 = 20;
pub const TYPE_TIMESPEC: u32 = 21;
pub const TYPE_SIGACTION: u32 = 22;
pub const TYPE_SIGINFO: u32 = 23;
pub const TYPE_STACK_T: u32 = 24;
pub const TYPE_POLLFD: u32 = 25;
pub const TYPE_STAT: u32 = 26;

// ---- Registry indices (from common/const.go:179-238) -----------------------
pub const CONST_ARGTYPE_START: u32 = 0;
pub const POINTER: u32 = 1;
pub const INT: u32 = 2;
pub const UINT: u32 = 3;
pub const INT8: u32 = 4;
pub const INT16: u32 = 5;
pub const INT32: u32 = 6;
pub const INT64: u32 = 7;
pub const UINT8: u32 = 8;
pub const UINT16: u32 = 9;
pub const UINT32: u32 = 10;
pub const UINT64: u32 = 11;
pub const NUM: u32 = 12;
pub const STRING: u32 = 13;
pub const STRING16: u32 = 14;
pub const STD_STRING: u32 = 15;
pub const IL2CPP_STRING: u32 = 16;
pub const STRUCT: u32 = 17;
pub const ARRAY: u32 = 18;
pub const BUFFER: u32 = 19;
pub const IOVEC: u32 = 20;
pub const MSGHDR: u32 = 21;
pub const SOCKLEN_T: u32 = 22;
pub const SIZE_T: u32 = 23;
pub const SSIZE_T: u32 = 24;
pub const SOCKADDR: u32 = 25;
pub const TIMESPEC: u32 = 26;
pub const STAT: u32 = 27;
pub const POLLFD: u32 = 28;
pub const SIGACTION: u32 = 29;
pub const SIGINFO: u32 = 30;
pub const STACK_T: u32 = 31;
pub const LINUX_DIRENT64: u32 = 32;
pub const STRING_ARRAY: u32 = 33;
pub const ITTMERSPEC: u32 = 34;
pub const RUSAGE: u32 = 35;
pub const UTSNAME: u32 = 36;
pub const TIMEVAL: u32 = 37;
pub const TIMEZONE: u32 = 38;
pub const SYSINFO: u32 = 39;
pub const STATFS: u32 = 40;
pub const EPOLLEVENT: u32 = 41;
pub const INT_ARRAY_1: u32 = 42;
pub const INT_ARRAY_2: u32 = 43;
pub const SIGINFO_V2: u32 = 44;
pub const UINT_ARRAY_1: u32 = 45;
pub const SIGSET: u32 = 46;
pub const INT_PTR: u32 = 47;
pub const UINT_PTR: u32 = 48;
pub const BUFFER_X2: u32 = 49;
pub const IOVEC_X2: u32 = 50;
pub const INT_FCNTL_FLAGS: u32 = 51;
pub const INT_STATX_FLAGS: u32 = 52;
pub const INT_UNLINK_FLAGS: u32 = 53;
pub const INT_SOCKET_FLAGS: u32 = 54;
pub const INT_FILE_FLAGS: u32 = 55;
pub const INT16_PERM_FLAGS: u32 = 56;
pub const CONST_ARGTYPE_END: u32 = 57;

// ---- Operational constants (from common/const.go:3-10) ---------------------
pub const MAX_IOV_COUNT: u32 = 6;
pub const MAX_LOOP_COUNT: u32 = 32;
pub const MAX_BUF_READ_SIZE: u32 = 4096;

// ---- arm64 struct sizes (Go unsafe.Sizeof on linux/arm64) ------------------
// These are the sizes Go's `unsafe.Sizeof` computes for the target arch.
// The eBPF VM uses them to know how many bytes to read per struct.
// Values verified against Go 1.21+ syscall package definitions for linux/arm64.
pub const SIZEOF_TIMESPEC: u32 = 16;
pub const SIZEOF_TIMEVAL: u32 = 16;
pub const SIZEOF_STAT_T: u32 = 128;
pub const SIZEOF_STATFS_T: u32 = 120;
pub const SIZEOF_RUSAGE: u32 = 144;
pub const SIZEOF_SYSINFO_T: u32 = 112;
pub const SIZEOF_EPOLL_EVENT: u32 = 12;
pub const SIZEOF_IOVEC: u32 = 16;
pub const SIZEOF_MSGHDR: u32 = 56;
pub const SIZEOF_POLLFD: u32 = 8;
pub const SIZEOF_SOCKADDR_UN: u32 = 110;

// Custom structs (from config_struct.go / config_struct_forarm64.go)
pub const SIZEOF_SIGACTION: u32 = 40; // 5 * uint64
pub const SIZEOF_SIGINFO: u32 = 24; // 4*i32 + u64
pub const SIZEOF_STACK_T: u32 = 16; // u64 + i32 + i32 (Go def, not C ABI)
pub const SIZEOF_DIRENT: u32 = 280; // u64+i64+u16+u8+[256]byte+[5]byte
pub const SIZEOF_ITTMERSPEC: u32 = 32; // 2 * Timespec(16)
pub const SIZEOF_UTSNAME: u32 = 390; // 6 * [65]int8
pub const SIZEOF_TIMEZONE: u32 = 8; // 2 * int32

// ---- arm64 struct field offsets (Go unsafe.Offsetof on linux/arm64) --------
// Used by Build* op constructors for iovec/msghdr field accesses.
pub const OFFSET_IOVEC_LEN: u64 = 8;
pub const OFFSET_MSGHDR_IOV: u64 = 16;
pub const OFFSET_MSGHDR_IOVLEN: u64 = 24;
pub const OFFSET_MSGHDR_CONTROL: u64 = 32;
pub const OFFSET_MSGHDR_CONTROLLEN: u64 = 40;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_index_constants_match_go() {
        assert_eq!(CONST_ARGTYPE_START, 0);
        assert_eq!(POINTER, 1);
        assert_eq!(INT, 2);
        assert_eq!(BUFFER, 19);
        assert_eq!(IOVEC, 20);
        assert_eq!(CONST_ARGTYPE_END, 57);
    }

    #[test]
    fn format_constants_match_go() {
        assert_eq!(FORMAT_NUM, 0);
        assert_eq!(FORMAT_BIN, 5);
    }
}
