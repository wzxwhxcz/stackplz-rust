//! Constants for BPF map offsets. Mirrors `user/util/helper.go`.

// Re-exported from the single source of truth in [`crate::contract::consts`] so
// the two copies can never drift apart again. The `common_list` segment stride
// used to be duplicated as a literal here and in `ebpf/common/consts.h`.
pub use crate::contract::consts::{
    COMMON_LIST_MAX_KEY, COMMON_LIST_SEGMENT_STRIDE, PID_BLACKLIST_START, PID_WHITELIST_START,
    SYS_BLACKLIST_START, SYS_WHITELIST_START, TID_BLACKLIST_START, TID_WHITELIST_START,
    UID_BLACKLIST_START, UID_WHITELIST_START,
};
