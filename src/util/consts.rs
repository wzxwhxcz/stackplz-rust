//! Constants for BPF map offsets. Mirrors `user/util/helper.go`.

/// Offset ranges for common_list map entries.
/// These offsets partition the map key space for different filter types.
pub const SYS_WHITELIST_START: u32 = 0x400;
pub const SYS_BLACKLIST_START: u32 = SYS_WHITELIST_START + 0x400;
pub const UID_WHITELIST_START: u32 = SYS_BLACKLIST_START + 0x400;
pub const UID_BLACKLIST_START: u32 = UID_WHITELIST_START + 0x400;
pub const PID_WHITELIST_START: u32 = UID_BLACKLIST_START + 0x400;
pub const PID_BLACKLIST_START: u32 = PID_WHITELIST_START + 0x400;
pub const TID_WHITELIST_START: u32 = PID_BLACKLIST_START + 0x400;
pub const TID_BLACKLIST_START: u32 = TID_WHITELIST_START + 0x400;
