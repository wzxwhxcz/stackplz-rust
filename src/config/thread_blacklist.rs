//! Default thread-name blacklist shared by every module.
//!
//! Mirrors `ModuleConfig.DefaultThreadBlacklist()` in
//! `user/config/config_module.go:809-836` (branch `dev`):
//!
//! ```go
//! var thread_blacklist []string = []string{
//!     "Profile Saver", "Runtime worker", "ReferenceQueueD",
//!     "FinalizerDaemon", "FinalizerWatchd", "HeapTaskDaemon",
//!     "perfetto_hprof_", /* "Jit thread pool", */ "RenderThread",
//!     "FinalizerDaemon", "RxCachedThreadS", "mali-cmar-backe",
//!     "mali-utility-wo", "mali-mem-purge", "mali-hist-dump",
//!     "mali-event-hand", "hwuiTask0", "hwuiTask1", "NDK MediaCodec_",
//! }
//! if this.FullTName { return []string{} }
//! ```
//!
//! Two details are deliberately preserved because they are observable:
//! - **18 entries**, not the 10 this crate used to ship (report W8/F6).
//! - `"FinalizerDaemon"` appears **twice** in upstream. The duplicate is kept so
//!   a future diff against `dev` stays a pure diff instead of quietly growing a
//!   "cleanup" that would make the lists differ again.
//! - `"Jit thread pool"` is commented out upstream (it is >16 bytes), so it is
//!   absent here too.
//!
//! Every entry must fit the 16-byte `thread_filter` key (`thread_name_t` in
//! `ebpf/common/types.h`), otherwise the map update cannot represent it; see
//! [`validate_thread_name`].

use anyhow::Result;

/// Maximum thread-name length expressible in the eBPF `thread_filter` key.
/// `struct thread_filter_t { char thread_name[16]; }` — 16 bytes, no NUL
/// terminator required (the kernel side compares `__builtin_memcmp` over 16).
pub const THREAD_NAME_MAX_LEN: usize = 16;

/// The upstream `dev` default thread blacklist (18 entries, duplicate included).
pub const DEFAULT_THREAD_BLACKLIST: [&str; 18] = [
    "Profile Saver",
    "Runtime worker",
    "ReferenceQueueD",
    "FinalizerDaemon",
    "FinalizerWatchd",
    "HeapTaskDaemon",
    "perfetto_hprof_",
    "RenderThread",
    "FinalizerDaemon",
    "RxCachedThreadS",
    "mali-cmar-backe",
    "mali-utility-wo",
    "mali-mem-purge",
    "mali-hist-dump",
    "mali-event-hand",
    "hwuiTask0",
    "hwuiTask1",
    "NDK MediaCodec_",
];

/// `DefaultThreadBlacklist()`: the 18 defaults, or nothing when the user asked
/// for `--full-tname` (disable the default blacklist).
pub fn default_thread_blacklist(full_tname: bool) -> &'static [&'static str] {
    if full_tname {
        &[]
    } else {
        &DEFAULT_THREAD_BLACKLIST
    }
}

/// Upstream panics (`"[%s] thread name max len is 16"`) when a user-supplied
/// thread name exceeds 16 bytes; here it is a recoverable error.
pub fn validate_thread_name(name: &str) -> Result<()> {
    if name.len() > THREAD_NAME_MAX_LEN {
        anyhow::bail!(
            "[{}] thread name max len is 16 (got {} bytes)",
            name,
            name.len()
        );
    }
    Ok(())
}

/// Build the fixed-size `thread_filter` map key for `name`.
/// Upstream does `copy(filter_key.ThreadName[:], v)`, i.e. zero-padded.
pub fn thread_filter_key(name: &str) -> Result<[u8; THREAD_NAME_MAX_LEN]> {
    validate_thread_name(name)?;
    let mut key = [0u8; THREAD_NAME_MAX_LEN];
    key[..name.len()].copy_from_slice(name.as_bytes());
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Report W8/F6: this crate shipped 10 entries; upstream `dev` has 18, with
    /// 17 distinct values (one duplicate).
    #[test]
    fn default_blacklist_matches_dev_eighteen_entries() {
        assert_eq!(DEFAULT_THREAD_BLACKLIST.len(), 18);
        let mut distinct: Vec<&str> = DEFAULT_THREAD_BLACKLIST.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            17,
            "upstream contains FinalizerDaemon twice"
        );

        // Spot-check the entries that only upstream has: the old 10-entry list
        // was prefix-based (`pool-`, `mali-`, `Binder:`) and could never match
        // under the 16-byte exact comparison in `ebpf/common/filtering.h`.
        for name in [
            "Profile Saver",
            "Runtime worker",
            "NDK MediaCodec_",
            "hwuiTask0",
        ] {
            assert!(DEFAULT_THREAD_BLACKLIST.contains(&name), "missing {name}");
        }
        assert!(
            !DEFAULT_THREAD_BLACKLIST.contains(&"pool-"),
            "prefix entries are dead under a 16-byte exact match and are not in dev"
        );
        assert!(!DEFAULT_THREAD_BLACKLIST.contains(&"Jit thread pool"));
    }

    /// `--full-tname` disables the default blacklist entirely (dev semantics).
    #[test]
    fn full_tname_disables_the_default_blacklist() {
        assert_eq!(default_thread_blacklist(false).len(), 18);
        assert!(default_thread_blacklist(true).is_empty());
    }

    /// Every default entry must be representable in the 16-byte key.
    #[test]
    fn every_default_entry_fits_the_sixteen_byte_key() {
        for name in DEFAULT_THREAD_BLACKLIST {
            assert!(
                name.len() <= THREAD_NAME_MAX_LEN,
                "{name} does not fit the thread_filter key"
            );
            let key = thread_filter_key(name).unwrap();
            assert_eq!(&key[..name.len()], name.as_bytes());
            assert!(key[name.len()..].iter().all(|b| *b == 0));
        }
    }

    /// User-supplied names longer than 16 bytes are rejected instead of being
    /// silently truncated (dev panics; here it is a `bail!`).
    #[test]
    fn overlong_thread_name_is_rejected() {
        assert!(validate_thread_name("0123456789abcdef").is_ok());
        let err = validate_thread_name("0123456789abcdefg").unwrap_err();
        assert!(err.to_string().contains("max len is 16"), "{err}");
    }
}
