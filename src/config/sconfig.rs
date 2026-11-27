//! Shared hook config primitives.

use anyhow::{bail, Result};

/// Maximum number of entries in the tid blacklist. Mirrors Go constant.
pub const MAX_TID_BLACKLIST_COUNT: usize = 5;

/// Shared hook options, embedded into both `ProbeConfig` and `SyscallConfig`.
/// Master-era `SConfig` (`origin/master:user/config/iconfig.go:26-35`); dev
/// folds these fields into `ModuleConfig` (`config_module.go:752-799`).
#[derive(Debug, Clone, Default)]
pub struct SConfig {
    pub uid: u64,
    pub pid: u64,
    pub tid_blacklist_mask: u32,
    pub tid_blacklist: [u32; MAX_TID_BLACKLIST_COUNT],
}

/// Trait abstraction over hook configs. Master-era `IConfig` interface
/// (`origin/master:user/config/iconfig.go:20-24`): `GetSConfig()/SetDebug()/Info()`.
pub trait HookConfig: Send + Sync {
    fn sconfig(&self) -> &SConfig;
    fn sconfig_mut(&mut self) -> &mut SConfig;
    fn info(&self) -> String;
}

/// Build a tid blacklist (array + mask) from a comma-separated string.
/// Mirrors master-era `persistentPreRunEFunc` tid parsing
/// (`origin/master:cli/cmd/root.go:81-92`).
///
/// Returns `(blacklist_array, mask)`. Errors if more than 5 entries.
pub fn parse_tid_blacklist(raw: &str) -> Result<([u32; MAX_TID_BLACKLIST_COUNT], u32)> {
    let mut blacklist = [0u32; MAX_TID_BLACKLIST_COUNT];
    let mut mask: u32 = 0;
    if raw.is_empty() {
        return Ok((blacklist, mask));
    }
    let parts: Vec<&str> = raw.split(',').collect();
    if parts.len() > MAX_TID_BLACKLIST_COUNT {
        bail!(
            "max tid blacklist count is {}, provided count:{}",
            MAX_TID_BLACKLIST_COUNT,
            parts.len()
        );
    }
    for (i, v) in parts.iter().enumerate() {
        let value: u32 = v.trim().parse().unwrap_or(0);
        blacklist[i] = value;
        mask |= 1u32 << i;
    }
    Ok((blacklist, mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tid_blacklist_basic() {
        let (arr, mask) = parse_tid_blacklist("100,200").unwrap();
        assert_eq!(arr, [100, 200, 0, 0, 0]);
        assert_eq!(mask, 0b00011);
    }

    #[test]
    fn parse_tid_blacklist_empty() {
        let (arr, mask) = parse_tid_blacklist("").unwrap();
        assert_eq!(arr, [0; 5]);
        assert_eq!(mask, 0);
    }

    #[test]
    fn parse_tid_blacklist_too_many() {
        assert!(parse_tid_blacklist("1,2,3,4,5,6").is_err());
    }

    #[test]
    fn parse_tid_blacklist_full() {
        let (_, mask) = parse_tid_blacklist("1,2,3,4,5").unwrap();
        assert_eq!(mask, 0b11111);
    }
}
