//! Resolved target-app state. Mirrors `TargetConfig` in
//! `user/config/config_target.go`, populated by `parseByPackage`/`parseByUid`
//! (master) and by dev's `persistentPreRunEFunc` package-resolution loop
//! (`cli/cmd/root.go:206-250`).

/// Flags for the `-n` uid groups. Mirrors `util.GROUP_*`
/// (`user/util/helper.go:290-295`); the values are shared with the eBPF side
/// through `common_filter_t.trace_uid_group` (`contract::enums::TraceGroup`).
pub use crate::contract::enums::TraceGroup;

/// Mirrors Go `config.TargetConfig`.
#[derive(Debug, Clone, Default)]
pub struct TargetConfig {
    pub name: String,
    pub uid: u64,
    pub pid: u64,
    /// Legacy 5-entry tid blacklist for the `filter_map` wire struct
    /// (`struct filter_t.tid_blacklist[5]`). The full list goes to
    /// `common_list`; this array is only the old on-wire mirror.
    pub tid_blacklist: [u32; crate::config::MAX_TID_BLACKLIST_COUNT],
    pub tid_blacklist_mask: u32,
    /// `ModuleConfig.TraceGroup`: uid-group bitmask from `-n root/system/...`.
    /// Written into `common_filter.trace_uid_group` (dev
    /// `config_module.go:991-993`). The previous stack module hard-coded `0xFF`
    /// here, which authorised every group for every run (report W17).
    pub trace_uid_group: u32,
    /// `-n` values that are package names (everything that is not a uid group).
    pub package_names: Vec<String>,
    /// Library search directories discovered via `legacyNativeLibraryDir/arm64`,
    /// plus any appended from the JSON hook config (`library_dirs`).
    pub library_dirs: Vec<String>,
    pub data_dir: String,
    /// CPU ABI string (only `arm64-v8a` is supported).
    pub abi: String,
}

impl TargetConfig {
    /// The device-independent part of `persistentPreRunEFunc`: turn `-n` into
    /// uid-group bits plus package names, and take the raw `-p` value.
    ///
    /// The device lookups (`dumpsys package`, `pm list package --uid`) are
    /// layered on top in `cli::root`; keeping this pure makes the group
    /// semantics testable on any host.
    pub fn from_globals(global: &crate::config::GlobalConfig) -> anyhow::Result<Self> {
        let (trace_uid_group, package_names) =
            crate::config::global::parse_name_groups(&global.name);
        let pid_list = crate::config::global::parse_id_list("PidWhitelist", &global.pid)?;
        Ok(TargetConfig {
            name: package_names.first().cloned().unwrap_or_default(),
            pid: pid_list.first().copied().unwrap_or(0) as u64,
            trace_uid_group,
            package_names,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::global::GlobalConfig;

    /// Report W4/F3: `-n root` must become a uid-group bit, never a package
    /// lookup, and the bit values must match `ebpf/common/consts.h`.
    #[test]
    fn name_groups_become_trace_group_bits() {
        let global = GlobalConfig {
            name: "root,system,shell,app,iso".to_string(),
            ..Default::default()
        };
        let target = TargetConfig::from_globals(&global).unwrap();
        assert_eq!(
            target.trace_uid_group,
            TraceGroup::Root as u32
                | TraceGroup::System as u32
                | TraceGroup::Shell as u32
                | TraceGroup::App as u32
                | TraceGroup::Iso as u32
        );
        assert_eq!(target.trace_uid_group, 0b11_1110);
        assert!(target.package_names.is_empty());
    }

    /// A package name still lands in `package_names` and is not silently
    /// dropped (report W19: a non-existent package used to be `Ok`).
    #[test]
    fn package_names_are_kept_separate_from_groups() {
        let global = GlobalConfig {
            name: "root,com.example.app".to_string(),
            ..Default::default()
        };
        let target = TargetConfig::from_globals(&global).unwrap();
        assert_eq!(target.trace_uid_group, TraceGroup::Root as u32);
        assert_eq!(target.package_names, vec!["com.example.app".to_string()]);
        assert_eq!(target.name, "com.example.app");
    }

    /// `-p 0` is a real whitelist entry under dev semantics (trace pid 0, i.e.
    /// nothing), not "flag absent".
    #[test]
    fn pid_zero_is_taken_literally() {
        let global = GlobalConfig {
            pid: "0".to_string(),
            ..Default::default()
        };
        let target = TargetConfig::from_globals(&global).unwrap();
        assert_eq!(target.pid, 0);
        // The distinction lives in the parsed list, not in this u64 mirror.
        assert_eq!(
            crate::config::global::parse_id_list("PidWhitelist", "0").unwrap(),
            vec![0]
        );
    }
}
