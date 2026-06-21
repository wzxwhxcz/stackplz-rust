//! Resolved target-app state. Mirrors `TargetConfig` in
//! `user/config/config_target.go`, populated by `parseByPackage`/`parseByUid`
//! in `cli/cmd/root.go`.

/// Mirrors Go `config.TargetConfig`.
#[derive(Debug, Clone, Default)]
pub struct TargetConfig {
    pub name: String,
    pub uid: u64,
    pub pid: u64,
    pub tid_blacklist: [u32; crate::config::MAX_TID_BLACKLIST_COUNT],
    pub tid_blacklist_mask: u32,
    /// Library search directories discovered via `legacyNativeLibraryDir/arm64`,
    /// plus any appended from the JSON hook config (`library_dirs`).
    pub library_dirs: Vec<String>,
    pub data_dir: String,
    /// CPU ABI string (only `arm64-v8a` is supported).
    pub abi: String,
}
