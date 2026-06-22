//! Kernel capability probing. Mirrors `pkg/ebpf/{bpf.go, android.go, parse.go}`.
//!
//! - `get_system_config()` reads `/proc/config.gz` (auto-detecting gzip via the
//!   `0x1f 0x8b` magic) and parses `CONFIG_*` lines into a map. Mirrors
//!   `pkg/ebpf/android.go` + `parse.go`.
//! - `is_enable_bpf()` asserts required BPF/uprobe configs are `y`. Mirrors
//!   `IsEnableBPF` (`bpf.go`).

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::io::Read;

const REQUIRED_CONFIGS: &[&str] = &[
    "CONFIG_BPF",
    "CONFIG_UPROBES",
    "CONFIG_ARCH_SUPPORTS_UPROBES",
];

/// Read `/proc/config.gz` (or a known fallback path) and return the kernel
/// config as a `CONFIG_*` -> value map. Mirrors `GetSystemConfig`.
pub fn get_system_config() -> Result<HashMap<String, String>> {
    let raw = std::fs::read("/proc/config.gz")?;
    let text = if raw.starts_with(&[0x1f, 0x8b]) {
        // gzip magic
        let mut decoder = flate2::read::GzDecoder::new(&raw[..]);
        let mut out = String::new();
        decoder.read_to_string(&mut out)?;
        out
    } else {
        String::from_utf8_lossy(&raw).into_owned()
    };
    Ok(parse_config(&text))
}

/// Parse `CONFIG_XXX=y|n|m|...` lines into a map. Mirrors `parse()`.
pub fn parse_config(text: &str) -> HashMap<String, String> {
    let re = regex::Regex::new(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$").unwrap();
    let mut map = HashMap::new();
    for line in text.lines() {
        if let Some(caps) = re.captures(line.trim()) {
            let key = caps.get(1).unwrap().as_str().to_string();
            let value = caps.get(2).unwrap().as_str().trim_matches('"').to_string();
            map.insert(key, value);
        }
    }
    map
}

/// Whether the kernel has the required BPF/uprobe features enabled.
/// Mirrors `IsEnableBPF`.
pub fn is_enable_bpf() -> Result<()> {
    let config = get_system_config()?;
    for key in REQUIRED_CONFIGS {
        let v = config
            .get(*key)
            .cloned()
            .unwrap_or_else(|| "not set".into());
        if v != "y" {
            return Err(anyhow!(
                "{} is not enabled ({}), please check kernel config",
                key,
                v
            ));
        }
    }
    Ok(())
}

/// Whether BTF is available (`/sys/kernel/btf/vmlinux` exists, or
/// `CONFIG_DEBUG_INFO_BTF=y`). Mirrors `IsEnableBTF`.
pub fn is_enable_btf() -> bool {
    if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        return true;
    }
    if let Ok(config) = get_system_config() {
        if config.get("CONFIG_DEBUG_INFO_BTF").map(|s| s.as_str()) == Some("y") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config_basic() {
        let text = "\
# comment
CONFIG_BPF=y
CONFIG_UPROBES=y
CONFIG_ARCH_SUPPORTS_UPROBES=y
CONFIG_DEBUG_INFO_BTF=n
CONFIG_FOO=\"bar\"
";
        let m = parse_config(text);
        assert_eq!(m.get("CONFIG_BPF").map(|s| s.as_str()), Some("y"));
        assert_eq!(m.get("CONFIG_UPROBES").map(|s| s.as_str()), Some("y"));
        assert_eq!(m.get("CONFIG_FOO").map(|s| s.as_str()), Some("bar"));
        assert_eq!(
            m.get("CONFIG_DEBUG_INFO_BTF").map(|s| s.as_str()),
            Some("n")
        );
        assert!(!m.contains_key("# comment"));
    }

    #[test]
    fn parse_config_ignores_unrelated_lines() {
        let m = parse_config("random line\nNOT_CONFIG=y\nCONFIG_X=m");
        assert_eq!(m.get("CONFIG_X").map(|s| s.as_str()), Some("m"));
        assert!(!m.contains_key("NOT_CONFIG"));
    }
}
