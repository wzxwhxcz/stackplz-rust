//! JSON hook-config DTOs for the `stack --config` file.
//! Mirrors `BaseHookConfig`, `LibHookConfig`, `HookConfig` in
//! `cli/cmd/stack.go:28-44` and the `parseConfig` logic (`stack.go:199-307`).
//!
//! Schema (matches the shipped `config.json`):
//! ```jsonc
//! {
//!   "library_dirs": ["/apex/com.android.runtime/lib64"],
//!   "libs": [
//!     {
//!       "library": "bionic/libc.so",
//!       "disable": false,
//!       "configs": [
//!         { "stack": true, "regs": true, "symbols": ["open"], "offsets": [] },
//!         { "stack": false, "regs": true, "symbols": ["read"], "offsets": ["0xF37C"] }
//!       ]
//!     }
//!   ]
//! }
//! ```

use serde::{Deserialize, Serialize};

/// One (stack, regs) combination with its symbols and offsets.
/// Mirrors `BaseHookConfig` (`stack.go:28-33`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaseHookConfig {
    #[serde(rename = "stack", default)]
    pub unwindstack: bool,
    #[serde(default)]
    pub regs: bool,
    #[serde(default)]
    pub symbols: Vec<String>,
    #[serde(default)]
    pub offsets: Vec<String>,
}

/// A library's full hook config. Mirrors `LibHookConfig` (`stack.go:35-39`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LibHookConfig {
    pub library: String,
    #[serde(default)]
    pub disable: bool,
    #[serde(default)]
    pub configs: Vec<BaseHookConfig>,
}

/// Top-level hook config. Mirrors `HookConfig` (`stack.go:41-44`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookConfig {
    #[serde(rename = "library_dirs", default)]
    pub library_dirs: Vec<String>,
    #[serde(default)]
    pub libs: Vec<LibHookConfig>,
}

/// Decode a hex offset string like `"0xF37C"` / `"0xf37c"` to a u64.
/// Mirrors `hex2int` (`stack.go:46-50`): strip the `0x` prefix then parse
/// base-16. Invalid input yields 0 (matching Go's ignored error).
pub fn hex2int(hex: &str) -> u64 {
    let cleaned = hex.replace("0x", "").replace("0X", "");
    u64::from_str_radix(&cleaned, 16).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample_config_json() {
        let json = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.json")).unwrap();
        let cfg: HookConfig = serde_json::from_str(&json).unwrap();
        assert!(!cfg.library_dirs.is_empty());
        assert_eq!(cfg.libs.len(), 2);
        assert_eq!(cfg.libs[0].library, "bionic/libc.so");
        assert_eq!(cfg.libs[0].configs.len(), 2);
        assert_eq!(cfg.libs[0].configs[0].symbols, vec!["open"]);
        assert_eq!(cfg.libs[0].configs[1].symbols, vec!["read", "send", "recv"]);
        assert_eq!(cfg.libs[1].library, "libnative-lib.so");
        assert_eq!(cfg.libs[1].configs[0].symbols, vec!["_Z5func1v"]);
        assert_eq!(cfg.libs[1].configs[0].offsets, vec!["0xF37C"]);
    }

    #[test]
    fn hex2int_values() {
        assert_eq!(hex2int("0xF37C"), 0xF37C);
        assert_eq!(hex2int("0xf37c"), 0xF37C);
        assert_eq!(hex2int("F37C"), 0xF37C);
        assert_eq!(hex2int("0"), 0);
        assert_eq!(hex2int("garbage"), 0);
    }

    #[test]
    fn serde_roundtrip() {
        let cfg = HookConfig {
            library_dirs: vec!["/a".into()],
            libs: vec![LibHookConfig {
                library: "libc.so".into(),
                disable: false,
                configs: vec![BaseHookConfig {
                    unwindstack: true,
                    regs: false,
                    symbols: vec!["open".into()],
                    offsets: vec![],
                }],
            }],
        };
        let s = serde_json::to_string(&cfg).unwrap();
        let back: HookConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back.libs[0].configs[0].symbols, vec!["open"]);
    }
}
