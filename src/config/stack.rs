//! `stack` subcommand config and single-hook probe config.
//! Mirrors `config_stack.go` (`StackConfig`) and `config_hook.go` (`ProbeConfig`).

use super::sconfig::{stack_filter_from, HookConfig, SConfig, StackFilter};
use anyhow::{bail, Result};
use rand::Rng;

/// Flags for the `stack` subcommand. Mirrors `StackConfig` (`config_stack.go`).
#[derive(Debug, Clone, Default)]
pub struct StackConfig {
    pub unwind_stack: bool,
    pub show_regs: bool,
    pub library: String,
    pub symbol: String,
    pub offset: u64,
    pub reg_name: String,
    pub config: String,
}

impl StackConfig {
    pub fn from(args: &crate::cli::args::StackArgs) -> Self {
        Self {
            unwind_stack: args.stack,
            show_regs: args.regs,
            library: args.library.clone(),
            symbol: args.symbol.clone(),
            offset: args.offset,
            reg_name: args.reg.clone(),
            config: args.config.clone(),
        }
    }
}

/// A single uprobe hook point. Mirrors `ProbeConfig` (`config_hook.go`).
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub sconfig: SConfig,
    /// Library display name from config (informational).
    pub lib_name: String,
    /// Resolved full library path on disk.
    pub library: String,
    /// Target symbol name (may be a synthetic random string when only an
    /// offset is supplied, because ebpfmanager requires a non-empty
    /// `AttachToFuncName`).
    pub symbol: String,
    /// Target file offset (0 if hooking by symbol).
    pub offset: u64,
}

impl ProbeConfig {
    /// Validate the hook point. Mirrors `ProbeConfig.Check()` in
    /// `config_hook.go:32-56`.
    ///
    /// Rules:
    /// - Library must exist on disk.
    /// - Exactly one of symbol / offset must be set (not both, not neither).
    /// - When only an offset is provided, fill `symbol` with a random 8-char
    ///   string (the manager still needs a non-empty `AttachToFuncName`).
    pub fn check(&mut self) -> Result<()> {
        if self.library.is_empty() {
            bail!("library path is empty");
        }
        if !std::path::Path::new(&self.library).exists() {
            bail!("library not found: {}", self.library);
        }
        let has_symbol = !self.symbol.is_empty();
        let has_offset = self.offset != 0;
        if !has_symbol && !has_offset {
            bail!("must set symbol or offset");
        }
        if has_symbol && has_offset {
            bail!("set symbol or offset, not both");
        }
        if !has_symbol {
            // ebpfmanager requires AttachToFuncName non-empty even when an
            // offset is used. Fill with a random 8-char ASCII lowercase name.
            let mut rng = rand::thread_rng();
            let chars: String = (0..8)
                .map(|_| {
                    let c = rng.gen_range(b'a'..=b'z');
                    c as char
                })
                .collect();
            self.symbol = chars;
        }
        Ok(())
    }

    /// Produce the on-wire `StackFilter` for `filter_map`.
    /// Mirrors `ProbeConfig.GetFilter()` (`config_hook.go:58-66`).
    pub fn get_filter(&self) -> StackFilter {
        stack_filter_from(&self.sconfig)
    }

    /// Human-readable hook label, used for log lines.
    /// Mirrors `ProbeConfig.Info()` (`config_hook.go`).
    pub fn info(&self) -> String {
        if self.offset != 0 && !self.lib_name.is_empty() {
            format!("{} {}+0x{:x}", self.lib_name, self.symbol, self.offset)
        } else if self.offset != 0 {
            format!("0x{:x}", self.offset)
        } else {
            self.symbol.clone()
        }
    }
}

impl HookConfig for ProbeConfig {
    fn sconfig(&self) -> &SConfig {
        &self.sconfig
    }
    fn sconfig_mut(&mut self) -> &mut SConfig {
        &mut self.sconfig
    }
    fn info(&self) -> String {
        ProbeConfig::info(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_lib() -> String {
        // Use the cargo manifest path as a stand-in existing file.
        env!("CARGO_MANIFEST_DIR").to_string() + "/Cargo.toml"
    }

    #[test]
    fn check_requires_symbol_or_offset() {
        let mut p = ProbeConfig {
            sconfig: SConfig::default(),
            lib_name: String::new(),
            library: tmp_lib(),
            symbol: String::new(),
            offset: 0,
        };
        assert!(p.check().is_err());
    }

    #[test]
    fn check_rejects_both_symbol_and_offset() {
        let mut p = ProbeConfig {
            sconfig: SConfig::default(),
            lib_name: String::new(),
            library: tmp_lib(),
            symbol: "open".into(),
            offset: 0x1000,
        };
        assert!(p.check().is_err());
    }

    #[test]
    fn check_fills_random_symbol_when_offset_only() {
        let mut p = ProbeConfig {
            sconfig: SConfig::default(),
            lib_name: String::new(),
            library: tmp_lib(),
            symbol: String::new(),
            offset: 0x1000,
        };
        assert!(p.check().is_ok());
        assert_eq!(p.symbol.len(), 8);
        assert!(p.symbol.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn check_symbol_only_passes() {
        let mut p = ProbeConfig {
            sconfig: SConfig::default(),
            lib_name: String::new(),
            library: tmp_lib(),
            symbol: "open".into(),
            offset: 0,
        };
        assert!(p.check().is_ok());
        assert_eq!(p.symbol, "open");
    }

    #[test]
    fn get_filter_produces_expected_bytes() {
        let p = ProbeConfig {
            sconfig: SConfig {
                uid: 5,
                pid: 7,
                tid_blacklist_mask: 0b1,
                tid_blacklist: [42, 0, 0, 0, 0],
                ..Default::default()
            },
            lib_name: String::new(),
            library: String::new(),
            symbol: "x".into(),
            offset: 0,
        };
        let f = p.get_filter();
        assert_eq!(f.uid, 5);
        assert_eq!(f.pid, 7);
        assert_eq!(f.tid_blacklist_mask, 0b1);
        assert_eq!(f.tid_blacklist[0], 42);
    }
}
