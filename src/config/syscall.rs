//! `syscall` subcommand config. Mirrors `SyscallConfig` (`config_syscall.go`).

use super::sconfig::{syscall_filter_from, HookConfig, SConfig, SyscallFilter};

/// A single syscall tracepoint hook. Mirrors `SyscallConfig`.
#[derive(Debug, Clone)]
pub struct SyscallConfig {
    pub sconfig: SConfig,
    /// Syscall hook config file path (currently unused beyond CLI parsing).
    pub config: String,
    /// Syscall number to filter on. -1 means "match none" (default).
    pub nr: i64,
}

impl SyscallConfig {
    /// Produce the on-wire `SyscallFilter` for `filter_map`.
    /// Mirrors `SyscallConfig.GetFilter()` (`config_syscall.go:26-35`).
    pub fn get_filter(&self) -> SyscallFilter {
        syscall_filter_from(&self.sconfig, self.nr)
    }

    /// Human-readable hook label, used for log lines.
    /// Mirrors `SyscallConfig.Info()` (`config_syscall.go`).
    pub fn info(&self) -> String {
        format!("nr:{}", self.nr)
    }
}

impl HookConfig for SyscallConfig {
    fn sconfig(&self) -> &SConfig {
        &self.sconfig
    }
    fn sconfig_mut(&mut self) -> &mut SConfig {
        &mut self.sconfig
    }
    fn info(&self) -> String {
        SyscallConfig::info(self)
    }
}
