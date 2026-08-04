//! Perf mmap2 monitoring configuration. Mirrors `user/config/config_perf_mmap.go` (if exists).

use super::sconfig::{HookConfig, SConfig};

/// Configuration for the perf mmap2 monitoring module.
#[derive(Debug, Clone)]
pub struct PerfMmapConfig {
    pub sconfig: SConfig,
    pub debug: bool,
}

impl PerfMmapConfig {
    pub fn new() -> Self {
        Self {
            sconfig: SConfig::default(),
            debug: false,
        }
    }
}

impl Default for PerfMmapConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl HookConfig for PerfMmapConfig {
    fn sconfig(&self) -> &SConfig {
        &self.sconfig
    }

    fn sconfig_mut(&mut self) -> &mut SConfig {
        &mut self.sconfig
    }

    fn info(&self) -> String {
        format!(
            "PerfMmapConfig {{ uid:{} pid:{} debug:{} }}",
            self.sconfig.uid, self.sconfig.pid, self.debug
        )
    }
}
