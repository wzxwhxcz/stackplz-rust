//! Syscall tracepoint module. Mirrors `MSyscall` (`user/module/syscall.go`).
//!
//! Implements the dev-branch syscall runtime:
//!   - Loads `syscall.o` and attaches `raw_tracepoint/sys_enter` + `sys_exit` + `sched_process_fork`
//!   - Updates BPF maps: `base_config`, `common_filter`, `common_list`, `thread_filter`,
//!     `arg_filter`, `sysenter_point_args`, `sysexit_point_args`, `op_list`
//!   - Polls the unified `events` perf map and decodes TLV payloads via `contract::decode`

use crate::config::SyscallConfig;
use crate::logger::Logger;
use anyhow::{bail, Result};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use {
    crate::contract::{THREAD_NAME_BLACKLIST, THREAD_NAME_WHITELIST},
    anyhow::{anyhow, Context},
    libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder, PerfBufferBuilder},
    std::sync::atomic::{AtomicBool, Ordering},
    std::time::Duration,
};

/// Module name. Mirrors `MODULE_NAME_SYSCALL` (`const.go`).
pub const NAME: &str = super::MODULE_NAME_SYSCALL;

pub struct SyscallTracepointModule {
    pub conf: SyscallConfig,
    pub lib_path: String,
}

impl SyscallTracepointModule {
    pub fn new(conf: SyscallConfig, lib_path: String) -> Self {
        SyscallTracepointModule { conf, lib_path }
    }

    /// Run the module until cancelled / an error occurs.
    #[cfg(not(target_os = "linux"))]
    pub fn run(self, _logger: Arc<Logger>) -> Result<()> {
        bail!("{}: Linux-only module", NAME)
    }

    #[cfg(target_os = "linux")]
    pub fn run(self, logger: Arc<Logger>) -> Result<()> {
        logger.println(&format!("{}: starting syscall runtime", NAME));

        // Load eBPF object
        let bpf_path = format!("{}/syscall.o", self.lib_path);
        logger.println(&format!("{}: loading {}", NAME, bpf_path));
        
        let mut obj_builder = ObjectBuilder::default();
        obj_builder.debug(self.conf.debug);
        let open_obj = obj_builder
            .open_file(&bpf_path)
            .context("failed to open syscall.o")?;
        
        let mut obj = open_obj.load().context("failed to load syscall.o")?;

        // Attach raw tracepoints
        logger.println(&format!("{}: attaching raw tracepoints", NAME));
        self.attach_tracepoints(&mut obj)?;

        // Update all BPF maps
        logger.println(&format!("{}: updating BPF maps", NAME));
        self.update_all_maps(&mut obj, &logger)?;

        // Set up perf event polling
        logger.println(&format!("{}: starting event polling", NAME));
        self.poll_events(&mut obj, logger)?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn attach_tracepoints(&self, obj: &mut Object) -> Result<()> {
        // Attach sys_enter
        let prog = obj
            .progs_mut()
            .find(|p| p.name() == "raw_tracepoint__sys_enter")
            .ok_or_else(|| anyhow!("sys_enter program not found"))?;
        let _link = prog.attach()?;
        std::mem::forget(_link); // Keep attached

        // Attach sys_exit
        let prog = obj
            .progs_mut()
            .find(|p| p.name() == "raw_tracepoint__sys_exit")
            .ok_or_else(|| anyhow!("sys_exit program not found"))?;
        let _link = prog.attach()?;
        std::mem::forget(_link);

        // Attach sched_process_fork
        let prog = obj
            .progs_mut()
            .find(|p| p.name() == "raw_tracepoint__sched_process_fork")
            .ok_or_else(|| anyhow!("sched_process_fork program not found"))?;
        let _link = prog.attach()?;
        std::mem::forget(_link);

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn update_all_maps(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        self.update_base_config(obj, logger)?;
        self.update_common_filter(obj, logger)?;
        self.update_child_parent(obj, logger)?;
        self.update_thread_filter(obj, logger)?;
        self.update_arg_filter(obj, logger)?;
        self.update_sysenter_point_args(obj, logger)?;
        self.update_sysexit_point_args(obj, logger)?;
        self.update_op_list(obj, logger)?;
        
        // Update syscall whitelist/blacklist
        self.update_common_list(
            obj,
            &self.conf.sys_whitelist,
            crate::util::SYS_WHITELIST_START,
            "syscall whitelist",
            logger,
        )?;
        self.update_common_list(
            obj,
            &self.conf.sys_blacklist,
            crate::util::SYS_BLACKLIST_START,
            "syscall blacklist",
            logger,
        )?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn update_base_config(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        let map = obj
            .maps_mut()
            .find(|m| m.name() == "base_config")
            .context("base_config map not found")?;
        let key: u32 = 0;
        let value = self.conf.to_base_config_bytes();
        
        map.update(&key.to_ne_bytes(), &value, MapFlags::ANY)
            .context("failed to update base_config")?;
        
        logger.println("updated base_config");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn update_common_filter(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        // Update uid/pid/tid whitelists and blacklists
        self.update_common_list(
            obj,
            &self.conf.uid_whitelist,
            crate::util::UID_WHITELIST_START,
            "uid whitelist",
            logger,
        )?;
        self.update_common_list(
            obj,
            &self.conf.uid_blacklist,
            crate::util::UID_BLACKLIST_START,
            "uid blacklist",
            logger,
        )?;
        self.update_common_list(
            obj,
            &self.conf.pid_whitelist,
            crate::util::PID_WHITELIST_START,
            "pid whitelist",
            logger,
        )?;
        self.update_common_list(
            obj,
            &self.conf.pid_blacklist,
            crate::util::PID_BLACKLIST_START,
            "pid blacklist",
            logger,
        )?;
        self.update_common_list(
            obj,
            &self.conf.tid_whitelist,
            crate::util::TID_WHITELIST_START,
            "tid whitelist",
            logger,
        )?;
        self.update_common_list(
            obj,
            &self.conf.tid_blacklist,
            crate::util::TID_BLACKLIST_START,
            "tid blacklist",
            logger,
        )?;

        // Update common_filter struct
        let map = obj
            .maps_mut()
            .find(|m| m.name() == "common_filter")
            .context("common_filter map not found")?;
        let key: u32 = 0;
        let value = self.conf.to_common_filter_bytes();
        
        map.update(&key.to_ne_bytes(), &value, MapFlags::ANY)
            .context("failed to update common_filter")?;
        
        logger.println("updated common_filter");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn update_common_list(
        &self,
        obj: &mut Object,
        items: &[u32],
        offset: u32,
        name: &str,
        logger: &Logger,
    ) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }

        let map = obj
            .maps_mut()
            .find(|m| m.name() == "common_list")
            .context("common_list map not found")?;
        
        for &item in items {
            let key = item + offset;
            map.update(&key.to_ne_bytes(), &key.to_ne_bytes(), MapFlags::ANY)
                .with_context(|| format!("failed to update common_list for {}", name))?;
        }
        
        logger.println(&format!("updated {} ({} items)", name, items.len()));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn update_child_parent(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        if self.conf.pid_whitelist.is_empty() {
            return Ok(());
        }

        let map = obj
            .maps_mut()
            .find(|m| m.name() == "child_parent_map")
            .context("child_parent_map not found")?;
        
        for &pid in &self.conf.pid_whitelist {
            map.update(&pid.to_ne_bytes(), &pid.to_ne_bytes(), MapFlags::ANY)
                .context("failed to update child_parent_map")?;
        }
        
        logger.println("updated child_parent_map");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn update_thread_filter(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        let map = obj
            .maps_mut()
            .find(|m| m.name() == "thread_filter")
            .context("thread_filter map not found")?;
        
        // Add default blacklist
        for name in self.conf.default_thread_blacklist() {
            self.add_thread_filter(map, name, THREAD_NAME_BLACKLIST)?;
        }
        
        // Add user-specified blacklist
        for name in &self.conf.tname_blacklist {
            self.add_thread_filter(map, name, THREAD_NAME_BLACKLIST)?;
        }
        
        // Add user-specified whitelist
        for name in &self.conf.tname_whitelist {
            self.add_thread_filter(map, name, THREAD_NAME_WHITELIST)?;
        }
        
        logger.println("updated thread_filter");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn add_thread_filter(
        &self,
        map: &libbpf_rs::Map,
        name: &str,
        filter_type: u32,
    ) -> Result<()> {
        if name.len() > 16 {
            bail!("thread name '{}' exceeds 16 bytes", name);
        }
        
        let mut key = [0u8; 16];
        key[..name.len()].copy_from_slice(name.as_bytes());
        
        map.update(&key, &filter_type.to_ne_bytes(), MapFlags::ANY)
            .with_context(|| format!("failed to add thread filter for '{}'", name))
    }

    #[cfg(target_os = "linux")]
    fn update_arg_filter(&self, _obj: &mut Object, logger: &Logger) -> Result<()> {
        // TODO: implement filter parser in Phase 4
        logger.println("arg_filter update skipped (Phase 4)");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn update_sysenter_point_args(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        use crate::contract::SyscallPointArgs;
        
        let map = obj
            .maps_mut()
            .find(|m| m.name() == "sysenter_point_args")
            .context("sysenter_point_args map not found")?;

        // TODO Phase 4: Parse syscall points from config file.
        // For now, we iterate over an empty list. Once config parsing is complete,
        // this.conf.syscall_points will be populated with SyscallPoint structs.
        let syscall_points: Vec<(u32, Vec<u32>)> = Vec::new(); // (syscall_nr, op_list)
        
        for (syscall_nr, enter_ops) in &syscall_points {
            let mut point_args = SyscallPointArgs::default();
            point_args.enter_key = 0;
            point_args.signal = 0;
            point_args.op_count = enter_ops.len().min(point_args.op_key_list.len()) as u32;
            
            for (i, &op) in enter_ops.iter().enumerate() {
                if i >= point_args.op_key_list.len() {
                    break;
                }
                point_args.op_key_list[i] = op;
            }
            
            let key = syscall_nr.to_ne_bytes();
            let val = unsafe {
                std::slice::from_raw_parts(
                    &point_args as *const _ as *const u8,
                    std::mem::size_of::<SyscallPointArgs>(),
                )
            };
            
            map.update(&key, val, libbpf_rs::MapFlags::ANY)
                .with_context(|| format!("Failed to update sysenter_point_args for syscall {}", syscall_nr))?;
        }
        
        logger.println(&format!("sysenter_point_args updated: {} entries", syscall_points.len()));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn update_sysexit_point_args(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        use crate::contract::SyscallPointArgs;
        
        let map = obj
            .maps_mut()
            .find(|m| m.name() == "sysexit_point_args")
            .context("sysexit_point_args map not found")?;

        // TODO Phase 4: Parse syscall points from config file.
        let syscall_points: Vec<(u32, Vec<u32>)> = Vec::new(); // (syscall_nr, op_list)
        
        for (syscall_nr, exit_ops) in &syscall_points {
            let mut point_args = SyscallPointArgs::default();
            point_args.enter_key = 0;
            point_args.signal = 0;
            point_args.op_count = exit_ops.len().min(point_args.op_key_list.len()) as u32;
            
            for (i, &op) in exit_ops.iter().enumerate() {
                if i >= point_args.op_key_list.len() {
                    break;
                }
                point_args.op_key_list[i] = op;
            }
            
            let key = syscall_nr.to_ne_bytes();
            let val = unsafe {
                std::slice::from_raw_parts(
                    &point_args as *const _ as *const u8,
                    std::mem::size_of::<SyscallPointArgs>(),
                )
            };
            
            map.update(&key, val, libbpf_rs::MapFlags::ANY)
                .with_context(|| format!("Failed to update sysexit_point_args for syscall {}", syscall_nr))?;
        }
        
        logger.println(&format!("sysexit_point_args updated: {} entries", syscall_points.len()));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn update_op_list(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        use crate::contract::OpConfig;
        
        let map = obj
            .maps_mut()
            .find(|m| m.name() == "op_list")
            .context("op_list map not found")?;

        // TODO Phase 4: Generate op_list from argtype definitions.
        // This requires porting argtype::GetALLOpList() which collects all
        // operation configs from registered argument types.
        let op_configs: Vec<(u32, OpConfig)> = Vec::new(); // (op_key, op_config)
        
        for (op_key, op_config) in &op_configs {
            let key = op_key.to_ne_bytes();
            let val = unsafe {
                std::slice::from_raw_parts(
                    &op_config as *const _ as *const u8,
                    std::mem::size_of::<OpConfig>(),
                )
            };
            
            map.update(&key, val, libbpf_rs::MapFlags::ANY)
                .with_context(|| format!("Failed to update op_list for key {}", op_key))?;
        }
        
        logger.println(&format!("op_list updated: {} entries", op_configs.len()));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn poll_events(&self, obj: &mut Object, logger: Arc<Logger>) -> Result<()> {
        let map = obj
            .maps()
            .find(|m| m.name() == "events")
            .context("events map not found")?;
        
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .context("failed to set Ctrl-C handler")?;

        let logger_clone = Arc::clone(&logger);
        let handle_event = move |_cpu: i32, data: &[u8]| {
            match crate::contract::decode_perf_record(data) {
                Ok(decoded) => {
                    logger_clone.println(&format!("{:?}", decoded));
                }
                Err(e) => {
                    logger_clone.println(&format!("decode error: {}", e));
                }
            }
        };

        let handle_lost = |_cpu: i32, count: u64| {
            eprintln!("Lost {} events", count);
        };

        let perf = PerfBufferBuilder::new(map)
            .sample_cb(handle_event)
            .lost_cb(handle_lost)
            .build()
            .context("failed to build perf buffer")?;

        logger.println(&format!("{}: polling events (Ctrl-C to stop)", NAME));

        while running.load(Ordering::SeqCst) {
            if let Err(e) = perf.poll(Duration::from_millis(100)) {
                logger.println(&format!("poll error: {}", e));
                break;
            }
        }

        logger.println(&format!("{}: shutting down", NAME));
        Ok(())
    }
}
