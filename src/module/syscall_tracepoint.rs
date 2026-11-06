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

    /// Build the `(sysno, point_args_t)` entries for one side of the table.
    ///
    /// This is the **pure** half of `update_sysenter_point_args` /
    /// `update_sysexit_point_args`: the map is only written on Linux, but the
    /// payload must be testable everywhere, otherwise a regression back to
    /// "empty table" (report W1/F1) would compile and pass on the host.
    pub fn point_args_entries(
        &self,
        side: PointArgsSide,
    ) -> Vec<(u32, crate::contract::SyscallPointArgs)> {
        use crate::contract::SyscallPointArgs;
        let mut entries = Vec::with_capacity(self.conf.point_table.len());
        for point in self.conf.point_table.points() {
            let config = match side {
                PointArgsSide::Enter => point.enter_config(),
                PointArgsSide::Exit => point.exit_config(),
            };
            // `--kill`/`--tkill` are delivered through `common_filter`
            // (`signal`/`tsignal`), not per point; `syscall.c:165-167` reads the
            // per-point `signal` only for the legacy path, so it stays 0 exactly
            // like `SyscallPoint.GetEnterConfig()` does.
            let mut value = SyscallPointArgs {
                enter_key: 0,
                signal: 0,
                ..Default::default()
            };
            let op_count = config.op_key_list.len().min(value.op_key_list.len());
            value.op_count = op_count as u32;
            value.op_key_list[..op_count].copy_from_slice(&config.op_key_list[..op_count]);
            entries.push((point.nr, value));
        }
        entries
    }

    /// Build the `(filter_index, arg_filter_t bytes)` entries for the
    /// `arg_filter` map: the pure half of `update_arg_filter`.
    pub fn arg_filter_entries(&self) -> Vec<(u64, [u8; 272])> {
        crate::config::get_filters()
            .iter()
            .map(|filter| {
                (
                    u64::from(filter.filter_index),
                    arg_filter_wire_value(&filter.to_ebpf_value()),
                )
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    pub fn run(self, logger: Arc<Logger>) -> Result<()> {
        logger.println(&format!("{}: starting syscall runtime", NAME));

        // Load eBPF object from embedded bytecode
        logger.println(&format!("{}: loading embedded syscall.o", NAME));

        let obj_bytes = crate::ebpf::bpf_common::SYSCALL_OBJ;
        let mut obj_builder = ObjectBuilder::default();
        obj_builder.debug(self.conf.debug);
        let open_obj = obj_builder
            .open_memory(obj_bytes)
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

        // Add the default blacklist (18 dev entries, empty with --full-tname).
        for name in self.conf.default_thread_blacklist() {
            self.add_thread_filter(&map, name, THREAD_NAME_BLACKLIST)?;
        }

        // Add user-specified blacklist
        for name in &self.conf.tname_blacklist {
            self.add_thread_filter(&map, name, THREAD_NAME_BLACKLIST)?;
        }

        // Add user-specified whitelist
        for name in &self.conf.tname_whitelist {
            self.add_thread_filter(&map, name, THREAD_NAME_WHITELIST)?;
        }

        logger.println("updated thread_filter");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn add_thread_filter(&self, map: &libbpf_rs::Map, name: &str, filter_type: u32) -> Result<()> {
        if name.len() > 16 {
            bail!("thread name '{}' exceeds 16 bytes", name);
        }

        let mut key = [0u8; 16];
        key[..name.len()].copy_from_slice(name.as_bytes());

        map.update(&key, &filter_type.to_ne_bytes(), MapFlags::ANY)
            .with_context(|| format!("failed to add thread filter for '{}'", name))
    }

    #[cfg(target_os = "linux")]
    fn update_arg_filter(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        // Mirrors `MSyscall.update_arg_filter()` (`user/module/syscall.go:299-320`):
        // every filter registered by `-f` is written at key `filter_index`
        // (u64 key, `arg_filter_t` value) so `opc_filter_value` /
        // `opc_filter_string` can look it up on the kernel side.
        let entries = self.arg_filter_entries();
        if entries.is_empty() {
            logger.println("arg_filter: no -f filters to write");
            return Ok(());
        }

        let map = obj
            .maps_mut()
            .find(|m| m.name() == "arg_filter")
            .context("arg_filter map not found")?;

        for (filter_index, value) in &entries {
            let key = filter_index.to_ne_bytes();
            map.update(&key, value, MapFlags::ANY)
                .with_context(|| format!("failed to update arg_filter {filter_index}"))?;
        }

        logger.println(&format!("arg_filter updated: {} filters", entries.len()));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn update_sysenter_point_args(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        // Mirrors `MSyscall.update_sysenter_point_args()`
        // (`user/module/syscall.go:322-340`): one `point_args_t` per syscall
        // number, built from `SyscallPoint::enter_config()`. This is the map
        // `ebpf/syscall.c:86-87` looks up — if it is empty, the kernel program
        // returns 0 for every syscall and the whole module is a no-op
        // (report W1/F1).
        self.write_point_args(obj, logger, PointArgsSide::Enter)
    }

    #[cfg(target_os = "linux")]
    fn update_sysexit_point_args(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        // Mirrors `MSyscall.update_sysexit_point_args()`
        // (`user/module/syscall.go:342-360`).
        self.write_point_args(obj, logger, PointArgsSide::Exit)
    }

    /// Shared body of the enter/exit point-args writers.
    ///
    /// The kernel object defines the two maps with the same value type
    /// (`point_args_t` with `op_key_list[MAX_OP_COUNT]`, 256 entries for the
    /// syscall module), so only the map name and the argument side differ.
    #[cfg(target_os = "linux")]
    fn write_point_args(
        &self,
        obj: &mut Object,
        logger: &Logger,
        side: PointArgsSide,
    ) -> Result<()> {
        let map_name = side.map_name();
        let map = obj
            .maps_mut()
            .find(|m| m.name() == map_name)
            .with_context(|| format!("{map_name} map not found"))?;

        let entries = self.point_args_entries(side);
        for (nr, value) in &entries {
            let key = nr.to_ne_bytes();
            let value_bytes = bytemuck::bytes_of(value);
            map.update(&key, value_bytes, MapFlags::ANY)
                .with_context(|| format!("failed to update {map_name} for syscall {nr}"))?;
        }

        logger.println(&format!("{map_name} updated: {} entries", entries.len()));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn update_op_list(&self, obj: &mut Object, logger: &Logger) -> Result<()> {
        // Mirrors `MSyscall.update_op_list()` (`user/module/syscall.go:362-378`):
        // every op the argtype registry created (including the ones the point
        // table just created while building its op lists) must be in the map, or
        // the kernel VM cannot execute `op_key_list` entries.
        let map = obj
            .maps_mut()
            .find(|m| m.name() == "op_list")
            .context("op_list map not found")?;

        let op_configs = crate::argtype::get_all_op_list();
        for (op_key, op_config) in &op_configs {
            let key = op_key.to_ne_bytes();
            let value_bytes = bytemuck::bytes_of(op_config);
            map.update(&key, value_bytes, MapFlags::ANY)
                .with_context(|| format!("failed to update op_list for key {op_key}"))?;
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

        // The renderer needs the point table to turn a decoded record into the
        // dev-format line (`argtype`-aware, not the raw `Debug` dump).
        let point_table = Arc::new(self.conf.point_table.clone());
        let dump_hex = self.conf.dump_hex;
        let logger_clone = Arc::clone(&logger);
        let handle_event = move |_cpu: i32, data: &[u8]| {
            let rendered = crate::contract::decode_perf_record(data).and_then(|mut decoded| {
                crate::event::render::render_syscall_event(&point_table, &mut decoded, dump_hex)
            });
            match rendered {
                Ok(line) => logger_clone.println(&line),
                Err(e) => logger_clone.println(&format!("decode error: {}", e)),
            }
        };

        let handle_lost = |_cpu: i32, count: u64| {
            eprintln!("Lost {} events", count);
        };

        let perf = PerfBufferBuilder::new(&map)
            // `-b/--buffer` is in MiB; the perf ring buffer is measured in
            // 4 KiB pages, so 1 MiB == 256 pages (dev `GlobalConfig.Buffer`,
            // a "perf cache buffer size" in MB).
            .pages(self.conf.buffer_mb as usize * 256)
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

/// Serialize `arg_filter_t` (272 bytes) for the `arg_filter` map.
///
/// Layout from `ebpf/types.h` / `user/config/config_filter.go`:
/// `u32 filter_type`, `char str_val[MAX_STRCMP_LEN]`, `u32 str_len`,
/// `u64 num_val` — the compiler places `num_val` right after `str_len` at
/// offset 264 (already 8-aligned), so the struct is exactly 272 bytes with no
/// trailing padding. Written by hand instead of `bytemuck::bytes_of` because
/// `EArgFilter` has no `Pod` impl (and an unsafe one would need this same
/// layout argument anyway).
fn arg_filter_wire_value(value: &crate::config::EArgFilter) -> [u8; 272] {
    let mut bytes = [0u8; 272];
    bytes[0..4].copy_from_slice(&value.filter_type.to_ne_bytes());
    bytes[4..260].copy_from_slice(&value.str_val);
    bytes[260..264].copy_from_slice(&value.str_len.to_ne_bytes());
    bytes[264..272].copy_from_slice(&value.num_val.to_ne_bytes());
    bytes
}

/// Which side of a syscall point a `point_args_t` map belongs to.
///
/// `ebpf/syscall.c` looks up `sysenter_point_args[sysno]` on enter and
/// `sysexit_point_args[sysno]` on exit (`:81-82`, `:188-189`); the two values
/// differ only in which `group_type`'s ops were flattened into `op_key_list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointArgsSide {
    Enter,
    Exit,
}

impl PointArgsSide {
    /// Map name on the eBPF side (`ebpf/maps.h`).
    pub fn map_name(self) -> &'static str {
        match self {
            PointArgsSide::Enter => "sysenter_point_args",
            PointArgsSide::Exit => "sysexit_point_args",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PointArgsSide, SyscallTracepointModule};
    use crate::config::{SyscallConfig, SyscallPointTable};

    /// Report W1/F1: the module config must carry the real point table, and the
    /// maps must be derivable from it. This test does not load eBPF (no root /
    /// clang here); it locks the data path that used to be an empty `Vec::new()`.
    #[test]
    fn point_args_are_built_from_the_embedded_table() {
        crate::argtype::init_argtypes();
        let table = SyscallPointTable::embedded().unwrap();
        let conf = SyscallConfig::with_table(table);
        // The exact three tables the kernel program reads.
        assert!(conf.point_table.len() > 250);
        let openat = conf.point_table.by_name("openat").unwrap();
        assert!(!openat.enter_config().op_key_list.is_empty());
    }

    /// The enter/exit payloads written into `sysenter_point_args` /
    /// `sysexit_point_args` must be one entry per table point, with a non-zero
    /// `op_count` wherever the syscall has arguments. Reverting the fill back to
    /// `Vec::new()` (the old W1 state) fails here.
    #[test]
    fn point_args_entries_cover_the_whole_table() {
        crate::argtype::init_argtypes();
        let table = SyscallPointTable::embedded().unwrap();
        let expected = table.len();
        let conf = SyscallConfig::with_table(table);
        let module = SyscallTracepointModule::new(conf, String::new());

        let enter = module.point_args_entries(PointArgsSide::Enter);
        let exit = module.point_args_entries(PointArgsSide::Exit);
        assert_eq!(enter.len(), expected, "one enter entry per point");
        assert_eq!(exit.len(), expected, "one exit entry per point");

        let openat_nr = module.conf.point_table.by_name("openat").unwrap().nr;
        let (_, openat_enter) = enter
            .iter()
            .find(|(nr, _)| *nr == openat_nr)
            .expect("openat must be in sysenter_point_args");
        assert!(
            openat_enter.op_count > 0,
            "openat must carry ops, otherwise ebpf/syscall.c reads nothing"
        );
        assert!(openat_enter.op_count as usize <= openat_enter.op_key_list.len());
        assert_eq!(
            openat_enter.enter_key, 0,
            "GetEnterConfig sets Signal=0, EnterKey is unused"
        );

        // A no-argument syscall (only `ret`) has zero *enter* ops but still an
        // entry, so the kernel program does not bail at `syscall.c:82`.
        let vhangup_nr = module.conf.point_table.by_name("vhangup").unwrap().nr;
        let (_, vhangup_enter) = enter.iter().find(|(nr, _)| *nr == vhangup_nr).unwrap();
        assert_eq!(vhangup_enter.op_count, 0);
    }

    /// Every filter registered by `-f` must produce one `arg_filter` entry with
    /// the 272-byte wire layout; the old implementation wrote nothing
    /// (`arg_filter update skipped (Phase 4)`).
    #[test]
    fn arg_filter_entries_serialize_the_wire_layout() {
        let _ = crate::config::add_filter("w:/data");
        let table = SyscallPointTable::empty();
        let module = SyscallTracepointModule::new(SyscallConfig::with_table(table), String::new());
        let entries = module.arg_filter_entries();
        assert!(!entries.is_empty(), "-f filters must reach arg_filter");
        for (index, bytes) in &entries {
            assert_ne!(*index, 0, "filter_index is 1-based");
            // filter_type at 0, str_val[256] at 4, str_len at 260, num_val at 264.
            let filter_type = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
            assert!(filter_type <= 6, "filter_type must be one of the 7 kinds");
            let str_len = u32::from_ne_bytes(bytes[260..264].try_into().unwrap());
            assert!(str_len as usize <= 256);
        }
    }

    /// The `op_list` payload must be non-empty once the point table has been
    /// built, otherwise every `op_key_list` entry would dangle.
    #[test]
    fn op_list_is_populated_by_the_point_table() {
        crate::argtype::init_argtypes();
        let table = SyscallPointTable::embedded().unwrap();
        let conf = SyscallConfig::with_table(table);
        let _ = conf.point_table.points();
        let ops = crate::argtype::get_all_op_list();
        assert!(
            !ops.is_empty(),
            "op_list must contain the ops the point table references"
        );
    }
}
