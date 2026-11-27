//! Syscall tracepoint module. Mirrors `MSyscall` (`user/module/syscall.go`).
//!
//! Implements the dev-branch syscall runtime:
//!   - Loads `syscall.o` and attaches `raw_tracepoint/sys_enter` + `sys_exit` + `sched_process_fork`
//!   - Updates BPF maps: `base_config`, `common_filter`, `common_list`, `thread_filter`,
//!     `arg_filter`, `sysenter_point_args`, `sysexit_point_args`, `op_list`
//!   - Polls the unified `events` perf map and decodes TLV payloads via `contract::decode`

use crate::config::SyscallConfig;
use crate::logger::Logger;
use crate::signal::{
    auto_resume_after_event, record_stopped_after_event, ConsoleResume, SignalManager,
};
use anyhow::{bail, Context, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use {
    crate::contract::decode::HasContext,
    crate::contract::{THREAD_NAME_BLACKLIST, THREAD_NAME_WHITELIST},
    anyhow::anyhow,
    libbpf_rs::{Link, MapCore, MapFlags, Object, ObjectBuilder, PerfBufferBuilder},
    std::time::Duration,
};

/// Module name. Mirrors `MODULE_NAME_SYSCALL` (`const.go`).
pub const NAME: &str = super::MODULE_NAME_SYSCALL;

pub struct SyscallTracepointModule {
    pub conf: SyscallConfig,
}

impl SyscallTracepointModule {
    pub fn new(conf: SyscallConfig) -> Self {
        SyscallTracepointModule { conf }
    }

    /// Run the module until cancelled / an error occurs.
    #[cfg(not(target_os = "linux"))]
    pub fn run(self, _logger: Arc<Logger>, _resume: Arc<ConsoleResume>) -> Result<()> {
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
    ) -> Result<Vec<(u32, crate::contract::SyscallPointArgs)>> {
        use crate::contract::SyscallPointArgs;
        let mut entries = Vec::with_capacity(self.conf.point_table.len());
        for point in self.conf.point_table.points() {
            let config = match side {
                PointArgsSide::Enter => point.enter_config()?,
                PointArgsSide::Exit => point.exit_config()?,
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
        Ok(entries)
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
    pub fn run(self, logger: Arc<Logger>, resume: Arc<ConsoleResume>) -> Result<()> {
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

        // Attach raw tracepoints. Keep the returned links alive until the poll
        // loop ends: `Link::drop` calls `bpf_link__destroy`, so a per-attach
        // local would detach the tracepoint immediately (`mem::forget` would
        // instead leak the fd).
        logger.println(&format!("{}: attaching raw tracepoints", NAME));
        let _links = self.attach_tracepoints(&mut obj)?;

        // Update all BPF maps
        logger.println(&format!("{}: updating BPF maps", NAME));
        self.update_all_maps(&mut obj, &logger)?;

        // Set up perf event polling
        logger.println(&format!("{}: starting event polling", NAME));
        self.poll_events(&mut obj, logger, resume)?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn attach_tracepoints(&self, obj: &mut Object) -> Result<Vec<Link>> {
        let mut links = Vec::with_capacity(3);
        for prog_name in [
            "raw_tracepoint__sys_enter",
            "raw_tracepoint__sys_exit",
            "raw_tracepoint__sched_process_fork",
        ] {
            let prog = obj
                .progs_mut()
                .find(|p| p.name() == prog_name)
                .ok_or_else(|| anyhow!("{prog_name} program not found"))?;
            links.push(prog.attach()?);
        }
        Ok(links)
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

        logger.println(&format!("{}: updated base_config", NAME));
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

        logger.println(&format!("{}: updated common_filter", NAME));
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

        // R11-10: compute all keys through the shared range-checked helper
        // (same rejection as the stack side) so a value that would land in the
        // next segment — e.g. a whitelist uid >= 0x400000 landing in the
        // blacklist segment — fails loudly here instead of silently flipping
        // the filter. Previously `item + offset` wrapped (u32::MAX) or spilled
        // into the blacklist segment without any error.
        let keys = crate::ebpf::bpf_common::common_list_keys(items, offset)
            .with_context(|| format!("invalid {name} entries"))?;

        let map = obj
            .maps_mut()
            .find(|m| m.name() == "common_list")
            .context("common_list map not found")?;

        for key in keys {
            map.update(&key.to_ne_bytes(), &key.to_ne_bytes(), MapFlags::ANY)
                .with_context(|| format!("failed to update common_list for {}", name))?;
        }

        logger.println(&format!(
            "{}: updated {} ({} items)",
            NAME,
            name,
            items.len()
        ));
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

        logger.println(&format!("{}: updated child_parent_map", NAME));
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

        logger.println(&format!("{}: updated thread_filter", NAME));
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
            logger.println(&format!("{}: arg_filter: no -f filters to write", NAME));
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

        logger.println(&format!(
            "{}: arg_filter updated: {} filters",
            NAME,
            entries.len()
        ));
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

        let entries = self.point_args_entries(side)?;
        for (nr, value) in &entries {
            let key = nr.to_ne_bytes();
            let value_bytes = bytemuck::bytes_of(value);
            map.update(&key, value_bytes, MapFlags::ANY)
                .with_context(|| format!("failed to update {map_name} for syscall {nr}"))?;
        }

        logger.println(&format!(
            "{}: {map_name} updated: {} entries",
            NAME,
            entries.len()
        ));
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

        logger.println(&format!(
            "{}: op_list updated: {} entries",
            NAME,
            op_configs.len()
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn poll_events(
        &self,
        obj: &mut Object,
        logger: Arc<Logger>,
        resume: Arc<ConsoleResume>,
    ) -> Result<()> {
        let map = obj
            .maps()
            .find(|m| m.name() == "events")
            .context("events map not found")?;

        // Ctrl-C is owned by `cli::install_signal_handler` (which flips
        // `cli::INTERRUPTED`); a second handler here would replace it and make
        // shutdown order-dependent, besides failing on a second module start.

        // The renderer needs the point table to turn a decoded record into the
        // dev-format line (`argtype`-aware, not the raw `Debug` dump).
        let point_table = Arc::new(self.conf.point_table.clone());
        let dump_hex = self.conf.dump_hex;
        let logger_clone = Arc::clone(&logger);
        // Round 7 / F4 / G3: before `--auto` resumes the event pid, record it
        // as stopped when the kill signal is SIGSTOP (Go `event_context.go:185`
        // records, `event_raw_syscalls.go:72-73` resumes). Round 9 / H24: the
        // manager is shared (`Arc<Mutex<…>>`) between this perf callback and
        // the stdin `c` resume thread spawned below.
        let auto_resume = self.conf.auto_resume;
        let kill_signal = self.conf.kill_signal;
        let sig_mgr = Arc::new(Mutex::new(SignalManager::new()));
        let sig_mgr_cb = Arc::clone(&sig_mgr);
        let sig_mgr_resume = Arc::clone(&sig_mgr_cb);
        let handle_event = move |_cpu: i32, data: &[u8]| {
            let mut decoded = match crate::contract::decode_perf_record(data) {
                Ok(decoded) => decoded,
                Err(e) => {
                    logger_clone.println(&format!("{e}"));
                    return;
                }
            };
            let pid = decoded.context().pid;
            match crate::event::render::render_syscall_event(&point_table, &mut decoded, dump_hex) {
                Ok(line) => {
                    logger_clone.println(&line);
                    {
                        let mut g = sig_mgr_cb.lock().unwrap_or_else(|p| p.into_inner());
                        record_stopped_after_event(&mut g, kill_signal, pid);
                    }
                    auto_resume_after_event(
                        &mut |pid| {
                            // resume_one prints its own diagnostics; nothing
                            // to propagate from a perf callback.
                            let mut g = sig_mgr_resume.lock().unwrap_or_else(|p| p.into_inner());
                            let _ = g.resume_one(pid);
                        },
                        auto_resume,
                        pid,
                    );
                }
                Err(e) => logger_clone.println(&format!("{e}")),
            }
        };

        let lost_logger = Arc::clone(&logger);
        let lost_total = Arc::new(AtomicU64::new(0));
        let lost_total_cb = Arc::clone(&lost_total);
        let handle_lost = move |cpu: i32, count: u64| {
            account_lost(&lost_total_cb, &lost_logger, NAME, cpu, count);
        };

        let perf = PerfBufferBuilder::new(&map)
            .pages(super::perf_pages(self.conf.buffer_mb)?)
            .sample_cb(handle_event)
            .lost_cb(handle_lost)
            .build()
            .context("failed to build perf buffer")?;

        logger.println(&format!("{}: polling events (Ctrl-C to stop)", NAME));

        // Round 9 / H24: stdin `c` resumes stopped pids (Go `root.go:429`).
        // Round 11 / R11-5: the console-resume thread moved up to `run_modules`
        // — one shared reader for all modules, so one `c` resumes every
        // module. Register this module's manager with that shared reader.
        resume.register(Arc::clone(&sig_mgr));

        // Round 10 / K1 (replaces round 9 / H1): a poll failure is not fatal
        // — Go logs the read error, stops this reader, and shuts down
        // normally with its TotalLost summary (`imodule.go:250-258`).
        poll_until_shutdown(
            || perf.poll(Duration::from_millis(100)),
            &logger,
            &lost_total,
            crate::cli::interrupted,
        );
        Ok(())
    }
}

/// Shared perf-loss accounting (Round 9 / H2, round 10 / I2): add `count` to
/// the running total and log the per-CPU line. Both modules print the
/// accumulated total at shutdown (`TotalLost => N`, mirroring Go). The line
/// carries the module name (Go `imodule.go:261` prints `child.Name()`); the
/// CPU field has no Go counterpart but is kept — it says which ring filled.
/// `record_type` (Go's `record.RecordType`) is NOT printed: libbpf-rs 0.27's
/// lost callback is `FnMut(cpu: i32, count: u64)` — neither it nor the
/// underlying C `perf_buffer_lost_fn` delivers a record type, so there is
/// nothing truthful to print here.
pub(crate) fn account_lost(total: &AtomicU64, logger: &Logger, name: &str, cpu: i32, count: u64) {
    total.fetch_add(count, Ordering::Relaxed);
    logger.println(&format!("{name}\tlost {count} samples on CPU {cpu}"));
}

/// Shared perf poll loop (Round 9 / H1): poll until Ctrl-C. A poll error is
/// returned to the caller instead of exiting cleanly as `Ok(())` — the old
/// syscall loop swallowed it with `break`. The caller decides what an error
/// means; round 10 / K1 treats it as "stop this reader" (log + normal
/// shutdown, [`poll_until_stop`]), never as fatal — so this helper keeps
/// returning `Result` (H1's test depends on it).
pub(crate) fn poll_loop<T, E>(
    mut poll_once: impl FnMut() -> Result<T, E>,
    _logger: &Logger,
) -> Result<()>
where
    E: std::error::Error + Send + Sync + 'static,
{
    while !crate::cli::interrupted() {
        poll_once().map_err(|e| anyhow::Error::new(e).context("perf poll failed"))?;
    }
    Ok(())
}

/// Round 10 / K1: poll until Ctrl-C or a read error. A read error only stops
/// this reader (Go `imodule.go:250-258`) — it is logged and the caller shuts
/// down normally; it never fails the run. `shutdown_pending` is consulted
/// only when a poll error actually arrives: an error that races Ctrl-C is
/// the shutdown interrupting the read (Go's `perf.ErrClosed` equivalent) and
/// stops silently, so the shutdown log is not polluted with a bogus
/// "poll error" line. On this platform the handler is installed with plain
/// `signal()` (glibc: SA_RESTART), so a blocking poll is resumed, not
/// failed, on Ctrl-C — the loop then exits through the `interrupted()`
/// check and this branch is normally never taken.
pub(crate) fn poll_until_stop<T, E>(
    name: &str,
    poll_once: impl FnMut() -> Result<T, E>,
    logger: &Logger,
    shutdown_pending: impl Fn() -> bool,
) where
    E: std::error::Error + Send + Sync + 'static,
{
    if let Err(e) = poll_loop(poll_once, logger) {
        if !shutdown_pending() {
            logger.println(&format!("{name}\tpoll error, stopping reads: {e:#}"));
        }
    }
}

/// Round 10 / K1: the syscall run-loop tail — poll until Ctrl-C or a read
/// error, then print the shutdown summary (`shutting down` + `TotalLost`).
/// A poll error never fails the run: it is logged by [`poll_until_stop`]
/// and the summary still prints (Go's `Close()` always prints TotalLost).
/// The stack tail is separate: it prints its own summary format and drops
/// its attach links after the summary.
fn poll_until_shutdown<T, E>(
    poll_once: impl FnMut() -> Result<T, E>,
    logger: &Logger,
    lost_total: &AtomicU64,
    shutdown_pending: impl Fn() -> bool,
) where
    E: std::error::Error + Send + Sync + 'static,
{
    poll_until_stop(NAME, poll_once, logger, shutdown_pending);
    logger.println(&format!("{NAME}: shutting down"));
    // Round 14 / R13-1: the shutdown summary carries the module tag like
    // the line above (round 12 / R12-1 only fixed the setup lines).
    logger.println(&format!(
        "{NAME}: TotalLost => {}",
        lost_total.load(Ordering::Relaxed)
    ));
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
    use super::{
        account_lost, poll_loop, poll_until_shutdown, poll_until_stop, PointArgsSide,
        SyscallTracepointModule, NAME,
    };
    use crate::config::{SyscallConfig, SyscallPointTable};

    /// A poll closure that always fails (H1/K1 tests).
    #[derive(Debug)]
    struct FakePollError;
    impl std::fmt::Display for FakePollError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "fake ring failure")
        }
    }
    impl std::error::Error for FakePollError {}

    /// K1/I2: a logger that writes to a temp file (quiet: no terminal
    /// output), so tests can assert on the exact log lines. Returns the
    /// logger and the path to read back; the caller removes the file.
    /// `tag` must be unique per test (tests run in parallel in one process).
    fn capturing_logger(tag: &str) -> (crate::logger::Logger, std::path::PathBuf) {
        let logger = crate::logger::Logger::new("", false);
        let file_name = format!("stackplz-test-{tag}-{}.log", std::process::id());
        let dir = std::env::temp_dir();
        logger
            .set_out_file(dir.to_str().unwrap(), &file_name, true)
            .expect("test log file must open");
        (logger, dir.join(file_name))
    }

    fn read_log(path: &std::path::Path) -> String {
        std::fs::read_to_string(path).expect("test log file must be readable")
    }

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
        assert!(!openat.enter_config().unwrap().op_key_list.is_empty());
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
        let module = SyscallTracepointModule::new(conf);

        let enter = module.point_args_entries(PointArgsSide::Enter).unwrap();
        let exit = module.point_args_entries(PointArgsSide::Exit).unwrap();
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
        let module = SyscallTracepointModule::new(SyscallConfig::with_table(table));
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

    /// H1: `poll_loop` must propagate a poll failure as an error, never
    /// swallow it as `Ok(())` like the old swallowed-`break` version.
    /// (Round 10 / K1 keeps this `poll_loop` behavior — the call site is
    /// what changed, not the loop itself.)
    #[test]
    fn poll_failure_propagates_as_module_error() {
        let logger = crate::logger::Logger::new("", false);
        assert!(!crate::cli::interrupted(), "Ctrl-C must be clear in tests");
        let err = poll_loop(|| Err::<(), FakePollError>(FakePollError), &logger)
            .expect_err("poll failure must propagate as an error");
        // anyhow's context wraps the source: `to_string()` shows only the
        // outer "perf poll failed", so assert on the full chain instead.
        assert!(format!("{err:#}").contains("fake ring failure"), "{err:#}");
    }

    /// K1(a): an immediately failing poll stops the reads, logs the error,
    /// and still prints the shutdown summary — the run ends normally, not
    /// as a fatal module error (round 9 / H1 behavior). Old code returned
    /// `Err` here and never printed `TotalLost`.
    #[test]
    fn poll_error_stops_reads_and_still_prints_total_lost() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let (logger, path) = capturing_logger("k1-immediate-fail");
        let lost_total = AtomicU64::new(0);
        poll_until_shutdown(
            || Err::<(), FakePollError>(FakePollError),
            &logger,
            &lost_total,
            || false,
        );
        let log = read_log(&path);
        assert!(log.contains("poll error, stopping reads"), "{log}");
        assert!(log.contains("fake ring failure"), "{log}");
        assert!(log.contains("shutting down"), "{log}");
        assert!(log.contains("TotalLost => 0"), "{log}");
        assert_eq!(lost_total.load(Ordering::Relaxed), 0);
        let _ = std::fs::remove_file(&path);
    }

    /// K1(b): a poll that succeeds twice and then fails processes the first
    /// two polls and stops after the third — reads stop, they do not keep
    /// retrying, and the summary still prints.
    #[test]
    fn poll_error_after_two_events_stops_reading() {
        use std::cell::Cell;
        use std::sync::atomic::AtomicU64;
        let (logger, path) = capturing_logger("k1-two-then-fail");
        let lost_total = AtomicU64::new(0);
        let calls = Cell::new(0u32);
        poll_until_shutdown(
            || {
                let n = calls.get();
                calls.set(n + 1);
                if n < 2 {
                    Ok::<(), FakePollError>(())
                } else {
                    Err(FakePollError)
                }
            },
            &logger,
            &lost_total,
            || false,
        );
        assert_eq!(calls.get(), 3, "two good polls, then the failing one");
        let log = read_log(&path);
        assert!(log.contains("poll error, stopping reads"), "{log}");
        assert!(log.contains("fake ring failure"), "{log}");
        assert!(log.contains("TotalLost => 0"), "{log}");
        let _ = std::fs::remove_file(&path);
    }

    /// K1(c): a poll error that arrives while shutdown is already pending is
    /// the shutdown racing the read (Go's `perf.ErrClosed` equivalent) — it
    /// stops silently, with no misleading "poll error" line; the summary
    /// still prints.
    #[test]
    fn poll_error_while_shutting_down_is_silent() {
        let (logger, path) = capturing_logger("k1-shutdown-pending");
        poll_until_stop(
            NAME,
            || Err::<(), FakePollError>(FakePollError),
            &logger,
            || true,
        );
        let log = read_log(&path);
        assert!(!log.contains("poll error"), "{log}");
        let _ = std::fs::remove_file(&path);
    }

    /// H2 / I2: lost batches accumulate into one total (Go `TotalLost => N`),
    /// and each per-batch line names the module (Go prints `child.Name()`).
    #[test]
    fn lost_samples_accumulate_into_total() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let total = AtomicU64::new(0);
        let (logger, path) = capturing_logger("i2-account-lost");
        account_lost(&total, &logger, NAME, 3, 7);
        account_lost(&total, &logger, NAME, 3, 3);
        assert_eq!(total.load(Ordering::Relaxed), 10);
        let log = read_log(&path);
        assert!(log.contains(NAME), "{log}");
        assert!(log.contains("lost 7 samples on CPU 3"), "{log}");
        assert!(log.contains("lost 3 samples on CPU 3"), "{log}");
        let _ = std::fs::remove_file(&path);
    }
}
