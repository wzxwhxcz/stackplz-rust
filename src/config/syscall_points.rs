//! Syscall point table: the ported `config_syscall_{aarch64,aarch32}.json`.
//!
//! This is the fix for report §3.2 / W1 (F1, fatal): the syscall module used to
//! ship four **permanently empty** tables
//! (`sysenter_point_args` / `sysexit_point_args` / `op_list` / `arg_filter`),
//! and `ebpf/syscall.c:86-87,196-197` returns 0 as soon as
//! `bpf_map_lookup_elem(&sys*_point_args, &sysno)` yields `NULL`. With empty
//! maps that is *every* syscall, so the module could not emit a single event on
//! a real device.
//!
//! Upstream `dev` solves this by loading `user/config/config_syscall_aarch64.json`
//! (306 points) / `config_syscall_aarch32.json` (397 points) at start-up
//! (`cli/cmd/root.go:258-268` → `ModuleConfig.LoadConfig` →
//! `SyscallConfig.Parse_FileConfig`, `user/config/config_module.go:518-556`).
//! This module is the faithful Rust port of that path:
//!
//! - [`SyscallPointTable::from_json_str`] parses one of the embedded tables.
//! - [`SyscallPoint::from_config`] mirrors `Parse_FileConfig`: parameter names
//!   become `PointArg`s, `ret` is exit-only (`REG_ARM64_MAX`, no register read),
//!   and every parameter is cloned into an enter-side and an exit-side list
//!   with `group_type` = `EBPF_SYS_ENTER` / `EBPF_SYS_EXIT`.
//! - [`SyscallPoint::enter_config`] / [`SyscallPoint::exit_config`] mirror
//!   `GetEnterConfig` / `GetExitConfig` (`config_syscall.go:28-45`) and produce
//!   the exact `point_args_t` payload written into `sysenter_point_args` /
//!   `sysexit_point_args`.
//!
//! The JSON is embedded with `include_str!` just like upstream embeds it through
//! go-bindata (`assets.RestoreAsset`), so the binary carries its own table and
//! `--prepare` cannot leave a stale copy behind.

use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;

use super::file_parser::{SyscallFileConfig, SyscallPointConfig};
use super::point_arg::{
    PointArg, UprobeArgs, EBPF_SYS_ALL, EBPF_SYS_ENTER, EBPF_SYS_EXIT, REG_ARM64_MAX,
};
use crate::argtype::consts::INT;
use crate::contract::MAX_OP_COUNT_SYSCALL;

/// `user/config/config_syscall_aarch64.json` (upstream dev `62fc9e8`), 306 points.
pub const SYSCALL_CONFIG_AARCH64: &str =
    include_str!("../../assets/syscall/config_syscall_aarch64.json");
/// `user/config/config_syscall_aarch32.json` (upstream dev `62fc9e8`), 397 points.
pub const SYSCALL_CONFIG_AARCH32: &str =
    include_str!("../../assets/syscall/config_syscall_aarch32.json");

/// Upstream picks the table by build tag: `config_global_forarm64.go` returns
/// the aarch64 file, `config_global_forarm.go` the aarch32 one. The Rust analogue
/// is the pointer width of the target the binary is built for.
pub const fn arch_config_json() -> &'static str {
    if cfg!(target_pointer_width = "32") {
        SYSCALL_CONFIG_AARCH32
    } else {
        SYSCALL_CONFIG_AARCH64
    }
}

/// One syscall point: its number, its name, and the enter-side / exit-side
/// argument programs.
///
/// Mirrors `config.SyscallPoint` (`user/config/config_syscall.go:12-16`).
#[derive(Debug, Clone)]
pub struct SyscallPoint {
    pub nr: u32,
    pub name: String,
    /// Arguments read/parsed on `sys_enter` (`group_type = EBPF_SYS_ENTER`).
    pub enter_point_args: Vec<PointArg>,
    /// Arguments read/parsed on `sys_exit`, always ending with `ret`
    /// (`user/config/config_module.go:521-526`).
    pub exit_point_args: Vec<PointArg>,
}

impl SyscallPoint {
    /// Mirrors `SyscallConfig.Parse_FileConfig` (`config_module.go:518-556`)
    /// for a single point.
    pub fn from_config(config: &SyscallPointConfig) -> Result<Self> {
        let mut enter_point_args: Vec<PointArg> = Vec::new();
        let mut exit_point_args: Vec<PointArg> = Vec::new();

        for (arg_index, param) in config.point.params.iter().enumerate() {
            if param.name == "ret" {
                // The `ret` parameter is the syscall return value: read on exit
                // only, at no register (REG_ARM64_MAX makes `get_op_list()`
                // return an empty op list, i.e. "no argument read").
                let point_arg = param
                    .get_point_arg(REG_ARM64_MAX, EBPF_SYS_EXIT)
                    .with_context(|| {
                        format!("parse ret of syscall {} ({})", config.nr, config.point.name)
                    })?;
                exit_point_args.push(point_arg);
                // Upstream `break`s: nothing after `ret` is parsed.
                break;
            }

            let point_type = match param.more.as_str() {
                "" | "enter" => EBPF_SYS_ENTER,
                "exit" => EBPF_SYS_EXIT,
                "all" => EBPF_SYS_ALL,
                other => bail!(
                    "syscall {} ({}): unknown point_type:{other}",
                    config.nr,
                    config.point.name
                ),
            };

            let point_arg = param
                .get_point_arg(arg_index as u32, point_type)
                .with_context(|| {
                    format!(
                        "parse param {} of syscall {} ({})",
                        param.name, config.nr, config.point.name
                    )
                })?;

            // The same argument config is evaluated once on enter and once on
            // exit; `group_type` decides which of the two `read_more()` accepts.
            let mut a_p = point_arg.clone();
            a_p.set_group_type(EBPF_SYS_ENTER);
            enter_point_args.push(a_p);

            let mut b_p = point_arg;
            b_p.set_group_type(EBPF_SYS_EXIT);
            exit_point_args.push(b_p);
        }

        Ok(SyscallPoint {
            nr: config.nr,
            name: config.point.name.clone(),
            enter_point_args,
            exit_point_args,
        })
    }

    /// `GetEnterConfig()` (`config_syscall.go:28-36`): flatten every enter-side
    /// `PointArg::get_op_list()` into one `op_key_list`.
    pub fn enter_config(&self) -> Result<SyscallPointOpConfig> {
        Self::flatten(&self.enter_point_args)
    }

    /// `GetExitConfig()` (`config_syscall.go:38-45`).
    pub fn exit_config(&self) -> Result<SyscallPointOpConfig> {
        Self::flatten(&self.exit_point_args)
    }

    fn flatten(point_args: &[PointArg]) -> Result<SyscallPointOpConfig> {
        let mut config = SyscallPointOpConfig::default();
        for point_arg in point_args {
            config.add_point_arg(point_arg)?;
        }
        Ok(config)
    }
}

/// `SyscallPointOpKeyConfig` (`user/config/iconfig.go:34-55`): the flattened op
/// list for one side of a syscall point.
///
/// `op_key_list` is `[u32; SYSCALL_MAX_OP_COUNT]` on the Go side; here it is a
/// `Vec` capped at [`MAX_OP_COUNT_SYSCALL`] so an impossible config is an error
/// instead of a panic (upstream panics with "need increase max op count").
#[derive(Debug, Clone, Default)]
pub struct SyscallPointOpConfig {
    pub signal: u32,
    pub op_key_list: Vec<u32>,
}

impl SyscallPointOpConfig {
    /// `AddPointArg`: append one argument's op list, refusing to overflow the
    /// contract `point_args_t.op_key_list` width.
    ///
    /// The `-c/--config` table is user input, so an oversized point is a usage
    /// error, not a bug in the shipped JSON: return it instead of panicking.
    pub fn add_point_arg(&mut self, point_arg: &PointArg) -> Result<()> {
        for op in point_arg.get_op_list() {
            if self.op_key_list.len() >= MAX_OP_COUNT_SYSCALL {
                bail!("syscall point op list overflow: more than {MAX_OP_COUNT_SYSCALL} ops");
            }
            self.op_key_list.push(op);
        }
        Ok(())
    }

    pub fn op_count(&self) -> u32 {
        self.op_key_list.len() as u32
    }
}

/// The whole point table (`ModuleConfig.SysCallConf.PointArgs`).
#[derive(Debug, Clone)]
pub struct SyscallPointTable {
    points: Vec<SyscallPoint>,
    by_nr: HashMap<u32, usize>,
    by_name: HashMap<String, usize>,
}

impl SyscallPointTable {
    /// An empty table, for hand-built configs (tests, `SyscallConfig::new`).
    pub fn empty() -> Self {
        SyscallPointTable {
            points: Vec::new(),
            by_nr: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    /// Parse one JSON table. `dump_hex` / `color` are the global output flags
    /// that upstream bakes into every argument type at parse time
    /// (`config_module.go:543-544`).
    pub fn from_json_str(text: &str) -> Result<Self> {
        let file: SyscallFileConfig =
            serde_json::from_str(text).context("failed to parse syscall point table JSON")?;
        if file.base.config_type != "syscall" {
            bail!(
                "unexpected syscall config type {:?} (expected \"syscall\")",
                file.base.config_type
            );
        }
        if file.points.is_empty() {
            bail!("syscall point table is empty");
        }

        let mut points = Vec::with_capacity(file.points.len());
        let mut by_nr = HashMap::with_capacity(file.points.len());
        let mut by_name = HashMap::with_capacity(file.points.len());
        for config in &file.points {
            let point = SyscallPoint::from_config(config)?;
            if by_nr.insert(point.nr, points.len()).is_some() {
                bail!("duplicate syscall nr {} in point table", point.nr);
            }
            if by_name.insert(point.name.clone(), points.len()).is_some() {
                bail!("duplicate syscall name {:?} in point table", point.name);
            }
            points.push(point);
        }

        Ok(SyscallPointTable {
            points,
            by_nr,
            by_name,
        })
    }

    /// The table embedded in the binary for the target architecture.
    pub fn embedded() -> Result<Self> {
        Self::from_json_str(arch_config_json())
    }

    pub fn points(&self) -> &[SyscallPoint] {
        &self.points
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// `GetSyscallPointByNR` (upstream panics on an unknown number).
    pub fn by_nr(&self, nr: u32) -> Option<&SyscallPoint> {
        self.by_nr.get(&nr).map(|&i| &self.points[i])
    }

    /// `GetSyscallPointByName` (upstream panics on an unknown name).
    pub fn by_name(&self, name: &str) -> Option<&SyscallPoint> {
        self.by_name.get(name).map(|&i| &self.points[i])
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.points.iter().map(|p| p.name.as_str())
    }

    /// Resolve a `-s`/`--no-syscall` token to `(nr, filter_groups)`.
    ///
    /// Upstream `Parse_Syscall` (`config_module.go:647-732`) only accepts
    /// syscall **names** (plus the `%group` aliases, which
    /// [`crate::config::syscall_filter_spec`] expands before this is called).
    /// This crate additionally accepts a raw syscall **number**, which the
    /// previous rounds' CLI and tests already rely on; the number must still
    /// exist in the table so `-s 9999` keeps failing loudly.
    pub fn resolve(&self, token: &str) -> Result<&SyscallPoint> {
        if let Ok(nr) = token.parse::<u32>() {
            return self
                .by_nr(nr)
                .ok_or_else(|| anyhow!("unknown syscall nr:{nr}"));
        }
        self.by_name(token)
            .ok_or_else(|| anyhow!("unknown syscall name:{}", token))
    }

    /// Mutable access used to attach `-s name:f0.f2` filters to one point.
    pub fn point_mut(&mut self, name: &str) -> Option<&mut SyscallPoint> {
        let index = *self.by_name.get(name)?;
        self.points.get_mut(index)
    }

    /// Mutable access by number (numeric `-s 63:f0` form).
    pub fn point_mut_by_nr(&mut self, nr: u32) -> Option<&mut SyscallPoint> {
        let index = *self.by_nr.get(&nr)?;
        self.points.get_mut(index)
    }

    /// `SyscallConfig.UpdateSyscallPoint` (`config_module.go:483-515`, round 11
    /// / P1): rebind one `-w ...]s` uprobe point onto the same-named syscall
    /// point, replacing that point's enter/exit argument lists with the uprobe
    /// point's arguments.
    ///
    /// Returns `Ok(false)` when the point does not bind (`bind_syscall` is
    /// false) — the caller keeps it in the uprobe list. An unknown syscall
    /// name is an error (Go panics with `unknown syscall name`; this crate
    /// returns it so the CLI can fail loudly instead of hanging a probe that
    /// goes nowhere).
    ///
    /// The replacement mirrors Go exactly: each argument is cloned twice
    /// (`group_type` ENTER / EXIT, `point_type` ALL when `exit_read`, else
    /// ENTER) and the exit list ends with a synthetic `ret` (`B("ret", INT)` —
    /// no register, `REG_ARM64_MAX`, so it contributes no ops, exactly like
    /// the `ret` that [`SyscallPoint::from_config`] builds for table points).
    ///
    /// Note the `]ss` suffix order: Go checks `]s` first, so its `]ss` branch
    /// is unreachable (`config_module.go:344-351`); this crate checks `]ss`
    /// first (`point_parser.rs`), so `exit_read` really is reachable here.
    /// That is a deliberate fix of the upstream bug, not a divergence to
    /// "align back".
    pub fn update_syscall_point(&mut self, point: &UprobeArgs) -> Result<bool> {
        if !point.bind_syscall {
            return Ok(false);
        }
        let index = *self
            .by_name
            .get(point.name.as_str())
            .ok_or_else(|| anyhow!("unknown syscall name:{}", point.name))?;
        let point_type = if point.exit_read {
            EBPF_SYS_ALL
        } else {
            EBPF_SYS_ENTER
        };
        let mut enter_point_args: Vec<PointArg> = Vec::with_capacity(point.point_args.len());
        let mut exit_point_args: Vec<PointArg> = Vec::with_capacity(point.point_args.len() + 1);
        for arg in &point.point_args {
            let mut a_p = arg.clone();
            a_p.set_group_type(EBPF_SYS_ENTER);
            a_p.set_point_type(point_type);
            enter_point_args.push(a_p);

            let mut b_p = arg.clone();
            b_p.set_group_type(EBPF_SYS_EXIT);
            b_p.set_point_type(point_type);
            exit_point_args.push(b_p);
        }
        exit_point_args.push(PointArg::new("ret", INT, EBPF_SYS_EXIT));
        let target = &mut self.points[index];
        target.enter_point_args = enter_point_args;
        target.exit_point_args = exit_point_args;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::argtype::init_argtypes;

    fn table() -> SyscallPointTable {
        init_argtypes();
        SyscallPointTable::embedded().expect("the embedded syscall table must parse")
    }

    /// Report §5.3 / brief item 1: the whole defect existed because nothing
    /// tested that the table is non-empty. This is the source-contract test.
    #[test]
    fn embedded_table_is_not_empty_and_has_real_arguments() {
        let table = table();
        assert!(
            table.len() > 250,
            "the ported dev table has 306 (aarch64) / 397 (aarch32) points, got {}",
            table.len()
        );
        // Every point must carry at least one enter-side op list entry, or the
        // C side would read nothing even when the map lookup succeeds.
        let points_with_ops = table
            .points()
            .iter()
            .filter(|p| p.enter_config().is_ok_and(|c| !c.op_key_list.is_empty()))
            .count();
        assert!(
            points_with_ops > 250,
            "expected nearly every point to have enter ops, got {points_with_ops}"
        );
    }

    /// The /proc-style syscalls this project documents must exist by name and
    /// number, matching upstream `dev`'s table.
    #[test]
    fn well_known_syscalls_resolve_by_name_and_nr() {
        let table = table();
        for (name, nr) in [
            ("write", 64u32),
            ("openat", 56),
            ("read", 63),
            ("execve", 221),
            ("clone", 220),
            ("io_setup", 0),
            ("set_mempolicy_home_node", 450),
        ] {
            let by_name = table
                .by_name(name)
                .unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(by_name.nr, nr, "{name} nr");
            assert_eq!(
                table.by_nr(nr).map(|p| p.name.as_str()),
                Some(name),
                "nr {nr} must map back to {name}"
            );
        }
    }

    /// aarch32 is a different table (397 points) and must parse too.
    #[test]
    fn aarch32_table_parses_with_the_other_point_count() {
        init_argtypes();
        let table = SyscallPointTable::from_json_str(SYSCALL_CONFIG_AARCH32).unwrap();
        assert_eq!(table.len(), 397);
        // aarch32 `write` is nr 4, aarch64 `write` is nr 64: the tables really
        // do differ, so embedding the right one matters.
        assert_eq!(table.by_name("write").map(|p| p.nr), Some(4));
        assert_eq!(table.by_name("openat").map(|p| p.nr), Some(322));
    }

    /// `ret` is exit-only and must contribute no ops of its own (it has no
    /// register: `REG_ARM64_MAX` short-circuits `get_op_list()`).
    ///
    /// Note the exit-side list also contains the *other* arguments (upstream
    /// clones every param into both lists, only `group_type` differs), and
    /// `get_op_list()` emits the register-read op for any arg with a register
    /// regardless of `read_more()`; so the assertion is on the `ret` arg itself,
    /// not on the whole exit list.
    #[test]
    fn ret_argument_is_exit_only_with_no_ops() {
        let table = table();
        let openat = table.by_name("openat").unwrap();
        let ret = openat
            .exit_point_args
            .last()
            .expect("openat's exit args end with ret");
        assert_eq!(ret.name, "ret");
        assert_eq!(ret.reg_index, REG_ARM64_MAX, "ret reads no register");
        assert!(ret.get_op_list().is_empty(), "ret contributes no ops");
        assert_eq!(
            ret.point_type, EBPF_SYS_EXIT,
            "ret is exit-only (upstream uses EBPF_SYS_EXIT)"
        );

        // The enter side never contains `ret`: only the exit list does.
        assert!(
            openat.enter_point_args.iter().all(|a| a.name != "ret"),
            "ret must not be read on sys_enter"
        );
        assert_eq!(
            openat.enter_point_args.len(),
            4,
            "dirfd/pathname/flags/mode"
        );

        let enter = openat.enter_config().unwrap();
        assert!(
            !enter.op_key_list.is_empty(),
            "openat must read arguments on enter"
        );
        assert!(enter.op_count() as usize <= MAX_OP_COUNT_SYSCALL);
    }

    /// A point with several arguments must produce more ops than a point with
    /// one, and the enter/exit splits must both be present where `more: all`
    /// is used (e.g. `read`'s buffer is filled on exit).
    #[test]
    fn enter_and_exit_side_op_lists_differ_for_in_out_syscalls() {
        let table = table();
        // `read(fd, buf, count)`: buf is an exit-side buffer on aarch64
        // (`more: exit`), so the exit config must carry ops.
        let read = table.by_name("read").unwrap();
        assert!(
            !read.exit_config().unwrap().op_key_list.is_empty(),
            "read's buffer is read on sys_exit"
        );
        let write = table.by_name("write").unwrap();
        assert!(
            !write.enter_config().unwrap().op_key_list.is_empty(),
            "write's buffer is read on sys_enter"
        );
    }

    /// Every argument name in the table must be resolvable at parse time: this
    /// is what catches a JSON type the argtype registry does not know.
    ///
    /// No-argument syscalls (e.g. `vhangup`, whose only param is `ret`) have an
    /// empty enter list but always an exit list holding `ret`.
    #[test]
    fn every_parameter_of_every_point_parses() {
        init_argtypes();
        let table = SyscallPointTable::from_json_str(SYSCALL_CONFIG_AARCH64).unwrap();
        for point in table.points() {
            assert!(
                !point.exit_point_args.is_empty(),
                "{} has no exit-side `ret`",
                point.name
            );
            // `parse_arg_type` / `get_point_arg` panic on unknown registries, so
            // reaching here already proves resolution; assert the type index is
            // registered to be explicit.
            for arg in point.enter_point_args.iter().chain(&point.exit_point_args) {
                assert!(
                    crate::argtype::is_registered(arg.type_index),
                    "{}: type index {} is not registered",
                    point.name,
                    arg.type_index
                );
            }
        }
    }

    /// Op lists must fit the contract `point_args_t.op_key_list` width (256).
    #[test]
    fn every_point_fits_the_syscall_op_width() {
        let table = table();
        for point in table.points() {
            for config in [point.enter_config(), point.exit_config()] {
                let config = config.unwrap();
                assert!(
                    config.op_key_list.len() <= MAX_OP_COUNT_SYSCALL,
                    "{} overflows op_key_list",
                    point.name
                );
            }
        }
    }

    /// Round 11 / P1: `-w 'write[int,buf:128,int]s'` replaces the builtin
    /// `write` point's enter/exit argument lists with the user's three args
    /// and appends a synthetic `ret` to the exit list.
    #[test]
    fn update_syscall_point_binds_write_args() {
        init_argtypes();
        let mut table = table();
        let points = crate::config::point_parser::parse_hook_point(
            &["write[int,buf:128,int]s".to_string()],
            "/libtest.so",
            false,
        )
        .unwrap();
        assert_eq!(points.len(), 1);
        assert!(table.update_syscall_point(&points[0]).unwrap());

        let write = table.by_name("write").unwrap();
        let enter_names: Vec<&str> = write
            .enter_point_args
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(enter_names, ["arg_0", "arg_1", "arg_2"]);
        assert!(
            write
                .enter_point_args
                .iter()
                .all(|a| { a.point_type == EBPF_SYS_ENTER && a.group_type == EBPF_SYS_ENTER }),
            "bound enter args are ENTER/ENTER"
        );
        assert!(
            write.enter_point_args[1].is_buffer(),
            "buf:128 stays a buffer"
        );

        let exit_names: Vec<&str> = write
            .exit_point_args
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(exit_names, ["arg_0", "arg_1", "arg_2", "ret"]);
        let ret = write.exit_point_args.last().unwrap();
        assert_eq!(ret.reg_index, REG_ARM64_MAX, "ret reads no register");
        assert_eq!(ret.point_type, EBPF_SYS_EXIT, "ret is exit-only");
        assert!(ret.get_op_list().is_empty(), "ret contributes no ops");
    }

    /// Round 11 / P1: `-w 'write[int]ss'` binds with `exit_read`, so both
    /// clones of the argument get `point_type` ALL (Go's `]ss` branch is
    /// unreachable upstream; this crate checks `]ss` first, so it works).
    #[test]
    fn update_syscall_point_ss_sets_all_point_type() {
        init_argtypes();
        let mut table = table();
        let points = crate::config::point_parser::parse_hook_point(
            &["write[int]ss".to_string()],
            "/libtest.so",
            false,
        )
        .unwrap();
        assert!(table.update_syscall_point(&points[0]).unwrap());
        let write = table.by_name("write").unwrap();
        assert!(
            write
                .enter_point_args
                .iter()
                .chain(&write.exit_point_args)
                .filter(|a| a.name != "ret")
                .all(|a| a.point_type == EBPF_SYS_ALL),
            "exit_read binds both clones as ALL"
        );
    }

    /// Round 11 / P1: binding an unknown syscall name bails (Go panics with
    /// `unknown syscall name`) instead of silently hanging an ordinary uprobe.
    #[test]
    fn update_syscall_point_unknown_name_bails() {
        init_argtypes();
        let mut table = table();
        let points = crate::config::point_parser::parse_hook_point(
            &["nosuchsyscall[int]s".to_string()],
            "/libtest.so",
            false,
        )
        .unwrap();
        let err = table.update_syscall_point(&points[0]).unwrap_err();
        assert!(
            format!("{err:#}").contains("unknown syscall name:nosuchsyscall"),
            "{err:#}"
        );
    }

    /// Round 11 / P1: without the `]s` suffix nothing is bound and the table
    /// is untouched — the point stays in the uprobe list.
    #[test]
    fn update_syscall_point_unbound_returns_false_and_keeps_table() {
        init_argtypes();
        let mut table = table();
        let before: Vec<String> = table
            .by_name("write")
            .unwrap()
            .enter_point_args
            .iter()
            .map(|a| a.name.clone())
            .collect();
        let points = crate::config::point_parser::parse_hook_point(
            &["write[int,buf:128,int]".to_string()],
            "/libtest.so",
            false,
        )
        .unwrap();
        assert!(!table.update_syscall_point(&points[0]).unwrap());
        let after: Vec<String> = table
            .by_name("write")
            .unwrap()
            .enter_point_args
            .iter()
            .map(|a| a.name.clone())
            .collect();
        assert_eq!(before, after, "unbound point must not touch the table");
    }
}
