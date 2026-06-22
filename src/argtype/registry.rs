//! ArgType registry �?faithful port of `user/argtype/iargtype.go`.
//!
//! The registry maps type indices �?[`ArgType`] instances. Types are registered
//! during initialization ([`init_base_types`] + [`super::complex_types::pre_register`])
//! and dynamically during `-w` parsing ([`register_new`]).
//!
//! # Port notes
//!
//! Go uses an interface (`IArgType`) with embedded structs (`ARG_NUM`,
//! `ARG_PTR`, `ARG_BUFFER`, `ARG_STRUCT`, `ARG_ARRAY`). We use a single flat
//! struct with optional fields �?simpler, avoids trait objects, and Clone works
//! trivially (needed by `register_pre`).
//!
//! Go mutates the `ArgType` via the returned pointer after registration
//! (`at.AddOp(...)`, `at.SetSize(...)`). We provide [`with_type`] which takes a
//! closure that receives `&mut ArgType` under the registry lock.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::consts::{CONST_ARGTYPE_END, FORMAT_NUM};

/// The userspace argtype descriptor. Mirrors Go's `ArgType` + extension fields
/// from `ARG_NUM`/`ARG_PTR`/`ARG_ARRAY`. Fields that aren't relevant to all
/// kinds default to `None`/`0`/`false`.
#[derive(Debug, Clone)]
pub struct ArgType {
    /// Type name, e.g. "int", "buffer", "ptr_int".
    pub name: String,
    /// Base type category (`TYPE_*` from `consts.rs`).
    pub base_type: u32,
    /// Unique registry index (`POINTER`, `INT`, ..., or dynamic).
    pub type_index: u32,
    /// Parent type index (for RegisterPre/RegisterNew clones).
    pub parent_index: u32,
    /// `sizeof` equivalent. 0 for variable-size types (buffer/string).
    pub size: u32,
    /// Op indices that define how the BPF VM reads this arg.
    pub op_list: Vec<u32>,
    /// Alternate names (e.g. "buf" for "buffer").
    pub alias_names: Vec<String>,

    // ---- ARG_NUM extensions (format output �?Phase 3) ----
    pub format_type: u32,

    // ---- ARG_PTR extensions ----
    /// Whether the pointer's child is a number (adds SaveStruct(8)).
    pub is_num: bool,
    /// Child type index for pointer types.
    pub ptr_type_index: Option<u32>,

    // ---- ARG_ARRAY extensions ----
    pub array_len: u32,
    pub array_type_index: Option<u32>,

    // ---- Rendering flags (Phase 3) ----
    pub dump_hex: bool,
    pub color: bool,
}

impl ArgType {
    /// Create a new ArgType with the given identity fields, all else defaulted.
    pub fn new(name: &str, base_type: u32, type_index: u32, size: u32) -> Self {
        Self {
            name: name.to_string(),
            base_type,
            type_index,
            parent_index: 0,
            size,
            op_list: Vec::new(),
            alias_names: Vec::new(),
            format_type: FORMAT_NUM,
            is_num: false,
            ptr_type_index: None,
            array_len: 0,
            array_type_index: None,
            dump_hex: false,
            color: false,
        }
    }

    /// `AddOp(op_index)` �?append an op index to the op list.
    pub fn add_op(&mut self, op_index: u32) {
        self.op_list.push(op_index);
    }

    /// `AddOpList(p)` �?append all ops from another type.
    pub fn add_op_list_from(&mut self, other: &ArgType) {
        self.op_list.extend_from_slice(&other.op_list);
    }

    /// `CleanOpList()`.
    pub fn clean_op_list(&mut self) {
        self.op_list.clear();
    }

    /// `HasAliasName(name)`.
    pub fn has_alias_name(&self, name: &str) -> bool {
        self.alias_names.iter().any(|a| a == name)
    }

    /// `AddAlias(alias_name)`.
    pub fn add_alias(&mut self, alias_name: &str) {
        self.alias_names.push(alias_name.to_string());
    }
}

// ---- Global registry --------------------------------------------------------

/// Counter for dynamically-registered types. Starts at `CONST_ARGTYPE_END`.
static NEXT_TYPE_INDEX: OnceLock<Mutex<u32>> = OnceLock::new();

fn next_type_counter() -> &'static Mutex<u32> {
    NEXT_TYPE_INDEX.get_or_init(|| Mutex::new(CONST_ARGTYPE_END))
}

/// Allocate the next dynamic type index.
pub fn next_type_index() -> u32 {
    let mut c = next_type_counter()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    *c += 1;
    *c
}

/// The global registry: `type_index �?ArgType`.
fn registry() -> &'static Mutex<HashMap<u32, ArgType>> {
    static REG: OnceLock<Mutex<HashMap<u32, ArgType>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Lock the registry, recovering from poison (a prior panic leaves the data
/// intact, so we can safely continue �?important for parallel tests).
fn lock_reg() -> std::sync::MutexGuard<'static, HashMap<u32, ArgType>> {
    registry().lock().unwrap_or_else(|p| p.into_inner())
}

/// `Register(name, base, index, size)` �?register a base type with a fixed
/// index. Panics on duplicate index (matches Go).
pub fn register(name: &str, base_type: u32, type_index: u32, size: u32) -> u32 {
    let mut reg = lock_reg();
    if reg.contains_key(&type_index) {
        panic!(
            "duplicate register for ArgType index={type_index} (existing: {})",
            reg[&type_index].name
        );
    }
    let at = ArgType::new(name, base_type, type_index, size);
    reg.insert(type_index, at);
    type_index
}

/// `RegisterPre(name, type_index, parent_index)` �?clone the parent and assign
/// a new type_index/name/parent_index. Returns the new type_index.
pub fn register_pre(name: &str, type_index: u32, parent_index: u32) -> u32 {
    let mut reg = lock_reg();
    if reg.contains_key(&type_index) {
        panic!(
            "duplicate register for ArgType index={type_index} (existing: {})",
            reg[&type_index].name
        );
    }
    let parent = reg
        .get(&parent_index)
        .unwrap_or_else(|| panic!("RegisterPre: parent index {parent_index} not found"))
        .clone();
    let mut new_p = parent;
    new_p.name = name.to_string();
    new_p.type_index = type_index;
    new_p.parent_index = parent_index;
    // Aliases belong only to the canonical type, not derivatives. Without this,
    // get_arg_type_by_name would find clones (e.g. buffer_x2) when looking up
    // "buf" instead of the original BUFFER type.
    new_p.alias_names.clear();
    reg.insert(type_index, new_p);
    type_index
}

/// `RegisterNew(name, parent_index)` �?dynamically register a new type by
/// cloning the parent and assigning the next available type index.
pub fn register_new(name: &str, parent_index: u32) -> u32 {
    let idx = next_type_index();
    register_pre(name, idx, parent_index)
}

/// `GetArgType(type_index)` �?clone the ArgType at the given index. Panics if
/// not found (matches Go).
pub fn get_arg_type(type_index: u32) -> ArgType {
    let reg = lock_reg();
    reg.get(&type_index)
        .cloned()
        .unwrap_or_else(|| panic!("GetArgType for type_index:{type_index} failed"))
}

/// `GetArgTypeByName(name)` �?find by name or alias. Panics if not found.
pub fn get_arg_type_by_name(name: &str) -> ArgType {
    let reg = lock_reg();
    for at in reg.values() {
        if at.name == name || at.has_alias_name(name) {
            return at.clone();
        }
    }
    panic!("GetArgType failed, name={name} not exists");
}

/// Try to find by name, returning `None` instead of panicking.
pub fn try_get_arg_type_by_name(name: &str) -> Option<ArgType> {
    let reg = lock_reg();
    reg.values()
        .find(|at| at.name == name || at.has_alias_name(name))
        .cloned()
}

/// `RegisterAlias(alias_name, name)` �?add an alias to an existing type.
pub fn register_alias(alias_name: &str, name: &str) {
    let mut reg = lock_reg();
    // Find the type by name.
    let type_index = reg
        .values()
        .find(|at| at.name == name || at.has_alias_name(name))
        .map(|at| at.type_index)
        .unwrap_or_else(|| panic!("RegisterAlias: type '{name}' not found"));
    reg.get_mut(&type_index).unwrap().add_alias(alias_name);
}

/// `RegisterAliasType(type_index, alias_type_index)` �?make `type_index` point
/// to the same ArgType as `alias_type_index`.
pub fn register_alias_type(type_index: u32, alias_type_index: u32) {
    let mut reg = lock_reg();
    if reg.contains_key(&type_index) {
        panic!(
            "duplicate register for ArgType index={type_index} (existing: {})",
            reg[&type_index].name
        );
    }
    let alias = reg
        .get(&alias_type_index)
        .cloned()
        .unwrap_or_else(|| panic!("RegisterAliasType: alias {alias_type_index} not found"));
    reg.insert(type_index, alias);
}

/// `UpdateArgType(p)` �?replace the ArgType at its type_index.
pub fn update_arg_type(at: ArgType) {
    let mut reg = lock_reg();
    reg.insert(at.type_index, at);
}

/// Mutate the ArgType at `type_index` under the registry lock. This is the
/// primary way to configure a type after registration (add ops, set size, etc.).
pub fn with_type<F: FnOnce(&mut ArgType)>(type_index: u32, f: F) {
    let mut reg = lock_reg();
    let at = reg
        .get_mut(&type_index)
        .unwrap_or_else(|| panic!("with_type: index {type_index} not found"));
    f(at);
}

/// Get the total number of registered types.
pub fn registry_count() -> usize {
    lock_reg().len()
}

/// Check if a type index is registered.
pub fn is_registered(type_index: u32) -> bool {
    lock_reg().contains_key(&type_index)
}

#[cfg(test)]
mod tests {
    use super::super::consts::*;
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Generate a unique test index in the 100000+ range to avoid collisions
    /// with init_argtypes (0-57 + dynamic ~58+) or other parallel test runs.
    static TEST_IDX: AtomicU32 = AtomicU32::new(100_000);
    fn next_test_idx() -> u32 {
        TEST_IDX.fetch_add(1, Ordering::SeqCst)
    }

    #[test]
    fn register_and_get() {
        let idx = next_test_idx();
        register("test_num", TYPE_INT, idx, 4);
        let at = get_arg_type(idx);
        assert_eq!(at.name, "test_num");
        assert_eq!(at.base_type, TYPE_INT);
        assert_eq!(at.size, 4);
    }

    #[test]
    fn register_pre_clones_parent() {
        let parent = next_test_idx();
        let child = next_test_idx();
        register("parent", TYPE_STRUCT, parent, 8);
        with_type(parent, |at| at.add_op(0));
        register_pre("child", child, parent);
        let c = get_arg_type(child);
        assert_eq!(c.name, "child");
        assert_eq!(c.parent_index, parent);
        assert_eq!(c.op_list, vec![0]); // inherited from parent
    }

    #[test]
    fn register_new_assigns_dynamic_index() {
        let base = next_test_idx();
        register("base", TYPE_INT, base, 4);
        let idx = register_new("dyn_int", base);
        assert!(idx > CONST_ARGTYPE_END);
        let at = get_arg_type(idx);
        assert_eq!(at.name, "dyn_int");
        assert_eq!(at.parent_index, base);
    }

    #[test]
    fn with_type_mutates_in_place() {
        let idx = next_test_idx();
        register("mutable", TYPE_STRUCT, idx, 0);
        with_type(idx, |at| {
            at.size = 42;
            at.add_op(5);
            at.add_op(10);
        });
        let at = get_arg_type(idx);
        assert_eq!(at.size, 42);
        assert_eq!(at.op_list, vec![5, 10]);
    }

    #[test]
    fn alias_lookup_works() {
        let idx = next_test_idx();
        register("base_type", TYPE_BUFFER, idx, 0);
        register_alias("bt", "base_type");
        let at = get_arg_type_by_name("bt");
        assert_eq!(at.type_index, idx);
    }

    #[test]
    #[should_panic(expected = "not_exists")]
    fn get_by_name_panics_on_missing() {
        let _ = get_arg_type_by_name("not_exists");
    }
}
