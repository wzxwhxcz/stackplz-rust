//! ArgType registry — faithful port of `user/argtype/iargtype.go`.
//!
//! The registry maps type indices → [`ArgType`] instances. Types are registered
//! during initialization ([`init_base_types`] + [`super::complex_types::pre_register`])
//! and dynamically during `-w` parsing ([`register_new`]).
//!
//! # Port notes
//!
//! Go uses an interface (`IArgType`) with embedded structs (`ARG_NUM`,
//! `ARG_PTR`, `ARG_BUFFER`, `ARG_STRUCT`, `ARG_ARRAY`). We use a single flat
//! struct with optional fields — simpler, avoids trait objects, and Clone works
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

    // ---- ARG_NUM extensions (format output — Phase 3) ----
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

    /// `AddOp(op_index)` — append an op index to the op list.
    pub fn add_op(&mut self, op_index: u32) {
        self.op_list.push(op_index);
    }

    /// `AddOpList(p)` — append all ops from another type.
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
    let mut c = next_type_counter().lock().unwrap();
    *c += 1;
    *c
}

/// The global registry: `type_index → ArgType`.
fn registry() -> &'static Mutex<HashMap<u32, ArgType>> {
    static REG: OnceLock<Mutex<HashMap<u32, ArgType>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `Register(name, base, index, size)` — register a base type with a fixed
/// index. Panics on duplicate index (matches Go).
pub fn register(name: &str, base_type: u32, type_index: u32, size: u32) -> u32 {
    let mut reg = registry().lock().unwrap();
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

/// `RegisterPre(name, type_index, parent_index)` — clone the parent and assign
/// a new type_index/name/parent_index. Returns the new type_index.
pub fn register_pre(name: &str, type_index: u32, parent_index: u32) -> u32 {
    let mut reg = registry().lock().unwrap();
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
    reg.insert(type_index, new_p);
    type_index
}

/// `RegisterNew(name, parent_index)` — dynamically register a new type by
/// cloning the parent and assigning the next available type index.
pub fn register_new(name: &str, parent_index: u32) -> u32 {
    let idx = next_type_index();
    register_pre(name, idx, parent_index)
}

/// `GetArgType(type_index)` — clone the ArgType at the given index. Panics if
/// not found (matches Go).
pub fn get_arg_type(type_index: u32) -> ArgType {
    let reg = registry().lock().unwrap();
    reg.get(&type_index)
        .cloned()
        .unwrap_or_else(|| panic!("GetArgType for type_index:{type_index} failed"))
}

/// `GetArgTypeByName(name)` — find by name or alias. Panics if not found.
pub fn get_arg_type_by_name(name: &str) -> ArgType {
    let reg = registry().lock().unwrap();
    for at in reg.values() {
        if at.name == name || at.has_alias_name(name) {
            return at.clone();
        }
    }
    panic!("GetArgType failed, name={name} not exists");
}

/// Try to find by name, returning `None` instead of panicking.
pub fn try_get_arg_type_by_name(name: &str) -> Option<ArgType> {
    let reg = registry().lock().unwrap();
    reg.values()
        .find(|at| at.name == name || at.has_alias_name(name))
        .cloned()
}

/// `RegisterAlias(alias_name, name)` — add an alias to an existing type.
pub fn register_alias(alias_name: &str, name: &str) {
    let mut reg = registry().lock().unwrap();
    // Find the type by name.
    let type_index = reg
        .values()
        .find(|at| at.name == name || at.has_alias_name(name))
        .map(|at| at.type_index)
        .unwrap_or_else(|| panic!("RegisterAlias: type '{name}' not found"));
    reg.get_mut(&type_index).unwrap().add_alias(alias_name);
}

/// `RegisterAliasType(type_index, alias_type_index)` — make `type_index` point
/// to the same ArgType as `alias_type_index`.
pub fn register_alias_type(type_index: u32, alias_type_index: u32) {
    let mut reg = registry().lock().unwrap();
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

/// `UpdateArgType(p)` — replace the ArgType at its type_index.
pub fn update_arg_type(at: ArgType) {
    let mut reg = registry().lock().unwrap();
    reg.insert(at.type_index, at);
}

/// Mutate the ArgType at `type_index` under the registry lock. This is the
/// primary way to configure a type after registration (add ops, set size, etc.).
pub fn with_type<F: FnOnce(&mut ArgType)>(type_index: u32, f: F) {
    let mut reg = registry().lock().unwrap();
    let at = reg
        .get_mut(&type_index)
        .unwrap_or_else(|| panic!("with_type: index {type_index} not found"));
    f(at);
}

/// Get the total number of registered types.
pub fn registry_count() -> usize {
    registry().lock().unwrap().len()
}

/// Check if a type index is registered.
pub fn is_registered(type_index: u32) -> bool {
    registry().lock().unwrap().contains_key(&type_index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::consts::*;

    #[test]
    fn register_and_get() {
        register("test_num", TYPE_INT, 9999, 4);
        let at = get_arg_type(9999);
        assert_eq!(at.name, "test_num");
        assert_eq!(at.base_type, TYPE_INT);
        assert_eq!(at.size, 4);
    }

    #[test]
    fn register_pre_clones_parent() {
        register("parent", TYPE_STRUCT, 8001, 8);
        with_type(8001, |at| at.add_op(0));
        register_pre("child", 8002, 8001);
        let child = get_arg_type(8002);
        assert_eq!(child.name, "child");
        assert_eq!(child.parent_index, 8001);
        assert_eq!(child.op_list, vec![0]); // inherited from parent
    }

    #[test]
    fn register_new_assigns_dynamic_index() {
        register("base", TYPE_INT, 7001, 4);
        let idx = register_new("dyn_int", 7001);
        assert!(idx > CONST_ARGTYPE_END);
        let at = get_arg_type(idx);
        assert_eq!(at.name, "dyn_int");
        assert_eq!(at.parent_index, 7001);
    }

    #[test]
    fn with_type_mutates_in_place() {
        register("mutable", TYPE_STRUCT, 6001, 0);
        with_type(6001, |at| {
            at.size = 42;
            at.add_op(5);
            at.add_op(10);
        });
        let at = get_arg_type(6001);
        assert_eq!(at.size, 42);
        assert_eq!(at.op_list, vec![5, 10]);
    }

    #[test]
    fn alias_lookup_works() {
        register("base_type", TYPE_BUFFER, 5001, 0);
        register_alias("bt", "base_type");
        let at = get_arg_type_by_name("bt");
        assert_eq!(at.type_index, 5001);
    }

    #[test]
    #[should_panic(expected = "not_exists")]
    fn get_by_name_panics_on_missing() {
        let _ = get_arg_type_by_name("not_exists");
    }
}
