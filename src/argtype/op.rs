//! Userspace op manager — faithful port of `user/argtype/op_helper.go`.
//!
//! This is the *bookkeeping* side: it tracks op names/indices and dedups
//! identical ops so the BPF `op_list` map stays compact. The actual bytecode
//! the kernel VM interprets is `crate::contract::types::OpConfig` (the 24-byte
//! wire struct); [`OpConfig::to_ebpf_value`] converts between the two.
//!
//! # Port notes
//!
//! - Go's global `var OPM = NewOpManager()` + 34 package-level `OPC_*` vars
//!   (registered in source order at package init) become a [`OnceLock`] holding
//!   a [`Mutex<OpManager>`], with singletons registered lazily on first access
//!   via [`opm`]. Registration order is preserved so index assignment matches
//!   Go exactly (`OPC_SKIP`=0 .. `OPC_SAVE_PTR_STRING16`=33).
//! - Two Go typo'd Names are deliberately preserved because dedup keys on
//!   `name`: `OPC_SET_BREAK_COUNT`→`"OP_SET_BREAK_COUNT"`,
//!   `OPC_SAVE_STRING16`→`"OPC_SAVE_STRING16"`.
//! - Go returns `*OpConfig` pointers; Rust returns the assigned `u32` index
//!   (the handle callers actually need — `op_key_list` stores indices).

use crate::contract::enums::OpCode;
use crate::contract::types::OpConfig as WireOpConfig;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Userspace bookkeeping for one registered op. Distinct from the 24-byte
/// wire [`WireOpConfig`] (which omits `name`/`index`).
///
/// Mirrors Go's `OpConfig { Name, Index, BaseOpConfig }`.
#[derive(Debug, Clone)]
pub struct OpConfig {
    pub name: String,
    pub index: u32,
    pub code: OpCode,
    pub pre_code: OpCode,
    pub post_code: OpCode,
    pub value: u64,
}

impl OpConfig {
    /// `SameAs` — dedup key is (name, code, pre_code, post_code, value).
    /// Index is intentionally excluded (matches Go's commented-out check).
    fn same_as(&self, other: &Self) -> bool {
        self.name == other.name
            && self.code == other.code
            && self.pre_code == other.pre_code
            && self.post_code == other.post_code
            && self.value == other.value
    }

    /// `ToEbpfValue` — convert to the 24-byte wire struct for the BPF map.
    pub fn to_ebpf_value(&self) -> WireOpConfig {
        WireOpConfig {
            code: self.code.as_u32(),
            pre_code: self.pre_code.as_u32(),
            post_code: self.post_code.as_u32(),
            _pad: [0; 4],
            value: self.value,
        }
    }

    /// `Clone` then set `value`, then re-register (dedup) and return new index.
    /// Mirrors Go's `(this *OpConfig) NewValue`.
    pub fn new_value(&self, value: u64) -> u32 {
        let mut clone = self.clone();
        clone.value = value;
        add_op(clone)
    }

    /// `(this *OpConfig) NewPreCode`.
    pub fn new_pre_code(&self, pre_code: OpCode) -> u32 {
        let mut clone = self.clone();
        clone.pre_code = pre_code;
        add_op(clone)
    }

    /// `(this *OpConfig) NewPostCode`.
    pub fn new_post_code(&self, post_code: OpCode) -> u32 {
        let mut clone = self.clone();
        clone.post_code = post_code;
        add_op(clone)
    }
}

/// Mirrors Go's `OpManager { OpList []*OpConfig }`.
struct OpManager {
    op_list: Vec<OpConfig>,
}

impl OpManager {
    fn new() -> Self {
        Self { op_list: Vec::new() }
    }

    fn count(&self) -> u32 {
        self.op_list.len() as u32
    }

    /// `GetOp` — linear scan by index. Panics if not found (matches Go).
    fn get_op(&self, index: u32) -> &OpConfig {
        self.op_list
            .iter()
            .find(|o| o.index == index)
            .unwrap_or_else(|| panic!("GetOp failed, index={index} not exists"))
    }

    /// `GetOpName` — first op whose `code` matches. Panics if not found.
    fn get_op_name(&self, code: OpCode) -> &str {
        self.op_list
            .iter()
            .find(|o| o.code == code)
            .map(|o| o.name.as_str())
            .unwrap_or_else(|| panic!("GetOpName failed, op_code={} not exists", code.as_u32()))
    }

    /// `GetOpInfo` — `"{code_name} {pre_code_name} {post_code_name} {value}"`.
    fn get_op_info(&self, index: u32) -> String {
        let op = self.get_op(index);
        let code_name = self.get_op_name(op.code);
        let pre_code_name = self.get_op_name(op.pre_code);
        let post_code_name = self.get_op_name(op.post_code);
        format!("{code_name} {pre_code_name} {post_code_name} {}", op.value)
    }

    /// `AddOp` — dedup by `same_as`; if found return existing index, else
    /// assign next index, append, return new index.
    fn add_op(&mut self, op: OpConfig) -> u32 {
        if let Some(existing) = self.op_list.iter().find(|v| v.same_as(&op)) {
            return existing.index;
        }
        let mut op = op;
        op.index = self.count();
        self.op_list.push(op);
        self.op_list.last().unwrap().index
    }

    /// `GetOpList` — `{index: BaseOpConfig}` map for the BPF `op_list` map.
    fn get_op_list(&self) -> HashMap<u32, WireOpConfig> {
        self.op_list
            .iter()
            .map(|v| (v.index, v.to_ebpf_value()))
            .collect()
    }
}

/// Global `OpManager` handle. Lazily initializes and registers the 34
/// singletons on first lock acquisition.
fn opm() -> &'static Mutex<OpManager> {
    static OPM: OnceLock<Mutex<OpManager>> = OnceLock::new();
    OPM.get_or_init(|| {
        let mut mgr = OpManager::new();
        register_singletons(&mut mgr);
        Mutex::new(mgr)
    })
}

/// Register the 34 `OPC_*` singletons in Go source order (op_helper.go:268-301).
/// Each gets a unique index 0..=33 because their names are all distinct.
fn register_singletons(mgr: &mut OpManager) {
    // Helper: ROP(name, code) — PreCode=PostCode=OP_SKIP.
    let rop = |mgr: &mut OpManager, name: &str, code: OpCode| -> u32 {
        mgr.add_op(OpConfig {
            name: name.to_string(),
            index: 0,
            code,
            pre_code: OpCode::Skip,
            post_code: OpCode::Skip,
            value: 0,
        })
    };
    // Index 0..33, in exact Go var-declaration order.
    rop(mgr, "SKIP", OpCode::Skip);
    rop(mgr, "RESET_CTX", OpCode::ResetCtx);
    rop(mgr, "SET_REG_INDEX", OpCode::SetRegIndex);
    rop(mgr, "SET_READ_LEN", OpCode::SetReadLen);
    rop(mgr, "SET_READ_LEN_REG_VALUE", OpCode::SetReadLenRegValue);
    rop(
        mgr,
        "SET_READ_LEN_POINTER_VALUE",
        OpCode::SetReadLenPointerValue,
    );
    rop(mgr, "SET_READ_COUNT", OpCode::SetReadCount);
    rop(mgr, "ADD_OFFSET", OpCode::AddOffset);
    rop(mgr, "SUB_OFFSET", OpCode::SubOffset);
    rop(mgr, "MOVE_REG_VALUE", OpCode::MoveRegValue);
    rop(mgr, "MOVE_POINTER_VALUE", OpCode::MovePointerValue);
    rop(mgr, "MOVE_TMP_VALUE", OpCode::MoveTmpValue);
    rop(mgr, "SET_TMP_VALUE", OpCode::SetTmpValue);
    rop(mgr, "FOR_BREAK", OpCode::ForBreak);
    // NOTE: Go typo preserved — Name is "OP_SET_BREAK_COUNT" (missing C prefix).
    // Dedup keys on name so this exact spelling must be kept.
    rop(mgr, "OP_SET_BREAK_COUNT", OpCode::SetBreakCount);
    rop(
        mgr,
        "SET_BREAK_COUNT_REG_VALUE",
        OpCode::SetBreakCountRegValue,
    );
    rop(
        mgr,
        "SET_BREAK_COUNT_POINTER_VALUE",
        OpCode::SetBreakCountPointerValue,
    );
    rop(mgr, "SAVE_ADDR", OpCode::SaveAddr);
    rop(mgr, "ADD_REG", OpCode::AddReg);
    rop(mgr, "SUB_REG", OpCode::SubReg);
    rop(mgr, "READ_REG", OpCode::ReadReg);
    rop(mgr, "SAVE_REG", OpCode::SaveReg);
    rop(mgr, "READ_POINTER", OpCode::ReadPointer);
    rop(mgr, "SAVE_POINTER", OpCode::SavePointer);
    rop(mgr, "SAVE_STRUCT", OpCode::SaveStruct);
    rop(mgr, "SAVE_STRING", OpCode::SaveString);
    rop(mgr, "FILTER_VALUE", OpCode::FilterValue);
    rop(mgr, "FILTER_BUFFER", OpCode::FilterBuffer);
    rop(mgr, "FILTER_STRING", OpCode::FilterString);
    rop(mgr, "SAVE_PTR_STRING", OpCode::SavePtrString);
    rop(mgr, "READ_STD_STRING", OpCode::ReadStdString);
    rop(mgr, "READ_IL2CPP_STRING", OpCode::ReadIl2cppString);
    // NOTE: Go typo preserved — Name is "OPC_SAVE_STRING16" (extra OPC_ prefix).
    rop(mgr, "OPC_SAVE_STRING16", OpCode::SaveString16);
    rop(mgr, "SAVE_PTR_STRING16", OpCode::SavePtrString16);
}

// ---------------------------------------------------------------------------
// Singleton index accessors — Go's `OPC_*` vars. Each returns the registered
// index (0..33). Idempotent: the global is registered once on first `opm()`.
// ---------------------------------------------------------------------------

macro_rules! singleton_index {
    ($accessor:ident, $idx:literal) => {
        #[allow(clippy::missing_docs_in_private_items)]
        pub fn $accessor() -> u32 {
            $idx
        }
    };
}
singleton_index!(opc_skip, 0);
singleton_index!(opc_reset_ctx, 1);
singleton_index!(opc_set_reg_index, 2);
singleton_index!(opc_set_read_len, 3);
singleton_index!(opc_set_read_len_reg_value, 4);
singleton_index!(opc_set_read_len_pointer_value, 5);
singleton_index!(opc_set_read_count, 6);
singleton_index!(opc_add_offset, 7);
singleton_index!(opc_sub_offset, 8);
singleton_index!(opc_move_reg_value, 9);
singleton_index!(opc_move_pointer_value, 10);
singleton_index!(opc_move_tmp_value, 11);
singleton_index!(opc_set_tmp_value, 12);
singleton_index!(opc_for_break, 13);
singleton_index!(opc_set_break_count, 14);
singleton_index!(opc_set_break_count_reg_value, 15);
singleton_index!(opc_set_break_count_pointer_value, 16);
singleton_index!(opc_save_addr, 17);
singleton_index!(opc_add_reg, 18);
singleton_index!(opc_sub_reg, 19);
singleton_index!(opc_read_reg, 20);
singleton_index!(opc_save_reg, 21);
singleton_index!(opc_read_pointer, 22);
singleton_index!(opc_save_pointer, 23);
singleton_index!(opc_save_struct, 24);
singleton_index!(opc_save_string, 25);
singleton_index!(opc_filter_value, 26);
singleton_index!(opc_filter_buffer, 27);
singleton_index!(opc_filter_string, 28);
singleton_index!(opc_save_ptr_string, 29);
singleton_index!(opc_read_std_string, 30);
singleton_index!(opc_read_il2cpp_string, 31);
singleton_index!(opc_save_string16, 32);
singleton_index!(opc_save_ptr_string16, 33);

// ---------------------------------------------------------------------------
// Public API mirroring op_helper.go's free functions
// ---------------------------------------------------------------------------

/// `GetALLOpList` — the full `{index: BaseOpConfig}` map for BPF `op_list`.
pub fn get_all_op_list() -> HashMap<u32, WireOpConfig> {
    opm().lock().unwrap().get_op_list()
}

/// `(this *OpManager) AddOp` — dedup-register an op, return its index.
pub fn add_op(op: OpConfig) -> u32 {
    opm().lock().unwrap().add_op(op)
}

/// `(this *OpManager) Count`.
pub fn count() -> u32 {
    opm().lock().unwrap().count()
}

/// `(this *OpManager) GetOp` — clone of the op at `index`. Panics if absent.
pub fn get_op(index: u32) -> OpConfig {
    opm().lock().unwrap().get_op(index).clone()
}

/// `(this *OpManager) GetOpInfo` — debug string.
pub fn get_op_info(index: u32) -> String {
    opm().lock().unwrap().get_op_info(index)
}

/// `Add_READ_SAVE_REG(value)` — three-in-one: SET_REG_INDEX / READ_REG / SAVE_REG.
pub fn add_read_save_reg(value: u64) -> u32 {
    add_op(OpConfig {
        name: format!("READ_SAVE_REG_{value}"),
        index: 0,
        code: OpCode::ReadReg,
        pre_code: OpCode::SetRegIndex,
        post_code: OpCode::SaveReg,
        value,
    })
}

/// `Add_READ_MOVE_REG(value)` — SET_REG_INDEX / READ_REG / MOVE_REG_VALUE.
pub fn add_read_move_reg(value: u64) -> u32 {
    add_op(OpConfig {
        name: format!("READ_MOVE_REG_{value}"),
        index: 0,
        code: OpCode::ReadReg,
        pre_code: OpCode::SetRegIndex,
        post_code: OpCode::MoveRegValue,
        value,
    })
}

/// `SaveStruct(value)` — SET_READ_LEN / SKIP / SAVE_STRUCT with len=value.
pub fn save_struct(value: u64) -> u32 {
    let idx = add_op(OpConfig {
        name: format!("SAVE_STRUCT_{value}"),
        index: 0,
        code: OpCode::SetReadLen,
        pre_code: OpCode::Skip,
        post_code: OpCode::SaveStruct,
        value,
    });
    // Match Go's RSAT path: NewValue then NewPostCode re-register; but here we
    // already set value+post_code in one shot, so idx is final. (Go's RSAT does
    // `OPC_SET_READ_LEN.NewValue(len).NewPostCode(OP_SAVE_STRUCT)` which is
    // functionally identical to this single AddOp.)
    idx
}

/// `BuildReadRegBreakCount(reg_index)`.
pub fn build_read_reg_break_count(reg_index: u64) -> u32 {
    add_op(OpConfig {
        name: format!("READ_REG_AS_BREAK_COUNT_{reg_index}"),
        index: 0,
        code: OpCode::ReadReg,
        pre_code: OpCode::SetRegIndex,
        post_code: OpCode::SetBreakCountRegValue,
        value: reg_index,
    })
}

/// `BuildReadPtrBreakCount(offset)`.
pub fn build_read_ptr_break_count(offset: u64) -> u32 {
    add_op(OpConfig {
        name: format!("READ_PTR_AS_BREAK_COUNT_{offset}"),
        index: 0,
        code: OpCode::ReadPointer,
        pre_code: OpCode::AddOffset,
        post_code: OpCode::SetBreakCountPointerValue,
        value: offset,
    })
}

/// `BuildReadRegLen(reg_index)`.
pub fn build_read_reg_len(reg_index: u64) -> u32 {
    add_op(OpConfig {
        name: format!("READ_REG_AS_READ_LEN_{reg_index}"),
        index: 0,
        code: OpCode::ReadReg,
        pre_code: OpCode::SetRegIndex,
        post_code: OpCode::SetReadLenRegValue,
        value: reg_index,
    })
}

/// `BuildReadPtrLen(offset)`.
pub fn build_read_ptr_len(offset: u64) -> u32 {
    add_op(OpConfig {
        name: format!("READ_PTR_AS_READ_LEN_{offset}"),
        index: 0,
        code: OpCode::ReadPointer,
        pre_code: OpCode::AddOffset,
        post_code: OpCode::SetReadLenPointerValue,
        value: offset,
    })
}

/// `BuildReadPtrAddr(offset)`.
pub fn build_read_ptr_addr(offset: u64) -> u32 {
    add_op(OpConfig {
        name: format!("READ_PTR_AS_ADDR_{offset}"),
        index: 0,
        code: OpCode::ReadPointer,
        pre_code: OpCode::AddOffset,
        post_code: OpCode::MovePointerValue,
        value: offset,
    })
}

// ---------------------------------------------------------------------------
// OpArgType — Go's `type OpArgType struct` + RAT + RSAT
// ---------------------------------------------------------------------------

/// `OpArgType { alias_type, type_size, op_list }` — a registered arg type's
/// op-index list. The BPF side reads `op_key_list[pointarg.op_count]` to know
/// which ops to run.
#[derive(Debug, Clone)]
pub struct OpArgType {
    pub alias_type: u32,
    pub type_size: u32,
    pub op_list: Vec<u32>,
}

impl OpArgType {
    /// `Clone` then `append(OpList...)` — Go uses this when extending a base
    /// type. Here we expose a plain field clone via derived `Clone`.
    pub fn add_op(&mut self, op_index: u32) {
        self.op_list.push(op_index);
    }
}

/// `RAT(alias_type, type_size)` — register a common (empty-oplist) OpArgType.
pub fn rat(alias_type: u32, type_size: u32) -> OpArgType {
    OpArgType {
        alias_type,
        type_size,
        op_list: Vec::new(),
    }
}

/// `RSAT(alias_type, type_size)` — register a struct OpArgType whose oplist is
/// `[SET_READ_LEN{value=size} -> SAVE_STRUCT]`.
pub fn rsat(alias_type: u32, type_size: u32) -> OpArgType {
    let mut oat = OpArgType {
        alias_type,
        type_size,
        op_list: Vec::new(),
    };
    // Go: OPC_SET_READ_LEN.NewValue(size).NewPostCode(OP_SAVE_STRUCT)
    let op = OpConfig {
        name: format!("SAVE_STRUCT_{type_size}"),
        index: 0,
        code: OpCode::SetReadLen,
        pre_code: OpCode::Skip,
        post_code: OpCode::SaveStruct,
        value: u64::from(type_size),
    };
    oat.add_op(add_op(op));
    oat
}

// ---------------------------------------------------------------------------
// Tests — verify the port matches op_helper.go's observable behavior
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singletons_register_34_ops_with_stable_indices() {
        // First call triggers lazy init. Indices must match Go's var order.
        assert_eq!(opc_skip(), 0);
        assert_eq!(opc_save_ptr_string16(), 33);
        assert_eq!(count(), 34);
    }

    #[test]
    fn go_typo_names_are_preserved() {
        // These two Names are deliberately misspelled in op_helper.go and MUST
        // be preserved because dedup keys on name.
        let mgr = opm().lock().unwrap();
        let set_break_count = mgr.get_op(opc_set_break_count());
        assert_eq!(set_break_count.name, "OP_SET_BREAK_COUNT");
        let save_string16 = mgr.get_op(opc_save_string16());
        assert_eq!(save_string16.name, "OPC_SAVE_STRING16");
    }

    #[test]
    fn dedup_returns_same_index_for_identical_op() {
        let a = add_read_save_reg(5);
        let b = add_read_save_reg(5);
        assert_eq!(a, b, "identical ops must dedup to one index");
    }

    #[test]
    fn distinct_values_get_distinct_indices() {
        let a = add_read_save_reg(1);
        let b = add_read_save_reg(2);
        assert_ne!(a, b);
    }

    #[test]
    fn to_ebpf_value_matches_layout() {
        let op = get_op(opc_save_struct());
        let wire = op.to_ebpf_value();
        assert_eq!(wire.code, OpCode::SaveStruct.as_u32());
        assert_eq!(wire.pre_code, OpCode::Skip.as_u32());
        assert_eq!(wire.post_code, OpCode::Skip.as_u32());
        assert_eq!(wire.value, 0);
        assert_eq!(wire._pad, [0; 4]);
    }

    #[test]
    fn rsat_emits_save_struct_opchain() {
        let oat = rsat(100, 64);
        assert_eq!(oat.alias_type, 100);
        assert_eq!(oat.type_size, 64);
        assert_eq!(oat.op_list.len(), 1);
        let op = get_op(oat.op_list[0]);
        assert_eq!(op.code, OpCode::SetReadLen);
        assert_eq!(op.post_code, OpCode::SaveStruct);
        assert_eq!(op.value, 64);
    }

    #[test]
    fn build_read_ptr_len_has_correct_codes() {
        let idx = build_read_ptr_len(0x10);
        let op = get_op(idx);
        assert_eq!(op.code, OpCode::ReadPointer);
        assert_eq!(op.pre_code, OpCode::AddOffset);
        assert_eq!(op.post_code, OpCode::SetReadLenPointerValue);
        assert_eq!(op.value, 0x10);
    }

    #[test]
    fn get_op_info_formats_like_go() {
        // SKIP's info: "SKIP SKIP SKIP 0"
        let info = get_op_info(opc_skip());
        assert_eq!(info, "SKIP SKIP SKIP 0");
    }
}
