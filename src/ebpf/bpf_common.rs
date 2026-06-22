//! eBPF loading glue. Replaces `ehids/ebpfmanager` + the embedded-bytecode
//! loading in `user/module/{probe_stack,tracepoint_raw_syscalls}.go`.
//!
//! Embedded bytecode: `stack.o` / `raw_syscalls.o` compiled from
//! `ebpf/{stack,raw_syscalls}.c` (see `build.rs`), included via `include_bytes!`
//! to mirror go-bindata embedding.
//!
//! The libbpf-rs API surface used here is gated to Linux (it won't compile on
//! other targets). Platform-independent helpers (symbol resolution, embedded
//! bytecode access) are always available so unit tests can run anywhere.

use anyhow::Result;

/// Embedded uprobe eBPF object. Mirrors `assets.Asset("user/bytecode/stack.o")`.
/// Compiled from `ebpf/stack.c` under `-D__MODULE_STACK`.
#[cfg(feature = "embedded_bpf")]
pub const STACK_OBJ: &[u8] = include_bytes!("../../ebpf/bpf/stack.o");
/// Embedded syscall eBPF object. Compiled from `ebpf/syscall.c` under
/// `-D__MODULE_SYSCALL` (dev branch renamed `raw_syscalls.c` -> `syscall.c`).
#[cfg(feature = "embedded_bpf")]
pub const SYSCALL_OBJ: &[u8] = include_bytes!("../../ebpf/bpf/syscall.o");
/// Embedded perf_mmap eBPF object (stub in dev; compiled from
/// `ebpf/perf_mmap.c`).
#[cfg(feature = "embedded_bpf")]
pub const PERF_MMAP_OBJ: &[u8] = include_bytes!("../../ebpf/bpf/perf_mmap.o");

// When the .o files aren't built yet, expose placeholder slices so the code
// compiles without `embedded_bpf` (the real loader is Linux-only anyway).
#[cfg(not(feature = "embedded_bpf"))]
pub const STACK_OBJ: &[u8] = b"<stack.o not built; run the ebpf build step>";
#[cfg(not(feature = "embedded_bpf"))]
pub const SYSCALL_OBJ: &[u8] = b"<syscall.o not built; run the ebpf build step>";
#[cfg(not(feature = "embedded_bpf"))]
pub const PERF_MMAP_OBJ: &[u8] = b"<perf_mmap.o not built; run the ebpf build step>";

/// Resolve a dynamic symbol name to its file offset inside an ELF shared
/// object. Replaces what `ebpfmanager`'s `AttachToFuncName` did internally
/// (walking `.dynsym` / `.dynstr`).
///
/// Returns the symbol's `st_value` (the file offset / virtual address for a
/// shared object). The caller passes this as the uprobe offset.
///
/// Note: `GNU_IFUNC` resolvers and symbol aliases (e.g. `strchr` vs
/// `__strchr_aarch64`) are NOT special-cased; per the README the user must
/// supply the actually-resolved symbol name. We return the first matching
/// global symbol.
pub fn resolve_symbol_offset(elf_bytes: &[u8], symbol: &str) -> Result<u64> {
    use object::{Object, ObjectSymbol};
    // `object::Error` does not implement `std::error::Error`, so it can't be
    // converted by `?` directly; wrap it explicitly.
    let obj = object::File::parse(elf_bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse ELF: {}", e))?;
    for sym in obj.symbols().chain(obj.dynamic_symbols()) {
        if sym
            .name_bytes()
            .map(|n| n == symbol.as_bytes())
            .unwrap_or(false)
        {
            return Ok(sym.address());
        }
    }
    Err(anyhow::anyhow!("symbol '{}' not found in ELF", symbol))
}

/// ARM64 register count sampled by the perf layer. Mirrors Go's
/// `RegMask = (1 << 33) - 1` (`imodule.go:164`): all 33 arm64 registers
/// (x0..x29 + lr + sp + pc).
pub const ARM64_REG_COUNT: u32 = 33;
/// Mask covering all 33 arm64 registers for `perf_event_attr.sample_regs_user`.
pub const ARM64_REG_MASK: u64 = (1u64 << ARM64_REG_COUNT) - 1;
/// Per-sample stack size captured by the perf layer. Mirrors Go's
/// `Sample_stack_user: 8192` (`imodule.go:180`).
pub const SAMPLE_STACK_USER: u64 = 8192;

// ---- Linux-only libbpf-rs glue -------------------------------------------

#[cfg(target_os = "linux")]
pub mod linux {
    //! libbpf-rs based loader. Implements the same flow as
    //! `MStackProbe.start()` / `MRawSyscallsTracepoint.start()`:
    //!   1. open the embedded object from memory
    //!   2. (load + attach happen in the module layer, which owns probe config)
    //!   3. write the `filter_map` value at key 0
    //!   4. expose the `*_events` perf-event-array map to the reader loop

    use anyhow::{anyhow, Result};
    use libbpf_rs::{Map, MapFlags, Object, ObjectBuilder};

    /// Open an embedded eBPF object from memory (no temp file needed).
    /// Mirrors `bpfManager.InitWithOptions(bytes.NewReader(byteBuf), ...)`.
    pub fn open_object(bytes: &[u8]) -> Result<Object> {
        let mut builder = ObjectBuilder::default();
        // Name is informational only; ignore the Result (name is optional).
        let _ = builder.name("stackplz");
        let open = builder.open_memory(bytes)?;
        Ok(open.load()?)
    }

    /// Write a `#[repr(C)]` filter value into the `filter_map` HASH map at key 0.
    /// Mirrors `filterMap.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter), ebpf.UpdateAny)`.
    pub fn write_filter_map<T: bytemuck::Pod>(obj: &Object, filter: &T) -> Result<()> {
        let map = obj
            .map("filter_map")
            .ok_or_else(|| anyhow!("cannot find filter_map"))?;
        let key = 0u32.to_ne_bytes();
        let value_bytes: &[u8] = bytemuck::bytes_of(filter);
        map.update(&key, value_bytes, MapFlags::ANY)?;
        Ok(())
    }

    /// Borrow the `*_events` PERF_EVENT_ARRAY map for the perf-reader loop.
    pub fn events_map<'a>(obj: &'a Object, name: &str) -> Result<&'a Map> {
        obj.map(name)
            .ok_or_else(|| anyhow!("cannot find map: {}", name))
    }

    /// Write a key/value pair into a HASH/ARRAY map by name.
    /// Mirrors Go's `bpf_map.Update(&key, value, ebpf.UpdateAny)`.
    pub fn write_map<K: bytemuck::Pod, V: bytemuck::Pod>(
        obj: &Object,
        map_name: &str,
        key: &K,
        value: &V,
    ) -> Result<()> {
        let map = obj
            .map(map_name)
            .ok_or_else(|| anyhow!("cannot find map: {map_name}"))?;
        let key_bytes = bytemuck::bytes_of(key);
        let val_bytes = bytemuck::bytes_of(value);
        map.update(key_bytes, val_bytes, MapFlags::ANY)?;
        Ok(())
    }

    /// Write a map entry with raw byte key/value (for maps with non-Pod shapes).
    pub fn write_map_raw(
        obj: &Object,
        map_name: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        let map = obj
            .map(map_name)
            .ok_or_else(|| anyhow!("cannot find map: {map_name}"))?;
        map.update(key, value, MapFlags::ANY)?;
        Ok(())
    }

    /// Write the entire `op_list` map from the argtype subsystem.
    /// Mirrors Go's `update_op_list()` in `stack.go:341-357`.
    pub fn write_op_list(obj: &Object) -> Result<()> {
        let map = obj
            .map("op_list")
            .ok_or_else(|| anyhow!("cannot find op_list map"))?;
        for (op_key, op_config) in crate::argtype::get_all_op_list() {
            let key_bytes = op_key.to_ne_bytes();
            let val_bytes = bytemuck::bytes_of(&op_config);
            map.update(&key_bytes, val_bytes, MapFlags::ANY)?;
        }
        Ok(())
    }

    /// Write the `uprobe_point_args` map from a list of `(index, point_args)`.
    /// Each point's op_list is flattened into the `op_key_list` array.
    /// Mirrors Go's `update_stack_config()` in `stack.go:359-379`.
    pub fn write_uprobe_point_args(
        obj: &Object,
        points: &[crate::config::UprobeArgs],
    ) -> Result<()> {
        use crate::contract::types::StackPointArgs;
        let map = obj
            .map("uprobe_point_args")
            .ok_or_else(|| anyhow!("cannot find uprobe_point_args map"))?;
        for point in points {
            let key = point.index.to_ne_bytes();
            // Build the point_args_t value from the point's config.
            let (enter_key, signal, _op_count, op_key_list) = point.get_config();
            let mut value = StackPointArgs::default();
            value.enter_key = enter_key;
            value.signal = signal;
            value.op_count = op_key_list.len().min(value.op_key_list.len()) as u32;
            for (i, &op_key) in op_key_list.iter().enumerate() {
                if i < value.op_key_list.len() {
                    value.op_key_list[i] = op_key;
                }
            }
            let val_bytes = bytemuck::bytes_of(&value);
            map.update(&key, val_bytes, MapFlags::ANY)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_mask_is_all_33_bits() {
        assert_eq!(ARM64_REG_MASK.count_ones(), 33);
        assert_eq!(ARM64_REG_MASK, 0x1FFFFFFFF);
    }

    #[test]
    fn sample_stack_constant() {
        assert_eq!(SAMPLE_STACK_USER, 8192);
    }

    #[test]
    fn resolve_symbol_missing_returns_err() {
        // Parse this Cargo.toml as a stand-in non-ELF file; should error.
        let bytes = b"not an elf";
        assert!(resolve_symbol_offset(bytes, "anything").is_err());
    }
}
