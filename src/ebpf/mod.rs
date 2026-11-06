//! eBPF subsystem. Mirrors dev's `user/util` kernel-config probing and provides
//! the libbpf-rs based loader used by `user/module`.
//!
//! - `capability.rs` => `user/util/{bpf.go, android.go}` (master-era `pkg/ebpf`)
//! - `bpf_common.rs` => the libbpf-rs loading glue (replaces ebpfmanager usage)

pub mod bpf_common;
pub mod capability;

pub use capability::{is_enable_bpf, is_enable_btf};
