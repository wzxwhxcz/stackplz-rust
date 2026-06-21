//! eBPF subsystem. Mirrors `pkg/ebpf` (kernel-config probing) and provides the
//! libbpf-rs based loader used by `user/module`.
//!
//! - `capability.rs` => `pkg/ebpf/{bpf.go, android.go, parse.go}`
//! - `bpf_common.rs` => the libbpf-rs loading glue (replaces ebpfmanager usage)

pub mod bpf_common;
pub mod capability;

pub use capability::{is_enable_bpf, is_enable_btf};
