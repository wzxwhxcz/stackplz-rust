//! stackplz library root. Re-exports the public modules so integration tests
//! and the binary can both access them.
//!
//! Report W10: the `dump` and `rpc` modules were deleted. Upstream `dev`
//! schedules them from `root.go` (dump-file replay / RPC server), but this
//! crate never constructed either one, so they were dead code that only looked
//! connected. Brief item 4 allows "connect or delete"; deletion is the accepted
//! option (detailed in DONE.md). Their CLI flags are removed in the same round.

pub mod argtype;
pub mod assets;
pub mod cli;
pub mod config;
pub mod contract;
pub mod ebpf;
pub mod event;
pub mod filter;
pub mod logger;
pub mod module;
pub mod signal;
pub mod util;
