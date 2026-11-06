//! Utility helpers. Mirrors `user/util` (`user/util/helper.go` in upstream
//! `dev`; the master-era `pkg/util/helper.go` path is not the reference).

pub mod consts;
pub mod fs;
pub mod hexdump;
pub mod reg;

pub use consts::*;
pub use fs::{find_lib, read_maps_by_pid};
pub use hexdump::{
    hex_dump_pure, pretty_byte_slice, COLOR_BLUE, COLOR_GREEN, COLOR_RED, COLOR_RESET, COLOR_YELLOW,
};
pub use reg::parse_reg;
