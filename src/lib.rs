// All `unsafe fn` in this crate are either `extern "C"` FFI entry-points whose
// safety contracts are documented in `specter.h`, or internal helpers whose
// callers are the FFI layer above them.  A Rust `# Safety` section would
// duplicate the C-header docs without adding value.
#![allow(clippy::missing_safety_doc)]

pub mod config;
pub mod ffi;
pub mod memory;
pub mod utils;
