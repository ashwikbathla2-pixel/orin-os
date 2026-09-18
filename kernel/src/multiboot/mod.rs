//! Bootloader protocol handling.
//!
//! M1 speaks Multiboot2 only. The Limine protocol and a direct-UEFI path are
//! designed in `docs/BOOT.md` §7 and will be additive: each produces the same
//! [`info::BootInfo`], and nothing downstream of the parser knows which loader
//! supplied it.

pub mod info;

pub use info::{
    parse, parse_params, read_from, BootInfo, BootParams, FramebufferInfo, MmapEntry, PanicAction,
    ParseError, BOOT_MAGIC,
};
