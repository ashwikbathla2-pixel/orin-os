//! # orink — the Orin OS kernel
//!
//! Freestanding `no_std` kernel for x86_64. Entry point is
//! [`main::orin_kernel_main`], called from the 32-bit boot stub in
//! `arch/x86_64/boot/boot.asm` after it has enabled long mode.
//!
//! ## Module map
//!
//! | Module | Owns | Milestone |
//! |---|---|---|
//! | [`arch`] | address translation, linker symbols, memory-map constants | M1 |
//! | [`console`] | serial, VGA text, structured logging, lock-free panic output | M1 |
//! | [`cpu`] | CPUID, MSRs, register capture, interrupt gating | M1 |
//! | [`interrupts`] | GDT/TSS, IDT, 8259 PIC, PIT | M1 |
//! | [`memory`] | physical frames, kernel page tables, kernel heap | M1 |
//! | [`multiboot`] | boot-info and command-line parsing | M1 |
//! | [`drivers`] | PS/2 keyboard (the only driver until M7) | M1 |
//! | [`syscall`] | the reserved syscall ABI — **not implemented until M5** | M5 |
//! | [`selftest`] | in-kernel verification suite | M1 |
//! | [`panic`] | the last diagnostic the system will produce about itself | M1 |
//!
//! ## Module rules
//!
//! Enforced in review; see `docs/KERNEL.md` §6:
//!
//! * No module reaches into a sibling's internals — only its public API.
//! * No file over ~400 lines. Grow → split.
//! * Every `unsafe` block carries a `// SAFETY:` comment naming the invariant.
//! * Every `static mut` is listed in the global-state inventory
//!   (`docs/KERNEL.md` §7) with the reason it cannot yet be a safe abstraction.
//!
//! ## What this kernel deliberately does not contain
//!
//! No parsers for untrusted file formats. No crypto policy. No package
//! management. No network protocols above IP. No text rendering. Those are the
//! historical source of kernel privilege escalations, and Orin refuses to host
//! them (`docs/ARCHITECTURE.md` §3.4).

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]
// `incomplete_features` is allowed because `const` generics in the heapless
// containers and `generic_const_exprs`-adjacent patterns are used
// deliberately. If this ever covers a genuinely unfinished feature, that is a
// bug in this attribute and it should be narrowed.
#![allow(incomplete_features)]
// `abi_x86_interrupt` (the `extern "x86-interrupt"` ABI used by every IDT
// handler) is stable as of Rust 1.88, so it needs no feature gate. These two
// are still nightly-only:
#![feature(custom_test_frameworks)]   // `cargo test` inside the kernel (M4+)
#![feature(alloc_error_handler)]      // `#[alloc_error_handler]` for heap OOM
// The `extern "x86-interrupt"` ABI is what makes a handler return with `iretq`
// and receive an `InterruptStackFrame` instead of a normal Rust call frame.
// Still unstable, still required, and the x86_64 crate gates its whole IDT API
// behind the same feature. Dropping it would mean hand-writing all 256 stubs in
// assembly — which M2 may do anyway, but not as an accident of a feature flag.
#![feature(abi_x86_interrupt)]

// `alloc` gives Vec/String/Box without a full std. It is enabled only after
// `memory::heap::init` has run; anything that allocates before that point is a
// bug, and the allocator's empty initial range turns it into a loud
// out-of-memory panic rather than silent corruption.
extern crate alloc;

// ---------------------------------------------------------------------------
// The one macro that must be defined before any `mod` item.
// ---------------------------------------------------------------------------

/// Take the *address* of a linker-script symbol as a `u64`, without ever
/// dereferencing it.
///
/// `#[macro_export]` places this at the crate root, so every module reaches it
/// as `crate::linker_sym!`. It is defined here rather than in `arch` because
/// macro visibility is textual: it must appear before the `mod` items that use
/// it, and defining it in `arch` while calling it as `crate::linker_sym!` from
/// elsewhere is the pattern that produced the E0255 "defined multiple times"
/// error this replaces.
///
/// The expansion resolves `$sym` against the **calling** module's namespace, so
/// each module that uses it must carry its own
/// `extern "C" { static _foo: u8; }` declaration. Declaring the same symbol in
/// two modules is fine — both bind to the one linker-defined address — and it
/// keeps each module's linker dependencies visible in the module itself.
///
/// # Safety contract
/// Not an `unsafe fn`, because the symbols are guaranteed to exist by
/// `arch/x86_64/orin.ld`: a missing one is a link error, not undefined
/// behaviour. `addr_of!` takes an address and never reads through it.
#[macro_export]
macro_rules! linker_sym {
    ($sym:ident) => {{
        core::ptr::addr_of!($sym) as u64
    }};
}


pub mod arch;
pub mod console;
pub mod cpu;
pub mod drivers;
pub mod interrupts;
pub mod kmain;
pub mod log;
pub mod memory;
pub mod multiboot;
pub mod panic;
pub mod selftest;
pub mod syscall;


/// Version of the OKI (Orin Kernel Interface) ABI this kernel implements.
///
/// Bumped on any incompatible change to the OKI request/response shape or to
/// the capability set. User-space checks this before making calls; see
/// `docs/ARCHITECTURE.md` §4.
///
/// **M1 status:** the version number is declared and reported, but orink does
/// not yet *serve* OKI — there is no user space to serve it to. The client side
/// exists and is exercised against the `linuxabi` shim in
/// `userspace/incubator/orinkern`. The server arrives in M9. This is recorded
/// as WIRED-STUB, not IMPLEMENTED, in `docs/ROADMAP.md`.
pub const OKI_ABI_VERSION: u32 = 3;

/// Kernel semantic version. Independent of the package version in
/// `Cargo.toml` because the two have different compatibility contracts: the
/// OKI ABI is append-only forever, the crate version follows the build.
pub const KERNEL_VERSION: &str = "0.1.0-m1";

/// Panic-on-allocation-failure glue.
///
/// `alloc_error_handler` is separate from `panic_handler` because the two have
/// different jobs: this one knows the requested `Layout`, which is the single
/// most useful fact when diagnosing a kernel OOM, and it must say so before
/// delegating.
#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    memory::heap::oom(layout)
}

/// Required by `core` for `no_std` targets without a compiler-builtins mem*
/// implementation. `-Zbuild-std` provides `compiler_builtins` with the
/// `mem` feature, so these are only needed if that changes; they are defined
/// behind a cfg that is off by default so a duplicate-symbol link error is
/// impossible.
// `-Zbuild-std=core,alloc,compiler_builtins` supplies `memcpy`/`memset`/
// `memcmp` with the `mem` feature, so the kernel does not define them. If a
// future build stops using build-std, a `mem_fns` module behind a cfg feature
// is the fix — deliberately NOT provided now, because defining symbols that
// `compiler_builtins` also defines is a duplicate-symbol link error.

// Re-export the logging macros at the crate root so call sites write
// `crate::kinfo!` rather than `crate::console::log::kinfo!`. `#[macro_export]`
// already places them at the root; this module exists to document that fact
// and to keep `cargo doc` navigable.
pub mod prelude {
    //! Convenience imports for kernel code.
    pub use crate::{kcrit, kdebug, kerror, kinfo, klog, ktrace, kwarn};
    pub use crate::{raw_print, raw_println};
    pub use crate::{serial_print, serial_println};
    pub use crate::{vga_print, vga_println};
}
