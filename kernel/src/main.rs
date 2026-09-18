//! The ELF entry point shim — the whole bin target, and the ONLY file in the
//! kernel that exports ABI symbols.
//!
//! That restriction is load-bearing, not stylistic. `#[unsafe(no_mangle)]`
//! removes the crate-hash mangling that keeps Rust symbols unique, so two
//! `no_mangle` functions with the same name in the bin and in its own lib
//! collide and the linker resolves the collision silently. Having exactly one
//! file that names symbols makes the ABI surface auditable in one screen, and
//! `make verify-elf` checks the result by disassembling the entry point.
//!
//! Everything else in the kernel lives in the `orin_kernel` library crate,
//! including the M1 init sequence in [`orin_kernel::kmain`]. This file exists
//! for one reason: the linker needs a `main` symbol to make `_start` happy, and
//! the boot stub needs an `extern "C"` entry point whose address the Multiboot2
//! header can name.
//!
//! ## Why `#![no_main]` still needs a `fn main`
//!
//! `#![no_main]` suppresses rustc's use of the C-runtime entry shim; it does
//! **not** remove the requirement that the binary define `main`. The Rust
//! `std`-style startup path calls `main` by name, and with `no_main` we are on
//! the hook for providing it. Omitting it produces
//! `#[panic_handler] function required, but not found`-style cascading errors
//! that look nothing like the actual problem, so it is worth a comment.
//!
//! ## Control flow at boot
//!
//! ```text
//! GRUB ──> _start (boot.asm, 32-bit protected mode)
//!              │  enables PAE, EFER.LME, CR0.PG|WP, far-jumps to 64-bit
//!              ▼
//!          _start64 (boot.asm) ──> orin_kernel_main(multiboot2 info phys addr)
//!              │                      = `main` below
//!              ▼
//!          orin_kernel::kmain::kernel_main() ──> never returns
//! ```
//!
//! The address GRUB jumps to comes from the `entry_address` tag in the
//! Multiboot2 header in `boot.asm`, which names `_start`. `make verify-header`
//! checks that tag resolves to the real `_start` in the linked ELF, so a rename
//! in one place cannot silently produce an unbootable image.

#![no_std]
#![no_main]

/// Rust's required entry symbol.
///
/// Never called by anything in Orin: `boot.asm` calls
/// [`orin_kernel_main`] directly. It exists so the linked ELF has a `main`, and
/// it forwards to the real entry point so that if some future loader *does*
/// enter through `main` the kernel still boots instead of faulting.
#[unsafe(no_mangle)]
pub extern "C" fn main() -> ! {
    orin_kernel_main(0, 0)
}

/// The real kernel entry point, called from `arch/x86_64/boot/boot.asm`.
///
/// `#[unsafe(no_mangle)]` gives it the exact symbol name the assembly `call`s
/// and that the Multiboot2 boot path depends on. Both arguments are **physical**
/// addresses, valid because the boot stub identity-maps the first 2 GiB:
///
/// * `multiboot_info_phys` — the Multiboot2 information structure GRUB left in
///   `%ebx`.
/// * `boot_params_phys` — orin.ld's `.boot_params` block, the physical addresses
///   the kernel needs but cannot reference as symbols under the kernel code
///   model. `boot.asm` explains why it is passed rather than linked.
///
/// Passing `0` for either means "absent": [`kernel_main`][orin_kernel::kmain::kernel_main] detects that,
/// logs it loudly, and continues where it safely can. That path is reachable
/// only from `main` above, i.e. only if something other than GRUB entered the
/// kernel — which is exactly the situation where continuing with a warning beats
/// faulting with no output. A `0` boot-params block is not survivable, so that
/// one halts with a named reason instead of dereferencing address zero.
#[unsafe(no_mangle)]
pub extern "C" fn orin_kernel_main(multiboot_info_phys: u64, boot_params_phys: u64) -> ! {
    orin_kernel::kmain::kernel_main(multiboot_info_phys, boot_params_phys)
}
