//! Architecture constants and address translation.
//!
//! The kernel is linked at the higher half (see `arch/x86_64/orin.ld` and
//! `docs/MEMORY.md` §2). Every kernel virtual address therefore satisfies:
//!
//! ```text
//!   virt = phys + KERNEL_VMA          (mod 2^64)
//!   phys = virt - KERNEL_VMA
//! ```
//!
//! Both directions wrap in 64-bit arithmetic, which is exactly what makes the
//! higher half work: `0 - 0xFFFFFFFF80000000 == 0x80000000`.
//!
//! During boot the identity map is also live, so a low physical address is
//! reachable at both `phys` and `phys + KERNEL_VMA`. After
//! `vmm::harden_boot_map()` the identity alias is supervisor-only and NX, and
//! after M4 it is removed entirely. **Kernel code must always use the
//! higher-half form.** Use [`phys_to_virt`] rather than casting, so that the
//! invariant is stated in one place and greppable.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::{PhysAddr, VirtAddr};

/// Link address of the kernel image. Matches `KERNEL_VMA` in the linker script.
pub const KERNEL_VMA: u64 = 0xFFFF_FFFF_8000_0000;

/// Any virtual address at or above this is kernel-owned. A single constant
/// comparison — this is the whole user/kernel boundary check (see
/// `docs/MEMORY.md` §2.1).
pub const KERNEL_SPACE_START: u64 = KERNEL_VMA;

/// Page size constants.
pub const PAGE_SIZE: u64 = 4096;
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
pub const HUGE_PAGE_SIZE: u64 = 1024 * 1024 * 1024;

/// Extent of physical memory covered by the boot page tables (2 GiB).
/// Frames beyond this are marked unusable by the PMM in M1 — see
/// `docs/MEMORY.md` §7.
pub const BOOT_MAPPED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

// --- Virtual regions, docs/MEMORY.md §2 ------------------------------------

/// Kernel heap base. 16 MiB, guarded on both sides.
pub const HEAP_VIRT_START: u64 = 0xFFFF_FFFF_0000_0000;
/// Kernel heap size in M1. Grown on demand once `vmalloc` exists (M4).
pub const HEAP_SIZE: usize = 16 * 1024 * 1024;

/// Direct/linear map base (M4).
pub const DIRECT_MAP_VIRT_START: u64 = 0xFFFF_8000_0000_0000;

// --- Symbols exported by the linker script ---------------------------------

extern "C" {
    pub static _kernel_virt_start: u8;
    pub static _kernel_virt_end: u8;
    pub static _kernel_text_start: u8;
    pub static _kernel_text_end: u8;
    pub static _kernel_rodata_start: u8;
    pub static _kernel_rodata_end: u8;
    pub static _kernel_data_start: u8;
    pub static _kernel_data_end: u8;
    pub static _kernel_bss_start: u8;
    pub static _kernel_bss_end: u8;
    pub static _kernel_phys_start: u8;
    pub static _kernel_phys_end: u8;
    pub static _boot_bss_phys_start: u8;
    pub static _boot_bss_phys_end: u8;
    pub static _boot_bss_phys_size: u8;
    pub static _boot_stack_top: u8;
    pub static _kernel_stack_top: u8;
    pub static _image_phys_start: u8;
}

/// Read a linker-provided symbol as a `u64` address.
///
/// # Safety contract (not an `unsafe fn`, because the symbols are guaranteed
/// to exist by the linker script — a missing one is a link error, not UB):
/// the `addr_of!` read never dereferences the symbol; it only takes its
/// address, which is what the linker script assigned.
// `linker_sym!` lives in lib.rs, defined before any `mod` item so that every
// module can reach it as `crate::linker_sym!`. See the note there for why it
// ---------------------------------------------------------------------------
// Boot parameters: physical addresses, delivered as data
// ---------------------------------------------------------------------------

/// Physical address of the linker-filled parameter block, handed to the kernel
/// by `boot.asm` in `%rsi`.
///
/// `0` means "not supplied", which only happens if something other than the boot
/// stub entered the kernel. [`boot_params`] refuses to guess in that case.
static BOOT_PARAMS_PHYS: AtomicU64 = AtomicU64::new(0);

/// Record the parameter block's physical address. Called once, from
/// [`crate::kmain::orin_kernel_main`], before anything that could need it.
///
/// `Relaxed` is correct and not laziness: this is written exactly once on the
/// boot core before `sti`, and every later read happens-after it in program
/// order on that same core. M4 gives each AP its own handoff before it enables
/// interrupts, and this becomes an `OnceLock` per CPU at that point.
pub fn set_boot_params(phys: u64) {
    BOOT_PARAMS_PHYS.store(phys, Ordering::Relaxed);
}

/// Physical addresses the linker script computed and Rust cannot reference
/// directly.
///
/// ## Why this struct exists
///
/// `-C code-model=kernel` makes every symbol reference RIP-relative, reaching
/// only ±2 GiB from `.text`. `.text` is at `0xFFFFFFFF80000000`, so the kernel
/// image, `.rodata`, `.bss` and the heap at `0xFFFFFFFF00000000` are all in
/// range — but the *physical* addresses of the boot page tables (`0x200000`)
/// and the heap backing store (`0x600000`) are about 2 GiB away in the other
/// direction and cannot be encoded at all. Referencing one produces
/// `relocation R_X86_64_32S out of range`, which names the symptom, not the
/// cause.
///
/// So `orin.ld` writes these values into a `.boot_params` section as plain
/// `QUAD`s — filled by the linker from the same expressions used elsewhere in
/// the script, so they cannot drift from the layout, and filled at *link* time,
/// so `boot.asm` computes nothing. Rust reads them back through the higher-half
/// alias as data.
///
/// **General rule this encodes:** in a higher-half kernel, a physical address is
/// a value to be loaded from mapped memory, never a symbol to be referenced.
///
/// ## Field order is an ABI
///
/// It must match the `QUAD` order in `orin.ld`'s `.boot_params` exactly.
/// `make verify-layout` dumps the section from the linked ELF and compares it
/// against these values, so a reordering in either place fails the build rather
/// than silently handing the frame allocator the wrong range to reserve.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootParams {
    /// Physical start of the loaded kernel image (1 MiB in practice).
    pub kernel_phys_start: u64,
    /// Physical end of everything the kernel occupies, including the heap
    /// backing store. The frame allocator reserves `[start, end)` and no more.
    pub kernel_phys_end: u64,
    /// Physical start of the boot stub's page tables and stacks.
    pub boot_bss_phys_start: u64,
    /// Physical end of the same.
    pub boot_bss_phys_end: u64,
    /// Physical start of the M1 heap backing store (2 MiB aligned).
    pub heap_phys_start: u64,
    /// Physical end of the same.
    pub heap_phys_end: u64,
}

/// Compile-time check that the struct is laid out the way `orin.ld` fills it.
///
/// These catch a reordered or padded Rust struct. They cannot catch the linker
/// script being reordered to match a wrong struct — `make verify-layout` covers
/// that direction by comparing against the linked ELF.
const _: () = assert!(core::mem::size_of::<BootParams>() == 48);
const _: () = assert!(core::mem::align_of::<BootParams>() == 8);
const _: () = assert!(core::mem::offset_of!(BootParams, kernel_phys_start) == 0x00);
const _: () = assert!(core::mem::offset_of!(BootParams, kernel_phys_end) == 0x08);
const _: () = assert!(core::mem::offset_of!(BootParams, boot_bss_phys_start) == 0x10);
const _: () = assert!(core::mem::offset_of!(BootParams, boot_bss_phys_end) == 0x18);
const _: () = assert!(core::mem::offset_of!(BootParams, heap_phys_start) == 0x20);
const _: () = assert!(core::mem::offset_of!(BootParams, heap_phys_end) == 0x28);

/// Read the linker-filled boot parameters.
///
/// Cheap and side-effect-free: one higher-half pointer read of 48 bytes that the
/// linker wrote into the image. Returns a copy, so no caller can hold a
/// reference into a section whose mapping the VMM later changes.
///
/// # Panics
/// If [`set_boot_params`] has not been called, i.e. the kernel was not entered
/// through `boot.asm`. There is no sensible fallback: every physical address the
/// kernel needs is in this block.
pub fn boot_params() -> BootParams {
    let phys = BOOT_PARAMS_PHYS.load(Ordering::Relaxed);
    assert!(
        phys != 0,
        "arch::boot_params called before boot.asm's parameter block was recorded. \
         kmain must call arch::set_boot_params(%rsi) as its very first action."
    );
    assert!(
        phys % core::mem::align_of::<BootParams>() as u64 == 0,
        "boot parameter block at {phys:#x} is not {}-byte aligned",
        core::mem::align_of::<BootParams>()
    );

    // The higher-half alias is formed HERE, at run time, rather than in orin.ld.
    // rust-lld truncates 64-bit symbol arithmetic, so a linker-script expression
    // like `_boot_params_phys + KERNEL_VMA` silently yields the low 32 bits —
    // 0x81600000 instead of 0xFFFFFFFF81600000 — and the failure surfaces as a
    // relocation error naming the symbol rather than the arithmetic that broke.
    // GNU ld would evaluate it correctly, so the trap is tool-specific. Adding
    // the offset in Rust is one `lea` and cannot be mis-evaluated by a tool.
    let va = phys_to_virt(PhysAddr::new(phys));

    // SAFETY: four conditions, all established before this call.
    //  * `phys` came from boot.asm, which took the address of orin.ld's
    //    `.boot_params` — a section the linker filled with six QUADs, so these
    //    are initialised bytes in the loaded image, not uninitialised memory.
    //  * `phys` is inside the first 2 GiB: orin.ld ASSERTs the whole image
    //    including .boot_params is within BOOT_MAPPED_BYTES, and boot.asm
    //    identity-maps physical 0..2 GiB at KERNEL_VMA..KERNEL_VMA+2 GiB with
    //    2 MiB large pages before jumping here. vmm::init inherits that
    //    mapping, so `va` stays readable for the whole life of the kernel.
    //  * `va` is 8-byte aligned because `phys` is (asserted above) and
    //    phys_to_virt adds a page-aligned constant, so the `*const BootParams`
    //    cast meets the type's alignment requirement.
    //  * `BootParams` is repr(C) with six u64 fields and no padding, and
    //    orin.ld ASSERTs `SIZEOF(.boot_params) == 48`, so the read stays inside
    //    the section and every field lands on the QUAD written for it.
    unsafe { *va.as_ptr::<BootParams>() }
}

/// Physical start of the loaded kernel image.
pub fn kernel_phys_start() -> u64 {
    boot_params().kernel_phys_start
}

/// Physical end of everything the kernel occupies, heap backing store included.
pub fn kernel_phys_end() -> u64 {
    boot_params().kernel_phys_end
}

/// Physical range occupied by the boot stub's page tables and stacks.
///
/// The frame allocator must reserve this: those bytes hold the page tables the
/// kernel is still running on until [`crate::memory::vmm`] switches CR3, and
/// the stacks the TSS points at.
pub fn boot_bss_phys_range() -> (u64, u64) {
    let p = boot_params();
    (p.boot_bss_phys_start, p.boot_bss_phys_end)
}

/// Physical range backing the M1 heap.
pub fn heap_phys_range() -> (u64, u64) {
    let p = boot_params();
    (p.heap_phys_start, p.heap_phys_end)
}

// --- Address translation ----------------------------------------------------

/// Translate a kernel-space virtual address to the physical address it names.
///
/// Returns `None` for addresses below [`KERNEL_SPACE_START`]: those are user
/// addresses in M4+, and during boot they are identity-map addresses that
/// kernel code must not be using. Rejecting them is deliberate — it turns
/// "someone passed a low pointer into a kernel API" into a handled error
/// instead of silent memory corruption.
pub fn virt_to_phys(va: VirtAddr) -> Option<PhysAddr> {
    if va.as_u64() < KERNEL_SPACE_START {
        return None;
    }
    // Wrapping subtract is the correct operation; see module docs.
    Some(PhysAddr::new(va.as_u64().wrapping_sub(KERNEL_VMA)))
}

/// Translate a physical address to its higher-half kernel virtual address.
///
/// Only valid while the identity/higher-half alias covers `pa`, i.e. for
/// `pa < BOOT_MAPPED_BYTES` in M1. Callers must check [`phys_is_boot_mapped`].
/// Identity-map virtual address for a low physical frame.
///
/// After `vmm::init` switches CR3 to Orin's own page tables, only PML4[0]
/// still carries the full 0..2 GiB identity map. The higher-half alias
/// (`phys + KERNEL_VMA`) is *not* fully rebuilt — only the kernel image,
/// heap, and a few device windows live there. Anything that must touch an
/// arbitrary boot-mapped physical frame after the CR3 switch (PMM canaries,
/// page-table walks, early DMA buffers) must use this identity form, not
/// [`phys_to_virt`].
///
/// M4 removes the identity map entirely; callers of this helper are exactly
/// the sites that must be rewritten then.
#[inline(always)]
pub fn phys_as_ident(pa: PhysAddr) -> VirtAddr {
    debug_assert!(
        pa.as_u64() < BOOT_MAPPED_BYTES,
        "phys_as_ident({:#x}) outside the M1 identity map",
        pa.as_u64()
    );
    VirtAddr::new(pa.as_u64())
}

pub fn phys_to_virt(pa: PhysAddr) -> VirtAddr {
    VirtAddr::new(pa.as_u64().wrapping_add(KERNEL_VMA))
}

/// True if `pa` is inside the range covered by the boot page tables.
pub fn phys_is_boot_mapped(pa: PhysAddr) -> bool {
    pa.as_u64() < BOOT_MAPPED_BYTES
}

/// Convert a raw pointer to a kernel virtual address without the canonicality
/// assertion that `VirtAddr::new` performs. Only for pointers known to come
/// from the linker script.
pub fn sym_to_virt<T>(p: *const T) -> VirtAddr {
    VirtAddr::new(p as u64)
}

#[cfg(test)]
mod tests {
    // Host-side tests for the pure arithmetic live in tools/hostcheck, because
    // the kernel crate is no_std and cannot run `cargo test` directly.
}
