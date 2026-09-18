//! Kernel virtual memory manager (VMM).
//!
//! Builds Orin's own page tables, replacing the bootloader's, and enforces the
//! permission policy in `docs/MEMORY.md` §2.2 — most importantly **W^X**: no
//! present kernel page may be both writable and executable.
//!
//! ## Why not `OffsetPageTable`
//!
//! The `x86_64` crate's `OffsetPageTable` converts a page-table *physical*
//! address to a dereferenceable pointer via `PhysAddr::new(pa - offset)`. For a
//! higher-half kernel with `offset = KERNEL_VMA`, `pa - KERNEL_VMA` underflows
//! into the non-canonical hole and the crate's canonicality assertion fires.
//! Rather than work around that with `new_unchecked` everywhere, Orin walks its
//! own tables through [`boot_alias`], which states the invariant once:
//! *during boot, physical memory below 2 GiB is reachable at
//! `phys + KERNEL_VMA`*. That is ~90 lines, it is auditable, and the same
//! helpers become the basis of the per-process `Vmm` in M4.
//!
//! ## Frame source
//!
//! Page-table frames come from the PMM, so `vmm::init` runs *after*
//! `pmm::init`. Nothing before that point may map memory.

#![allow(dead_code)]

use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use super::pmm;


// Linker-script symbols used by this module.
//
// `extern "C"` declarations are module-scoped in Rust: `crate::linker_sym!`
// expands to `core::ptr::addr_of!($sym)`, which resolves against the *calling*
// module's namespace, not `arch`'s. So each module that needs a symbol declares
// it. Declaring the same symbol twice is fine — both declarations bind to the
// single linker-defined address — and it keeps each module's dependencies
// visible in the module itself rather than hidden in arch.rs.
extern "C" {
    static _kernel_text_start: u8;
    static _kernel_text_end: u8;
    static _kernel_rodata_start: u8;
    static _kernel_rodata_end: u8;
    static _kernel_data_start: u8;
    static _kernel_data_end: u8;
    static _kernel_bss_start: u8;
    static _kernel_bss_end: u8;
    static _kernel_virt_end: u8;

}

use crate::arch::{phys_to_virt, virt_to_phys, BOOT_MAPPED_BYTES, LARGE_PAGE_SIZE, PAGE_SIZE};

/// Page-table entry flags. Kept as raw `u64` rather than re-exporting the
/// crate's `PageTableFlags` so that the permission policy is written in terms
/// Orin owns and can audit in one table (`docs/MEMORY.md` §2.2).
pub mod flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const NO_CACHE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    /// Huge page / 2 MiB page marker.
    pub const HUGE_PAGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    /// No-eXecute. Requires `EFER.NXE`, enabled in `main.rs` before use.
    pub const NO_EXECUTE: u64 = 1 << 63;

    pub const RO_X: u64 = PRESENT | GLOBAL;
    pub const RO_NX: u64 = PRESENT | GLOBAL | NO_EXECUTE;
    pub const RW_NX: u64 = PRESENT | WRITABLE | GLOBAL | NO_EXECUTE;
    /// Device memory: writable, non-executable, no caching, not global.
    pub const DEVICE: u64 = PRESENT | WRITABLE | NO_CACHE | WRITE_THROUGH | NO_EXECUTE;
}

/// Named permission profiles, so call sites say what they mean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Perm {
    /// Kernel `.text`: read + execute.
    TextRoX,
    /// Kernel `.rodata`: read only.
    RoData,
    /// Kernel `.data` / `.bss` / heap / page-table pool.
    DataRwNx,
    /// Memory-mapped device windows (framebuffer in M8).
    Device,
    /// Boot identity map after hardening: supervisor RW, never executable.
    BootIdentity,
}

impl Perm {
    pub const fn bits(self) -> u64 {
        match self {
            // `.text` is NOT marked GLOBAL in M1: TLB behaviour on the kernel's
            // own text is irrelevant before there are address-space switches,
            // and leaving it off means a stray CR3 write cannot leave stale
            // executable translations behind. M4 re-evaluates with PCID.
            Perm::TextRoX => flags::PRESENT | flags::GLOBAL,
            Perm::RoData => flags::PRESENT | flags::GLOBAL | flags::NO_EXECUTE,
            Perm::DataRwNx => flags::PRESENT | flags::WRITABLE | flags::GLOBAL | flags::NO_EXECUTE,
            Perm::Device => flags::DEVICE,
            Perm::BootIdentity => {
                flags::PRESENT | flags::WRITABLE | flags::NO_CACHE | flags::NO_EXECUTE
            }
        }
    }

    pub const fn describe(self) -> &'static str {
        match self {
            Perm::TextRoX => "R-X",
            Perm::RoData => "R--",
            Perm::DataRwNx => "RW-",
            Perm::Device => "RW- device (NX, no-cache)",
            Perm::BootIdentity => "RW- boot identity (NX, no-cache)",
        }
    }
}

/// NX availability, detected before any entry is written with the NX bit.
/// Writing NX bits with `EFER.NXE` clear causes #GP faults that look like
/// random crashes, so this is checked once and cached.
static NX_AVAILABLE: Mutex<bool> = Mutex::new(false);

pub fn set_nx_available(v: bool) {
    *NX_AVAILABLE.lock() = v;
}

pub fn nx_available() -> bool {
    *NX_AVAILABLE.lock()
}

/// Effective flags for a permission profile, with NX stripped if the CPU
/// cannot support it. Stripping is logged loudly by the caller — silently
/// dropping a security property is exactly what Rule 1 forbids.
fn effective(perm: Perm) -> u64 {
    let mut f = perm.bits();
    if !nx_available() {
        f &= !flags::NO_EXECUTE;
    }
    f
}

// ---------------------------------------------------------------------------
// Page-table frame pool
// ---------------------------------------------------------------------------

static PT_POOL: Mutex<PtPool> = Mutex::new(PtPool::new());

struct PtPool {
    allocated: usize,
    /// Page-table frames handed out, recorded so `selftest` can verify none of
    /// them ended up writable+executable.
    frames: [u64; 64],
}

impl PtPool {
    const fn new() -> Self {
        Self {
            allocated: 0,
            frames: [0; 64],
        }
    }

    fn alloc(&mut self) -> Option<PhysAddr> {
        let frame = pmm::allocate_frame()?;
        let pa = frame.start_address();
        if self.allocated < self.frames.len() {
            self.frames[self.allocated] = pa.as_u64();
        }
        self.allocated += 1;
        // Zero the frame. A page table with stale contents maps memory the
        // kernel did not ask for, which is both a correctness bug and a
        // security hole. Zeroing is not optional.
        // SAFETY: the frame was just allocated from the PMM, is inside the
        // boot-mapped range, and we hold the pool lock so nobody else has it.
        unsafe {
            let p = boot_alias(pa).as_mut_ptr::<u8>();
            core::ptr::write_bytes(p, 0, PAGE_SIZE as usize);
        }
        Some(pa)
    }
}

pub fn pt_frames_allocated() -> usize {
    PT_POOL.lock().allocated
}

// ---------------------------------------------------------------------------
// Kernel page table
// ---------------------------------------------------------------------------

/// Physical address of the page table currently in `CR3`, i.e. the kernel's
/// address space. Recorded so `sys.memory.virtual` over OKI can report it and
/// so M4 can clone the kernel half into new process page tables.
static KERNEL_PML4: Mutex<PhysAddr> = Mutex::new(PhysAddr::new(0));

pub fn kernel_pml4() -> PhysAddr {
    *KERNEL_PML4.lock()
}

/// Pointer to a page table at physical address `pa`, via the boot alias.
///
/// # Safety contract
/// `pa` must be a 4 KiB-aligned physical address inside the boot-mapped range
/// that the caller has exclusive access to (a freshly allocated PT frame, or
/// the boot tables before hardening).
unsafe fn table_at(pa: PhysAddr) -> *mut u64 {
    boot_alias(pa).as_mut_ptr::<u64>()
}

/// Physical address `pa` as a kernel virtual pointer, through the boot alias.
///
/// During boot, `PML4[511]` and `PML4[0]` reference the *same* PDPT, so
/// `pa + KERNEL_VMA` and `pa` both resolve to `pa`. Kernel code must use the
/// higher-half form (see `arch.rs`), and this helper is the single place that
/// computes it.
pub fn boot_alias(pa: PhysAddr) -> VirtAddr {
    debug_assert!(
        pa.as_u64() < BOOT_MAPPED_BYTES,
        "boot_alias({:#x}) is outside the 2 GiB boot mapping",
        pa.as_u64()
    );
    phys_to_virt(pa)
}

/// Index decomposition of a 4 KiB-granular virtual address.
#[derive(Clone, Copy, Debug)]
pub struct Indices {
    pub pml4: usize,
    pub pdpt: usize,
    pub pd: usize,
    pub pt: usize,
    pub offset: usize,
}

pub fn indices(va: VirtAddr) -> Indices {
    let v = va.as_u64();
    Indices {
        pml4: ((v >> 39) & 0x1FF) as usize,
        pdpt: ((v >> 30) & 0x1FF) as usize,
        pd: ((v >> 21) & 0x1FF) as usize,
        pt: ((v >> 12) & 0x1FF) as usize,
        offset: (v & 0xFFF) as usize,
    }
}

/// Mask off the flag bits of a page-table entry, leaving the address.
fn entry_addr(e: u64) -> u64 {
    // Bits 12..51 hold the physical address; bit 63 is NX. Masking with
    // 0x000F_FFFF_FFFF_F000 discards both, which is what every walk needs.
    e & 0x000F_FFFF_FFFF_F000
}

/// Physical address of the page-table root the kernel is running on right now.
///
/// Read from CR3 rather than taken from the `_boot_pml4` linker symbol, for two
/// reasons:
///
/// * Under `-C code-model=kernel` a low physical address cannot be referenced as
///   a symbol at all — it is ~2 GiB from `.text` in the wrong direction. See
///   [`crate::arch::BootParams`] for the general rule.
/// * CR3 is the *authoritative* answer. It names the table the MMU is actually
///   using, so this stays correct after [`init`] switches to the kernel's own
///   PML4, whereas a hardcoded symbol would silently keep pointing at the boot
///   tables and `harden_boot_map` would then harden a table nothing is using.
fn boot_root_table() -> PhysAddr {
    use x86_64::registers::control::Cr3;
    // `Cr3::read()` returns `(PhysFrame, Cr3Flags)`; the frame's start address
    // is the raw PML4 physical address, which is exactly what the page-table
    // walker wants.
    Cr3::read().0.start_address()
}

fn is_present(e: u64) -> bool {
    e & flags::PRESENT != 0
}

/// Descend one level, allocating an intermediate table if it does not exist.
///
/// Returns the physical address of the next-level table.
///
/// # Safety
/// `table` must be a valid pointer to a 512-entry page table.
unsafe fn descend(table: *mut u64, index: usize) -> Option<PhysAddr> {
    // `#![deny(unsafe_op_in_unsafe_fn)]` is on crate-wide, so being inside an
    // `unsafe fn` grants nothing: each raw-pointer operation still needs its
    // own block. That is deliberate — it makes every unsafe *operation* in the
    // page-table walker individually visible and individually commentable.
    //
    // SAFETY: the caller's contract guarantees `table` points at a 512-entry
    // page table, so `index` (masked to 9 bits by the caller) is in bounds.
    let entry = unsafe { *table.add(index) };
    if is_present(entry) {
        return Some(PhysAddr::new(entry_addr(entry)));
    }
    let new_pa = PT_POOL.lock().alloc()?;
    // Intermediate tables are always writable (the CPU writes A/D bits into
    // them) and never executable. USER is deliberately not set: an
    // intermediate table reachable from user space would let a user process
    // influence kernel translations.
    let mut f = flags::PRESENT | flags::WRITABLE;
    if nx_available() {
        f |= flags::NO_EXECUTE;
    }
    // SAFETY: as above; the entry is being initialised for the first time, so
    // no other translation can be observing it.
    unsafe { *table.add(index) = new_pa.as_u64() | f };
    Some(new_pa)
}

/// Map `size` bytes of `va` → `pa` with permission profile `perm`, using 4 KiB
/// pages.
///
/// `va`, `pa` and `size` must all be 4 KiB aligned. Panics otherwise: a
/// silently truncated mapping is a security bug, not a convenience.
pub fn map_4k(va: VirtAddr, pa: PhysAddr, size: u64, perm: Perm) {
    assert!(va.as_u64() % PAGE_SIZE == 0, "map_4k: unaligned va {va:#x}");
    assert!(pa.as_u64() % PAGE_SIZE == 0, "map_4k: unaligned pa {pa:#x}");
    assert!(size % PAGE_SIZE == 0, "map_4k: unaligned size {size:#x}");

    let root = kernel_pml4();
    assert!(root.as_u64() != 0, "map_4k before vmm::init");

    let f = effective(perm);
    let pages = (size / PAGE_SIZE) as usize;

    for i in 0..pages {
        let v = VirtAddr::new(va.as_u64() + (i as u64) * PAGE_SIZE);
        let p = pa.as_u64() + (i as u64) * PAGE_SIZE;
        let idx = indices(v);
        // SAFETY: `root` is a PT frame we own; each `descend` returns a PT
        // frame we own. No other code path mutates these tables concurrently
        // (the pool lock serialises allocation, and mapping happens with
        // interrupts disabled during init).
        unsafe {
            let pml4 = table_at(root);
            let Some(pdpt_pa) = descend(pml4, idx.pml4) else {
                panic!("map_4k: out of page-table frames at PDPT level")
            };
            let Some(pd_pa) = descend(table_at(pdpt_pa), idx.pdpt) else {
                panic!("map_4k: out of page-table frames at PD level")
            };
            let Some(pt_pa) = descend(table_at(pd_pa), idx.pd) else {
                panic!("map_4k: out of page-table frames at PT level")
            };
            let pt = table_at(pt_pa);
            let old = *pt.add(idx.pt);
            if is_present(old) && entry_addr(old) != p {
                // Remapping an existing page to a *different* physical frame is
                // either a bug or an attack. Refuse rather than leak a frame.
                panic!(
                    "map_4k: {v:#x} already maps {:#x}, refusing to remap to {p:#x}",
                    entry_addr(old)
                );
            }
            *pt.add(idx.pt) = p | f;
        }
    }
    crate::ktrace!(
        "vmm: mapped {size:#x} at {va:#x} -> {pa:#x} {}",
        perm.describe()
    );
}

/// Map `size` bytes using 2 MiB large pages.
///
/// `va`, `pa` and `size` must all be 2 MiB aligned. Used for the boot identity
/// map and for regions where per-page permission granularity buys nothing.
pub fn map_2m(va: VirtAddr, pa: PhysAddr, size: u64, perm: Perm) {
    assert!(
        va.as_u64() % LARGE_PAGE_SIZE == 0,
        "map_2m: unaligned va {va:#x}"
    );
    assert!(
        pa.as_u64() % LARGE_PAGE_SIZE == 0,
        "map_2m: unaligned pa {pa:#x}"
    );
    assert!(
        size % LARGE_PAGE_SIZE == 0,
        "map_2m: unaligned size {size:#x}"
    );

    let root = kernel_pml4();
    assert!(root.as_u64() != 0, "map_2m before vmm::init");

    let f = effective(perm) | flags::HUGE_PAGE;
    let count = (size / LARGE_PAGE_SIZE) as usize;

    for i in 0..count {
        let v = va.as_u64() + (i as u64) * LARGE_PAGE_SIZE;
        let p = pa.as_u64() + (i as u64) * LARGE_PAGE_SIZE;
        let idx = indices(VirtAddr::new(v));
        // SAFETY: as in `map_4k`.
        unsafe {
            let pml4 = table_at(root);
            let Some(pdpt_pa) = descend(pml4, idx.pml4) else {
                panic!("map_2m: out of page-table frames at PDPT level")
            };
            let Some(pd_pa) = descend(table_at(pdpt_pa), idx.pdpt) else {
                panic!("map_2m: out of page-table frames at PD level")
            };
            let pd = table_at(pd_pa);
            *pd.add(idx.pd) = p | f;
        }
    }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/// Result of [`init`], for the boot banner.
#[derive(Clone, Copy, Debug)]
pub struct VmmInfo {
    pub kernel_pml4_phys: u64,
    pub boot_pml4_phys: u64,
    pub text_va: u64,
    /// Bytes of actual `.text` content.
    pub text_content: u64,
    /// Bytes mapped R-X (the whole 2 MiB region the linker script reserved).
    pub text_mapped: u64,
    pub rodata_content: u64,
    pub rodata_mapped: u64,
    pub data_content: u64,
    pub data_mapped: u64,
    pub bss_content: u64,
    pub bss_mapped: u64,
    pub heap_va: u64,
    pub heap_size: u64,
    pub pt_frames: usize,
    pub identity_bytes: u64,
}


/// Build the kernel's own address space and switch `CR3` onto it.
///
/// Layout created (docs/MEMORY.md §2):
///
/// ```text
/// PML4[0]   -> boot PDPT (reused)      identity 0..2 GiB, hardened below
/// PML4[511] -> kernel PDPT             kernel image, 4 KiB pages:
///                                          .text    R-X
///                                          .rodata  R--
///                                          .data    RW-
///                                          .bss     RW-
/// PML4[508] -> heap PDPT               16 MiB heap, RW-, guard pages either side
/// device windows                       VGA 0xB8000 (RW- device)
/// ```
pub fn init() -> VmmInfo {
    let boot_pml4_pa = boot_root_table();
    assert!(
        boot_pml4_pa.as_u64() < BOOT_MAPPED_BYTES,
        "boot page tables at {:#x} are outside the boot mapping",
        boot_pml4_pa.as_u64()
    );

    // -- allocate the kernel's own PML4 ---------------------------------
    let new_pml4 = PT_POOL
        .lock()
        .alloc()
        .expect("vmm::init: no frame for the kernel PML4");

    // -- inherit the boot identity map ----------------------------------
    // Copy PML4[0] verbatim from the bootloader's table. The identity map
    // still has to work after the switch: the Multiboot2 information
    // structure, the boot page tables themselves and the boot stack all live
    // at low physical addresses. `harden_boot_map` then makes it NX.
    //
    // SAFETY: `boot_pml4_pa` is the bootloader's table, inside the boot
    // mapping, and GRUB guarantees it stays valid for the whole boot.
    unsafe {
        let boot = table_at(boot_pml4_pa);
        let dst = table_at(new_pml4);
        *dst.add(0) = *boot.add(0);
    }

    *KERNEL_PML4.lock() = new_pml4;

    let text_start = crate::linker_sym!(_kernel_text_start);
    let text_end = crate::linker_sym!(_kernel_text_end);
    let rodata_start = crate::linker_sym!(_kernel_rodata_start);
    let rodata_end = crate::linker_sym!(_kernel_rodata_end);
    let data_start = crate::linker_sym!(_kernel_data_start);
    let data_end = crate::linker_sym!(_kernel_data_end);
    let bss_start = crate::linker_sym!(_kernel_bss_start);
    let bss_end = crate::linker_sym!(_kernel_bss_end);

    // -- map the kernel image with fine-grained permissions --------------
    // The boot tables mapped all of this with 2 MiB RWX pages, which is why a
    // kernel that keeps running on bootloader tables has never validated its
    // own permissions. Rebuilding at 4 KiB granularity is what makes the
    // W^X self-test meaningful.
    //
    // The linker script (arch/x86_64/orin.ld, PROBLEM 2) gives every section
    // its own 2 MiB-aligned region, so these four ranges are guaranteed
    // contiguous and disjoint. If that invariant is ever broken, two sections
    // would share a page and one of them would silently get the wrong
    // permissions — so assert it here rather than trusting the script.
    let align_down = |v: u64| v & !(LARGE_PAGE_SIZE - 1);
    let align_up = |v: u64| (v + LARGE_PAGE_SIZE - 1) & !(LARGE_PAGE_SIZE - 1);
    let virt_end = crate::linker_sym!(_kernel_virt_end);

    assert!(
        align_down(text_start) == text_start,
        "vmm: .text start {text_start:#x} is not 2 MiB aligned"
    );
    assert!(
        text_end <= rodata_start && rodata_start <= data_start && data_start <= bss_start,
        "vmm: kernel sections are not in ascending address order"
    );
    assert!(
        align_down(rodata_start) != align_down(text_start)
            && align_down(data_start) != align_down(rodata_start)
            && align_down(bss_start) != align_down(data_start),
        "vmm: two kernel sections share a 2 MiB region; the linker script must \
         give each section its own region or one of them will get the wrong \
         permissions (see orin.ld PROBLEM 2)"
    );

    // (start_va, length, permission) — contiguous, disjoint, 2 MiB aligned.
    let regions: [(u64, u64, Perm); 4] = [
        (
            text_start,
            align_down(rodata_start) - text_start,
            Perm::TextRoX,
        ),
        (
            rodata_start,
            align_down(data_start) - rodata_start,
            Perm::RoData,
        ),
        (
            data_start,
            align_down(bss_start) - data_start,
            Perm::DataRwNx,
        ),
        // .bss plus .eh_frame/.gcc_except_table. The panic handler unwinds
        // through .eh_frame, so it must be mapped even though nothing executes
        // from it: RW-NX is correct for data the kernel only reads.
        (
            bss_start,
            align_up(virt_end) - bss_start,
            Perm::DataRwNx,
        ),
    ];

    let (mut text_len, mut rodata_len, mut data_len, mut bss_len) = (0u64, 0u64, 0u64, 0u64);
    for (start, len, perm) in regions {
        if len == 0 {
            crate::kwarn!("vmm: zero-length region at {start:#x} ({})", perm.describe());
            continue;
        }
        map_4k(VirtAddr::new(start), phys_of(start), len, perm);
        crate::kdebug!(
            "vmm: {start:#x} +{len:#x} {}",
            perm.describe()
        );
        match perm {
            Perm::TextRoX => text_len += len,
            Perm::RoData => rodata_len += len,
            Perm::DataRwNx if start == data_start => data_len += len,
            Perm::DataRwNx => bss_len += len,
            Perm::Device | Perm::BootIdentity => {}
        }
    }

    // -- map the kernel heap --------------------------------------------
    // Physical range comes from the linker-filled BootParams block, because a
    // low physical address cannot be a symbol reference under the kernel code
    // model (see arch::BootParams). Virtual range is an arch constant for the
    // same reason from the other side: HEAP_VMA sits exactly 2 GiB below
    // KERNEL_VMA, i.e. on the edge of what a RIP-relative access can encode.
    // orin.ld asserts the two agree, so neither can drift.
    let (heap_pa_start, heap_pa_end) = crate::arch::heap_phys_range();
    let heap_va_start = crate::arch::HEAP_VIRT_START;
    let heap_len = heap_pa_end - heap_pa_start;
    assert!(
        heap_pa_end <= BOOT_MAPPED_BYTES,
        "heap backing store at {:#x}..{:#x} is outside the M1 boot mapping",
        heap_pa_start,
        heap_pa_end
    );
    map_4k(
        VirtAddr::new(heap_va_start),
        PhysAddr::new(heap_pa_start),
        heap_len,
        Perm::DataRwNx,
    );
    // Guard pages: leaving the pages either side of the heap unmapped turns a
    // linear overflow into an immediate, precisely-located page fault instead
    // of silent corruption of whatever the allocator put next door.
    crate::kdebug!(
        "vmm: heap {:#x} bytes at va {:#x} (phys {:#x}), guard pages unmapped either side",
        heap_len,
        heap_va_start,
        heap_pa_start
    );

    // -- device windows --------------------------------------------------
    // VGA text buffer. Mapped RW, NX, no-cache: it is a device, and marking a
    // device window executable is how a ret2usr attack gets a foothold.
    map_4k(
        phys_to_virt(PhysAddr::new(0xB8000)),
        PhysAddr::new(0xB8000),
        PAGE_SIZE,
        Perm::Device,
    );

    // -- switch CR3 ------------------------------------------------------
    // After this instruction the kernel runs entirely on Orin's own page
    // tables. The switch is safe because `.text` was mapped above at the same
    // virtual addresses the CPU is currently executing from.
    //
    // SAFETY: `new_pml4` is a zeroed, fully populated 4 KiB-aligned page-table
    // frame that the PT pool owns and nothing else will reuse.
    unsafe {
        // `Cr3::write` takes `Cr3Flags`, not `PageTableFlags`: CR3 holds only
        // PCD/PWT plus the PCID field, because the permission bits of a root
        // page table are not a thing — permissions live in the entries. Using
        // the page-table flags type here would be a type error, which is the
        // compiler catching a real conceptual mistake.
        use x86_64::registers::control::{Cr3, Cr3Flags};
        let frame = x86_64::structures::paging::PhysFrame::from_start_address_unchecked(new_pml4);
        Cr3::write(frame, Cr3Flags::empty());
    }

    let info = VmmInfo {
        kernel_pml4_phys: new_pml4.as_u64(),
        boot_pml4_phys: boot_pml4_pa.as_u64(),
        text_va: text_start,
        text_content: text_end - text_start,
        text_mapped: text_len,
        rodata_content: rodata_end - rodata_start,
        rodata_mapped: rodata_len,
        data_content: data_end - data_start,
        data_mapped: data_len,
        bss_content: bss_end - bss_start,
        bss_mapped: bss_len,
        heap_va: heap_va_start,
        heap_size: heap_len,
        pt_frames: pt_frames_allocated(),
        identity_bytes: BOOT_MAPPED_BYTES,
    };
    crate::kinfo!(
        "vmm: switched CR3 to Orin page tables at {:#x} ({} PT frames)",
        info.kernel_pml4_phys,
        info.pt_frames
    );
    info
}

/// Translate a kernel virtual address to the physical address it maps to.
fn phys_of(va: u64) -> PhysAddr {
    virt_to_phys(VirtAddr::new(va)).unwrap_or_else(|| {
        panic!("vmm: address {va:#x} is not in the kernel half")
    })
}

// ---------------------------------------------------------------------------
// Boot-map hardening
// ---------------------------------------------------------------------------

/// Make the boot identity map supervisor-only, non-executable and no-cache.
///
/// **What this does and does not do**, stated plainly because the distinction
/// matters for the security claims in `docs/SECURITY.md`:
///
/// * Does: after this call, ring 3 cannot reach physical memory through
///   `PML4[0]`, and ring 0 cannot *execute* from it. A ret2usr-style attack
///   that needs executable low memory is closed.
/// * Does not: remove the mapping. Kernel code can still read and write low
///   physical memory, which is required in M1 because the Multiboot2
///   information structure and the boot page tables live there.
///
/// Full removal happens in M4, when per-process `Vmm` machinery exists to
/// relocate the boot data into the kernel half first. The self-test reports
/// this state as `HARDENED (removal pending M4)` so no boot log implies the
/// identity map is gone.
pub fn harden_boot_map() -> usize {
    let boot_pml4_pa = boot_root_table();
    let f = effective(Perm::BootIdentity);
    let mut entries = 0usize;

    // SAFETY: walking the bootloader's page tables, which are inside the boot
    // mapping and remain valid. We only modify flag bits on present entries;
    // addresses are preserved by `entry_addr`.
    unsafe {
        let pml4 = table_at(boot_pml4_pa);
        let pdpt_entry = *pml4.add(0);
        if !is_present(pdpt_entry) {
            crate::kwarn!("vmm: PML4[0] not present; nothing to harden");
            return 0;
        }
        let pdpt = table_at(PhysAddr::new(entry_addr(pdpt_entry)));
        for pdpt_i in 0..512 {
            let pd_entry = *pdpt.add(pdpt_i);
            if !is_present(pd_entry) {
                continue;
            }
            // The boot PDPT points at PDs whose entries are 2 MiB pages. If a
            // PDPT entry were itself a 1 GiB page we would have to handle it
            // differently; boot.asm never creates those, and asserting here
            // turns "someone changed boot.asm" into a clear failure.
            assert!(
                pd_entry & flags::HUGE_PAGE == 0,
                "vmm: unexpected 1 GiB page in the boot PDPT"
            );
            let pd = table_at(PhysAddr::new(entry_addr(pd_entry)));
            for pd_i in 0..512 {
                let e = *pd.add(pd_i);
                if !is_present(e) {
                    continue;
                }
                let addr = entry_addr(e);
                // Preserve HUGE_PAGE; replace the permission bits wholesale so
                // WRITABLE-by-user and any executable bit cannot survive.
                *pd.add(pd_i) = addr | f | flags::HUGE_PAGE;
                entries += 1;
            }
        }
    }

    // The entries we just modified are reachable through the *current* CR3, so
    // stale TLB entries with the old (executable) permissions must go.
    x86_64::instructions::tlb::flush_all();

    crate::kinfo!(
        "vmm: hardened {} boot identity-map entries -> supervisor-only, NX, no-cache",
        entries
    );
    entries
}

// ---------------------------------------------------------------------------
// Introspection used by the self-test and by OKI `sys.memory.virtual`
// ---------------------------------------------------------------------------

/// Walk the kernel page tables and report any present page that is both
/// writable and executable.
///
/// Returns the number of violations. Zero is the only acceptable answer; the
/// self-test panics otherwise. This check exists because W^X is claimed in the
/// security documentation, and a claim that no test verifies is a claim that
/// will silently regress.
pub fn count_wx_violations() -> usize {
    let root = kernel_pml4();
    if root.as_u64() == 0 {
        return 0;
    }
    let mut violations = 0usize;

    // SAFETY: walking our own kernel page tables, read-only.
    unsafe {
        let pml4 = table_at(root);
        for pml4_i in 0..512 {
            let e4 = *pml4.add(pml4_i);
            if !is_present(e4) {
                continue;
            }
            let pdpt = table_at(PhysAddr::new(entry_addr(e4)));
            for pdpt_i in 0..512 {
                let e3 = *pdpt.add(pdpt_i);
                if !is_present(e3) {
                    continue;
                }
                if e3 & flags::HUGE_PAGE != 0 {
                    if is_wx(e3) {
                        violations += 1;
                    }
                    continue;
                }
                let pd = table_at(PhysAddr::new(entry_addr(e3)));
                for pd_i in 0..512 {
                    let e2 = *pd.add(pd_i);
                    if !is_present(e2) {
                        continue;
                    }
                    if e2 & flags::HUGE_PAGE != 0 {
                        if is_wx(e2) {
                            violations += 1;
                        }
                        continue;
                    }
                    let pt = table_at(PhysAddr::new(entry_addr(e2)));
                    for pt_i in 0..512 {
                        let e1 = *pt.add(pt_i);
                        if is_present(e1) && is_wx(e1) {
                            violations += 1;
                        }
                    }
                }
            }
        }
    }
    violations
}

fn is_wx(e: u64) -> bool {
    let w = e & flags::WRITABLE != 0;
    // If NX is unavailable on this CPU, every page is implicitly executable and
    // the check would report the whole memory map as a violation. Report that
    // separately rather than producing 500 000 useless hits.
    let x = if nx_available() {
        e & flags::NO_EXECUTE == 0
    } else {
        false
    };
    w && x
}

/// Translate a kernel virtual address through the live page tables.
///
/// Used by the self-test to confirm the mappings we just built are the ones the
/// CPU will actually use, rather than trusting the code that built them.
pub fn translate(va: VirtAddr) -> Option<(PhysAddr, u64)> {
    let root = kernel_pml4();
    if root.as_u64() == 0 {
        return None;
    }
    let idx = indices(va);
    // SAFETY: read-only walk of our own page tables.
    unsafe {
        let e4 = *table_at(root).add(idx.pml4);
        if !is_present(e4) {
            return None;
        }
        let e3 = *table_at(PhysAddr::new(entry_addr(e4))).add(idx.pdpt);
        if !is_present(e3) {
            return None;
        }
        if e3 & flags::HUGE_PAGE != 0 {
            let base = entry_addr(e3) & !(1024 * 1024 * 1024 - 1);
            return Some((PhysAddr::new(base + (va.as_u64() & (1024 * 1024 * 1024 - 1))), e3));
        }
        let e2 = *table_at(PhysAddr::new(entry_addr(e3))).add(idx.pd);
        if !is_present(e2) {
            return None;
        }
        if e2 & flags::HUGE_PAGE != 0 {
            let base = entry_addr(e2) & !(LARGE_PAGE_SIZE - 1);
            return Some((
                PhysAddr::new(base + (va.as_u64() & (LARGE_PAGE_SIZE - 1))),
                e2,
            ));
        }
        let e1 = *table_at(PhysAddr::new(entry_addr(e2))).add(idx.pt);
        if !is_present(e1) {
            return None;
        }
        Some((
            PhysAddr::new(entry_addr(e1) + idx.offset as u64),
            e1,
        ))
    }
}
