//! Physical frame allocator (PMM).
//!
//! Owns every 4 KiB page frame of machine RAM. Nothing else in the kernel may
//! touch a physical address that the PMM has not explicitly handed out or
//! explicitly reserved — that rule is what makes `docs/MEMORY.md` §3.2
//! auditable instead of aspirational.
//!
//! ## Why a bitmap
//!
//! M1 uses a bitmap: one bit per frame, `1` = free, `0` = used or reserved.
//! See `docs/MEMORY.md` §3.3 for the full argument. The short version is that
//! a bitmap's state is inspectable by eye and its index arithmetic is a pure
//! function, so it can be unit-tested on the host (`tools/hostcheck`) before it
//! ever runs on real memory. A buddy allocator's free lists are exactly the
//! kind of structure that corrupts memory ten thousand allocations after the
//! bug, and M4 will introduce one only once demand paging actually needs
//! contiguous multi-frame allocations.
//!
//! ## Known limitations (tracked in docs/MEMORY.md §7)
//!
//! * Covers at most [`MAX_PHYS`] (2 GiB), matching the boot page tables.
//! * No contiguity guarantee for multi-frame requests beyond a linear scan.
//! * No NUMA awareness. Fine on M1's single socket; revisited in M18.

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;
use x86_64::structures::paging::PhysFrame;
use x86_64::structures::paging::Size4KiB;
use x86_64::PhysAddr;

use crate::arch::BOOT_MAPPED_BYTES;
use crate::multiboot::BootInfo;

/// Frame size. Orin's PMM is 4 KiB-granular throughout; large pages are a
/// *mapping* property handled by the VMM, not an allocation property.
pub const FRAME_SIZE: usize = 4096;

/// Highest physical address the M1 allocator will manage.
///
/// Equal to the extent of the boot page tables. Frames above this are counted
/// and reported as `unmapped` so that `orin system` on a 16 GiB machine says
/// "2 GiB usable in M1, 14 GiB present but unmapped" rather than quietly
/// pretending the machine is smaller than it is.
pub const MAX_PHYS: u64 = BOOT_MAPPED_BYTES;

/// Number of frames the bitmap can describe: 2 GiB / 4 KiB = 524 288.
pub const MAX_FRAMES: usize = (MAX_PHYS as usize) / FRAME_SIZE;

/// Bitmap storage: 64 KiB, one bit per frame.
const BITMAP_WORDS: usize = MAX_FRAMES / 64;

/// Multiboot2 memory-map entry types. Values are fixed by the specification;
/// do not renumber.
pub mod memtype {
    pub const AVAILABLE: u32 = 1;
    pub const ACPI_RECLAIMABLE: u32 = 2;
    pub const ACPI_NVS: u32 = 3;
    pub const BAD_RAM: u32 = 4;
    pub const BOOTLOADER_RECLAIMABLE: u32 = 5;
}

// ---------------------------------------------------------------------------
// Pure bitmap helpers — host-testable, no kernel state.
// ---------------------------------------------------------------------------

#[inline]
fn bit_set(map: &mut [u64], idx: usize) {
    map[idx / 64] |= 1u64 << (idx % 64);
}

#[inline]
fn bit_clear(map: &mut [u64], idx: usize) {
    map[idx / 64] &= !(1u64 << (idx % 64));
}

#[inline]
fn bit_test(map: &[u64], idx: usize) -> bool {
    map[idx / 64] & (1u64 << (idx % 64)) != 0
}

/// Find the lowest set bit at or after `from`, scanning 64 bits at a time.
///
/// Returns `None` if there is none below `limit`. This is the allocator's hot
/// path: a fully-zero word is skipped in one compare, so a 2 GiB bitmap scan
/// costs at most 8192 word loads.
fn next_free(map: &[u64], from: usize, limit: usize) -> Option<usize> {
    if from >= limit {
        return None;
    }
    let mut idx = from;
    // Skip to the start of the word containing `from`, then mask off the bits
    // below it so we never hand out a frame we were told to start after.
    let word = idx / 64;
    let bit = idx % 64;
    let mut w = map[word] >> bit;
    if w != 0 {
        return Some(word * 64 + bit + w.trailing_zeros() as usize);
    }
    idx = (word + 1) * 64;
    while idx < limit {
        let widx = idx / 64;
        w = map[widx];
        if w != 0 {
            return Some(widx * 64 + w.trailing_zeros() as usize);
        }
        idx += 64;
    }
    None
}

/// Find `count` consecutive set bits at or after `from`, with `align` frame
/// alignment. Used for the (rare in M1) contiguous allocation path.
fn next_free_run(map: &[u64], from: usize, limit: usize, count: usize, align: usize) -> Option<usize> {
    if count == 0 {
        return Some(from);
    }
    let align = align.max(1);
    let mut start = (from + align - 1) / align * align;
    while start + count <= limit {
        // Fast reject: if the first frame is taken, jump forward.
        if !bit_test(map, start) {
            start = (start / align + 1) * align;
            continue;
        }
        let mut ok = true;
        for i in 1..count {
            if !bit_test(map, start + i) {
                ok = false;
                break;
            }
        }
        if ok {
            return Some(start);
        }
        start = (start / align + 1) * align;
    }
    None
}

// ---------------------------------------------------------------------------
// Allocator state
// ---------------------------------------------------------------------------

/// Free-frame cursor. Resumes where the last allocation left off so that a
/// long-running kernel does not rescan the whole bitmap every time.
static CURSOR: AtomicU64 = AtomicU64::new(0);

struct PmmInner {
    /// One bit per frame; `true` = free.
    bitmap: [u64; BITMAP_WORDS],
    /// Frames the memory map reported as available RAM.
    total_frames: usize,
    /// Frames marked free right now.
    free_frames: usize,
    /// Frames reserved by us (kernel image, boot data, heap, firmware areas).
    reserved_frames: usize,
    /// Frames the firmware reported as bad RAM (multiboot2 type 4).
    bad_frames: usize,
    /// Present RAM above [`MAX_PHYS`] that M1 cannot map. Reported, not used.
    unmapped_bytes: u64,
    initialised: bool,
}

impl PmmInner {
    const fn new() -> Self {
        Self {
            bitmap: [0u64; BITMAP_WORDS],
            total_frames: 0,
            free_frames: 0,
            reserved_frames: 0,
            bad_frames: 0,
            unmapped_bytes: 0,
            initialised: false,
        }
    }
}

static PMM: Mutex<PmmInner> = Mutex::new(PmmInner::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Statistics snapshot, exported over OKI as `sys.memory.physical`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    pub total_frames: usize,
    pub free_frames: usize,
    pub reserved_frames: usize,
    pub bad_frames: usize,
    pub unmapped_bytes: u64,
    pub frame_size: usize,
    pub max_phys: u64,
}

pub fn stats() -> Stats {
    let p = PMM.lock();
    Stats {
        total_frames: p.total_frames,
        free_frames: p.free_frames,
        reserved_frames: p.reserved_frames,
        bad_frames: p.bad_frames,
        unmapped_bytes: p.unmapped_bytes,
        frame_size: FRAME_SIZE,
        max_phys: MAX_PHYS,
    }
}

pub fn is_initialised() -> bool {
    PMM.lock().initialised
}

/// Build the allocator from the firmware memory map.
///
/// Every region the firmware did *not* mark available is reserved, including
/// types Orin does not recognise. Guessing that an unknown region is usable is
/// how kernels corrupt firmware data structures.
pub fn init(info: &BootInfo) {
    let mut p = PMM.lock();
    if p.initialised {
        // Re-initialising would leak every outstanding frame. Refuse loudly
        // rather than silently producing a corrupt allocator.
        panic!("pmm::init called twice");
    }

    // Bitmap starts all-zero = all-used. Regions are then explicitly freed.
    for e in info.mmap.as_slice() {
        let base = e.base;
        let len = e.length;
        match e.mem_type {
            memtype::AVAILABLE => {
                let hi = base.saturating_add(len);
                if base >= MAX_PHYS {
                    p.unmapped_bytes += len;
                    crate::kwarn!(
                        "pmm: available RAM [{:#x}..{:#x}) is above the M1 boot map ({:#x}); \
                         {} KiB present but unusable until M4 extends the page tables",
                        base,
                        hi,
                        MAX_PHYS,
                        len / 1024
                    );
                    continue;
                }
                let (lo, clipped_hi) = (base, hi.min(MAX_PHYS));
                if hi > MAX_PHYS {
                    p.unmapped_bytes += hi - MAX_PHYS;
                }
                p.free_range(lo, clipped_hi);
            }
            memtype::BAD_RAM => {
                p.bad_frames += (len as usize) / FRAME_SIZE;
                crate::kwarn!(
                    "pmm: firmware reports bad RAM at [{:#x}..{:#x}); reserved permanently",
                    base,
                    base.saturating_add(len)
                );
            }
            memtype::ACPI_RECLAIMABLE => {
                // Reclaimable once ACPI tables are copied out (M7). Until then
                // it is reserved, and the reservation is logged so the M7 work
                // has a list of exactly which ranges to reclaim.
                crate::kdebug!(
                    "pmm: ACPI reclaimable [{:#x}..{:#x}) reserved until M7",
                    base,
                    base.saturating_add(len)
                );
            }
            other => {
                crate::kdebug!(
                    "pmm: firmware region type {} [{:#x}..{:#x}) reserved",
                    other,
                    base,
                    base.saturating_add(len)
                );
            }
        }
    }

    p.total_frames = p.free_frames;
    p.initialised = true;

    crate::kinfo!(
        "pmm: {} frames ({} MiB) usable, {} bad, {} MiB present-but-unmapped in M1",
        p.total_frames,
        (p.total_frames * FRAME_SIZE) / (1024 * 1024),
        p.bad_frames,
        p.unmapped_bytes / (1024 * 1024)
    );
}

/// Reserve a physical byte range. Idempotent and safe to call on ranges that
/// are already reserved.
///
/// Ranges are expanded outward to frame boundaries: a partially-covered frame
/// is **never** handed out, because two owners of one frame is memory
/// corruption with no diagnostic.
pub fn reserve_range(start: u64, end: u64) {
    let mut p = PMM.lock();
    p.reserve_range(start, end);
}

/// Allocate a single 4 KiB frame.
pub fn allocate_frame() -> Option<PhysFrame<Size4KiB>> {
    let mut p = PMM.lock();
    let idx = p.allocate(1, 1)?;
    Some(frame_from_index(idx))
}

/// Allocate `count` physically contiguous frames, aligned to `align_frames`.
///
/// M1 callers use this only for the page-table pool. M4's buddy allocator will
/// replace the linear scan.
pub fn allocate_contiguous(count: usize, align_frames: usize) -> Option<PhysFrame<Size4KiB>> {
    let mut p = PMM.lock();
    let idx = p.allocate(count, align_frames)?;
    Some(frame_from_index(idx))
}

/// Return a frame to the allocator.
///
/// In debug builds the frame's first word is overwritten with a canary so that
/// a double free or a use-after-free trips on the *next* allocation with the
/// offending frame index in the panic message, instead of surfacing as random
/// corruption later. See `docs/MEMORY.md` §3.4.
pub fn deallocate_frame(frame: PhysFrame<Size4KiB>) {
    let mut p = PMM.lock();
    p.deallocate(frame.start_address().as_u64());
}

/// Validate a frame against the debug canary. Returns `true` if the frame
/// looks like it was properly freed (or was never freed).
fn canary_ok(phys: u64) -> bool {
    if cfg!(not(debug_assertions)) {
        return true;
    }
    let idx = (phys as usize) / FRAME_SIZE;
    if idx >= MAX_FRAMES || !crate::arch::phys_is_boot_mapped(PhysAddr::new(phys)) {
        return true;
    }
    // SAFETY: `phys` is inside the boot-mapped range and the PMM owns it, so
    // the higher-half alias is a valid, exclusive pointer to this frame.
    let va = crate::arch::phys_to_virt(PhysAddr::new(phys));
    let word = unsafe { (va.as_u64() as *const u64).read_volatile() };
    word != FREE_CANARY
}

const FREE_CANARY: u64 = 0x4F52_494E_4652_4545; // "ORINFREE"

fn frame_from_index(idx: usize) -> PhysFrame<Size4KiB> {
    let addr = PhysAddr::new((idx * FRAME_SIZE) as u64);
    // SAFETY: idx * FRAME_SIZE is 4 KiB aligned by construction.
    unsafe { PhysFrame::from_start_address_unchecked(addr) }
}

impl PmmInner {
    fn free_range(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        let end = end.min(MAX_PHYS);
        // Round INWARD: only fully-contained frames become free.
        let first = ((start + FRAME_SIZE as u64 - 1) / FRAME_SIZE as u64) as usize;
        let last = (end / FRAME_SIZE as u64) as usize;
        for idx in first..last.min(MAX_FRAMES) {
            if !bit_test(&self.bitmap, idx) {
                bit_set(&mut self.bitmap, idx);
                self.free_frames += 1;
            }
        }
    }

    fn reserve_range(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        // Round OUTWARD: a partially-covered frame is fully reserved.
        let first = (start / FRAME_SIZE as u64) as usize;
        let last = ((end + FRAME_SIZE as u64 - 1) / FRAME_SIZE as u64) as usize;
        for idx in first..last.min(MAX_FRAMES) {
            if bit_test(&self.bitmap, idx) {
                bit_clear(&mut self.bitmap, idx);
                self.free_frames -= 1;
                self.reserved_frames += 1;
            }
        }
    }

    fn allocate(&mut self, count: usize, align: usize) -> Option<usize> {
        if !self.initialised {
            // Allocating before `init` would hand out firmware-reserved memory.
            // This is a kernel bug, and it must be loud.
            panic!("pmm: allocation before pmm::init()");
        }
        let from = CURSOR.load(Ordering::Relaxed).min(MAX_FRAMES as u64) as usize;
        let start = if count == 1 {
            next_free(&self.bitmap, from, MAX_FRAMES)
        } else {
            next_free_run(&self.bitmap, from, MAX_FRAMES, count, align)
        };
        // Wrap once from the beginning before giving up: the cursor may have
        // advanced past the only free run.
        let start = match start {
            Some(s) => s,
            None if from > 0 => {
                if count == 1 {
                    next_free(&self.bitmap, 0, from)?
                } else {
                    next_free_run(&self.bitmap, 0, from, count, align)?
                }
            }
            None => return None,
        };

        for i in 0..count {
            bit_clear(&mut self.bitmap, start + i);
        }
        self.free_frames -= count;
        CURSOR.store((start + count) as u64, Ordering::Relaxed);
        Some(start)
    }

    fn deallocate(&mut self, phys: u64) {
        let idx = (phys as usize) / FRAME_SIZE;
        if idx >= MAX_FRAMES {
            panic!(
                "pmm: deallocate of {:#x} is outside the managed range (max {:#x})",
                phys, MAX_PHYS
            );
        }
        if bit_test(&self.bitmap, idx) {
            // A double free means two owners believe they have the frame.
            // Continuing would corrupt memory silently; stop here with the
            // frame index in the message.
            panic!("pmm: double free of frame {} ({:#x})", idx, phys);
        }
        if !canary_ok(phys) {
            panic!(
                "pmm: frame {} ({:#x}) was modified after free (canary overwritten) — \
                 use-after-free in kernel code",
                idx, phys
            );
        }
        bit_set(&mut self.bitmap, idx);
        self.free_frames += 1;
        if cfg!(debug_assertions) {
            // SAFETY: frame is managed, inside the boot-mapped range, and we
            // hold the PMM lock so nobody else can be using it.
            let va = crate::arch::phys_to_virt(PhysAddr::new(phys));
            unsafe { (va.as_u64() as *mut u64).write_volatile(FREE_CANARY) };
        }
    }
}

// ---------------------------------------------------------------------------
// Host-side tests
// ---------------------------------------------------------------------------
// The pure helpers above (`bit_*`, `next_free`, `next_free_run`, and the
// round-inward/round-outward logic in `free_range`/`reserve_range`) are
// exercised by `tools/hostcheck`, which `#[path]`-includes this file into a
// std test crate. That is why they take `&mut [u64]` instead of touching the
// global `PMM` — testability is a design constraint here, not an afterthought.
