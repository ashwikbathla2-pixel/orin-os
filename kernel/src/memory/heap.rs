//! Kernel heap: the `#[global_allocator]`.
//!
//! ## M1 backing store
//!
//! The heap is a fixed 16 MiB region whose physical pages are reserved by the
//! linker script (`.heap_region`) and mapped RW+NX by [`super::vmm::init`],
//! with the pages on either side left unmapped as guard pages. A linear
//! overflow therefore faults immediately at a known address instead of
//! corrupting whatever the allocator placed next door.
//!
//! This is an honest simplification, recorded in `docs/MEMORY.md` §7: M4
//! replaces it with a growable heap in the `vmalloc` region, backed by
//! on-demand frame allocation, once per-process page tables exist to make
//! "grow the mapping" a real operation rather than a boot-time special case.
//!
//! ## Allocator choice
//!
//! `linked_list_allocator::LockedHeap`: ~300 lines of audited, well-known code.
//! Kernel heap allocation is not a hot path in M1 — there are no processes, no
//! file descriptors, no sockets. A slab allocator for the fixed-size objects
//! that *will* be hot (`Task`, `Vmm`, `FileDesc`) arrives in M4, where the
//! allocation rate justifies the complexity. Picking a slab allocator now would
//! be optimising something that does not yet exist (Rule 14).

use core::alloc::Layout;
use core::ptr;

// `GlobalAlloc` is not imported by name: `LockedHeap` implements it and the
// `#[global_allocator]` static below is what registers it with the compiler.
// Naming the trait here would be an unused import.

use linked_list_allocator::LockedHeap;



/// The global allocator. Initialised by [`init`] with the real bounds; until
/// then its range is empty, so an accidental allocation before init returns
/// null and trips [`oom`] with a precise message instead of scribbling on
/// whatever memory the linker happened to put nearby.
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Statistics for `sys.heap` over OKI and for the boot banner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeapStats {
    pub base: u64,
    pub size: usize,
    pub initialised: bool,
}

static mut STATS: HeapStats = HeapStats {
    base: 0,
    size: 0,
    initialised: false,
};

/// Bring the heap up. Must run after [`super::vmm::init`].
///
/// Returns the usable size, which callers log so the boot record shows exactly
/// how much heap this kernel has.
pub fn init() -> usize {
    // arch constants, not linker symbols. HEAP_VMA is exactly 2 GiB below
    // KERNEL_VMA, so a RIP-relative reference to `_heap_virt_start` sits on the
    // very edge of what the kernel code model can encode. orin.ld ASSERTs that
    // its HEAP_VMA/HEAP_SIZE match these constants, so using the constants
    // cannot drift from the script.
    let start = crate::arch::HEAP_VIRT_START;
    let end = start + crate::arch::HEAP_SIZE as u64;
    assert!(
        end > start,
        "heap: linker script produced an empty heap region ({start:#x}..{end:#x})"
    );
    let size = (end - start) as usize;

    // SAFETY: `_heap_virt_start.._heap_virt_end` is mapped RW+NX by vmm::init,
    // is exclusively owned by the allocator, and is never otherwise referenced.
    // `LockedHeap::init` requires the region to be valid for `'static`, which
    // a linker-defined kernel region is.
    unsafe {
        ALLOCATOR.lock().init(start as *mut u8, size);
        // A single `static mut` for read-mostly statistics, written once here
        // before any other CPU exists and before interrupts are enabled. M4
        // replaces this with a per-CPU structure; see docs/KERNEL.md §7 for the
        // global-state inventory this belongs to.
        STATS = HeapStats {
            base: start,
            size,
            initialised: true,
        };
    }
    size
}

/// Snapshot for diagnostics. Reading `static mut` needs care: it is written
/// once in [`init`] before interrupts are enabled and before any other CPU
/// exists, so a plain read cannot race in M1.
pub fn stats() -> HeapStats {
    // SAFETY: see above; single-core, written before interrupts, never again.
    unsafe { STATS }
}

/// Allocation failure handler.
///
/// A kernel OOM is always a bug: either a leak, an unbounded allocation, or a
/// heap that is too small for the workload. It is reported with the requested
/// layout so the bug can be located, and then the kernel panics — continuing
/// with a failed allocation would mean dereferencing a null pointer somewhere
/// that did not expect one.
pub fn oom(layout: Layout) -> ! {
    let s = stats();
    crate::kcrit!(
        "kernel heap exhausted: requested {} bytes (align {}) with {} byte heap at {:#x}",
        layout.size(),
        layout.align(),
        s.size,
        s.base
    );
    panic!("kernel out of memory");
}

/// Probe the allocator: allocate, write a pattern, verify, free.
///
/// Part of the boot self-test. An allocator that has never been exercised
/// before the first real kernel allocation is an allocator whose first real
/// use is also its first test, which is not acceptable for a component every
/// other subsystem depends on.
pub fn selftest() -> Result<(), &'static str> {
    use alloc::vec::Vec;

    let mut v: Vec<u64> = Vec::with_capacity(256);
    for i in 0..256u64 {
        v.push(i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    }
    for (i, x) in v.iter().enumerate() {
        let expect = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        if *x != expect {
            return Err("heap: read-back mismatch");
        }
    }
    drop(v);

    // Many small allocations then free, to exercise the free-list coalescing
    // path rather than only the bump path.
    let mut blocks: Vec<alloc::boxed::Box<[u8; 64]>> = Vec::new();
    for _ in 0..64 {
        let mut b = alloc::boxed::Box::new([0xA5u8; 64]);
        b[0] = 0x5A;
        blocks.push(b);
    }
    for b in blocks.iter() {
        if b[0] != 0x5A || b[63] != 0xA5 {
            return Err("heap: small-block corruption");
        }
    }
    // Free every other block, then allocate again: the new allocations should
    // reuse the holes.
    let mut kept = Vec::new();
    for (i, b) in blocks.into_iter().enumerate() {
        if i % 2 == 0 {
            kept.push(b);
        }
    }
    let _refill: Vec<alloc::boxed::Box<[u8; 64]>> =
        (0..16).map(|_| alloc::boxed::Box::new([0u8; 64])).collect();
    drop(kept);

    // Verify the heap is still usable and that a raw pointer round-trips.
    let p = ALLOCATOR.lock();
    drop(p);
    let raw = unsafe { alloc::alloc::alloc(Layout::from_size_align(4096, 4096).unwrap()) };
    if raw.is_null() {
        return Err("heap: 4 KiB aligned allocation returned null");
    }
    unsafe {
        ptr::write_bytes(raw, 0x3C, 4096);
        if *(raw.add(4095)) != 0x3C {
            alloc::alloc::dealloc(raw, Layout::from_size_align(4096, 4096).unwrap());
            return Err("heap: 4 KiB block not fully writable");
        }
        alloc::alloc::dealloc(raw, Layout::from_size_align(4096, 4096).unwrap());
    }
    Ok(())
}
