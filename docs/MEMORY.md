# Orin OS — Memory Architecture

**Status:** M1 IMPLEMENTED (physical + kernel virtual + heap) · M4 per-process VM · **Code:** [`kernel/src/memory/`](../kernel/src/memory)

---

## 1. The three allocators

Orin separates three concerns that toy kernels usually conflate:

```text
   kernel heap  (Box/Vec/String)     ←─ bump/buddy over frames
        │ allocates frames from
        ▼
   virtual memory  (Vmm)             ←─ page tables, per address space
        │ maps frames from
        ▼
   physical frames (Pmm)             ←─ bitmap over the machine's RAM
```

Each has exactly one implementation behind a trait, so each can be replaced
(the PMM is the first candidate for a buddy allocator in M4 when fragmentation
becomes measurable).

---

## 2. Virtual memory map

Canonical x86_64 addresses: bits 48–63 must sign-extend bit 47. Orin splits the
space in half and keeps a huge non-canonical hole in the middle.

```text
0x0000_0000_0000_0000  ┌──────────────────────────────────────┐
                       │  USER SPACE                          │
   0x0000_0040_0000_0000│   • code (PIE, ASLR'd)                │
                       │   • data / heap (brk-free; mmap only) │
                       │   • stacks (guard page below each)    │
                       │   • per-app sandbox subtree mappings  │
                       │   • IPC shared regions (granted)      │
0x0000_7FFF_FFFF_FFFF  ├──────────────────────────────────────┤
                       │  NON-CANONICAL HOLE (~128 TiB)        │
0xFFFF_8000_0000_0000  ├──────────────────────────────────────┤
                       │  direct / linear map                  │  M4
                       │   every usable physical frame mapped   │
                       │   once, contiguous, NX by default      │
   0xFFFF_BFFF_FFFF_FFFF                                        │
                       ├──────────────────────────────────────┤
                       │  vmalloc region                       │  M4
                       │   non-contiguous kernel allocations,   │
                       │   module images, IPC buffers           │
                       ├──────────────────────────────────────┤
                       │  kernel heap                          │  M1 ✔
0xFFFF_FFFF_0000_0000  │   64 MiB, guarded both sides           │
                       ├──────────────────────────────────────┤
                       │  boot trampoline (temporary)          │  M1 ✔
0xFFFF_FFFF_7FFF_FFFF  │   removed/hardened after init          │
                       ├──────────────────────────────────────┤
                       │  KERNEL IMAGE  (higher half)          │  M1 ✔
0xFFFF_FFFF_8000_0000  │   .text   R-X      (2 MiB, RO after)  │
0xFFFF_FFFF_8020_0000  │   .rodata R--      (2 MiB, RO after)  │
0xFFFF_FFFF_8040_0000  │   .data   RW-                         │
0xFFFF_FFFF_8060_0000  │   .bss    RW-                         │
                       │   per-CPU areas                       │  M4
                       ├──────────────────────────────────────┤
                       │  fixed mappings                       │  M4
0xFFFF_FFFF_FFFF_FFFF  │   APIC, HPET, early serial debug      │
                       └──────────────────────────────────────┘
```

### 2.1 Why higher-half, from M1

If the kernel lives at physical addresses in the low half, then *any* process
mapping the low half can alias kernel memory, and every "is this pointer a
kernel pointer?" check becomes a range comparison against a moving target.
Pinning the kernel to the top 2 GiB gives:

- a **constant** kernel/user boundary (`0xFFFF_FFFF_8000_0000`), so the check
  is one comparison and cannot be confused by ASLR;
- the whole low half free for user ASLR, with no hole to route around;
- the direct map (M4) able to sit in the middle without colliding.

The cost is a boot-time identity alias, which §4.3 handles explicitly.

### 2.2 Page flags policy

| Region | P | R/W | U/S | NX | Notes |
|---|---|---|---|---|---|
| kernel `.text` | ✔ | RO | S | **X** | written once at init, then write-protected |
| kernel `.rodata` | ✔ | RO | S | NX | |
| kernel `.data`/`.bss` | ✔ | RW | S | NX | W^X: nothing in the kernel is both writable and executable |
| boot identity map | ✔ | RW | S | **NX** | hardened at init step 9 |
| direct map (M4) | ✔ | RW | S | NX | never executable, ever |
| user code | ✔ | RO | U | X | PIE + ASLR |
| user data/heap/stack | ✔ | RW | U | NX | |
| IPC shared region | ✔ | RW | U | NX | granted per endpoint |

W^X is a **structural invariant**, checked by `selftest::run()` at boot: the
kernel walks its own page tables and fails the self-test if any present page
has both W and X. This is the kind of check that catches a regression the day
it's introduced rather than the day it's exploited.

---

## 3. Physical memory (PMM)

### 3.1 Source of truth

The multiboot2 **memory map** (tag 6). Entry types:

| Type | Meaning | Orin action |
|---|---|---|
| 1 | Available RAM | **usable** |
| 2 | ACPI reclaimable | usable after ACPI tables are copied out (M7) |
| 3 | ACPI NVS | reserved forever |
| 4 | Bad RAM | reserved forever, logged as a warning |
| 5 | Bootloader reclaimable | usable after init (M1: reserved, logged) |
| other | Reserved / unknown | reserved forever, logged with its raw type |

Orin **never assumes** a region is usable because it's below some address.
Unknown types are reserved and logged — guessing here is how kernels corrupt
firmware data.

### 3.2 Reserved sub-ranges

Even inside type-1 regions, these are carved out before the allocator starts:

```text
0x00000000 .. 0x00001000   real-mode IVT / BIOS data (never touch)
0x00009FC00 .. 0x000A0000  EBDA
0x000A0000 .. 0x000C0000   VGA memory + option ROMs
0x000C0000 .. 0x00100000   firmware / ROM area
[kernel_phys_start .. kernel_phys_end]        the kernel image itself
[boot_tables .. +16KiB]                       boot page tables & stack
[multiboot_info .. +info.total_size]          GRUB's info structure
[framebuffer.base .. +size]                   framebuffer (M8)
[ACPI RSDP .. +len]                           ACPI tables
[initrd .. +size]                             M9
```

The carving is done by `pmm::reserve_range()`, which is public and unit-tested
so a new reservation can't silently overlap an old one.

### 3.3 Allocator: bitmap

M1 uses a **bitmap allocator**, 1 bit per 4 KiB frame.

```text
1 GiB RAM  →  262 144 frames  →  32 KiB bitmap  →  8 pages
64 GiB RAM →  16.7M frames    →  2 MiB bitmap
```

Why a bitmap and not a buddy allocator for M1:

- O(1) free, O(n/64) worst-case allocate with a 64-bit word cursor that
  resumes where it left off (so the common case is O(1)).
- **Zero fragmentation metadata.** A buddy allocator's free lists are the
  thing you have to get exactly right, and getting it wrong corrupts memory in
  ways that surface ten thousand allocations later. A bitmap is auditable by
  eye.
- Deterministic and testable: the allocator's index arithmetic is pure
  functions in `memory/pmm.rs`, covered by host-side unit tests in
  `tools/hostcheck`.

Known limitation, recorded honestly: no contiguity guarantee for multi-frame
allocations. M1 only ever asks for single frames (the heap takes a fixed
16 KiB span up front). **M4 replaces this with a buddy + per-order free-list
allocator** before demand paging needs order-9 allocations; the trait
(`FrameAllocator`) already exists so the swap is local.

### 3.4 API

```rust
pub trait FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame>;
    fn allocate_contiguous(&mut self, n: usize, align: usize) -> Option<PhysFrame>;
    fn deallocate_frame(&mut self, f: PhysFrame);
    fn free_frames(&self) -> usize;
    fn total_frames(&self) -> usize;
}
```

`deallocate_frame` **poisons** the frame's first 8 bytes with a canary in debug
builds. Freeing twice, or using a frame after free, trips the canary on the
next allocate and panics with the frame index — turning a silent corruption
into an immediate, located failure. That is Rule 1 applied to memory safety.

---

## 4. Kernel address space (VMM)

### 4.1 Page table structure

4-level paging (PML4 → PDPT → PD → PT), 4 KiB base pages, 2 MiB large pages
where the mapping is naturally aligned and NX-safe.

- Kernel `.text` uses **2 MiB** pages in M1 for simplicity; M4 splits it into
  4 KiB pages so `.text` can be write-protected separately from `.rodata`.
- The boot tables use 2 MiB pages exclusively (only 2 PDs needed for 2 GiB).
- 5-level paging (LA57) is **detected via CPUID.07H:ECX.LA57** and reported,
  but not enabled in M1. Enabling it changes `VirtAddr` width and every
  assumption above; it's a deliberate M14 decision, not an oversight.

### 4.2 Kernel space ownership

At init step 8, the kernel allocates a fresh PML4 and **copies the kernel-half
entries** from the boot tables, then switches `CR3`. From that moment the boot
page tables are no longer referenced by the kernel's own address space — except
through the identity alias, which step 9 hardens.

This matters: a kernel that keeps running on the bootloader's page tables is a
kernel that has never validated its own mappings.

### 4.3 The identity map problem (honest accounting)

At boot, `PML4[0]` identity-maps the first 2 GiB because:
- GRUB's multiboot info structure lives at a physical address < 1 MiB;
- the boot page tables themselves are physical;
- the boot stack is at physical `0x9F000`.

All three are needed *while executing from the higher half*. The correct fix is
to relocate all three into higher-half-mapped memory and then unmap `PML4[0]`
entirely. That is real work and it is scheduled for **M4 (per-process Vmm)**,
because that milestone builds the machinery to create and destroy address
spaces anyway.

What M1 does instead, and this is not a compromise on security:

```rust
vmm::harden_boot_map();   // init step 9
// PML4[0] subtree:  clear USER (already clear) → assert supervisor-only
//                   set   NX  on every present entry
//                   keep  RW  (boot data still live)
//                   log   the exact ranges hardened
```

So after init: the identity map is not reachable from ring 3, and is not
executable from ring 0. The residual risk is a kernel code path dereferencing a
stale low pointer — which is a *correctness* bug, not a privilege boundary
hole, and is caught by the W^X self-test and by `ORIN_STRICT_PTR` checks that
reject low-half pointers inside kernel APIs.

`selftest` reports this as `boot-identity-map: HARDENED (removal pending M4)`
so nobody reading a boot log believes it's gone.

---

## 5. Kernel heap

```text
0xFFFF_FFFF_0000_0000   guard page  (no-access)
0xFFFF_FFFF_0000_1000   heap        16 MiB in M1 (grown on demand in M4)
0xFFFF_FFFF_0100_0000   guard page  (no-access)
```

- Allocator: `linked_list_allocator::LockedHeap` behind Orin's
  `#[global_allocator]`.
- Chosen because it is ~300 lines of audited, well-known code and because
  kernel heap allocation is **not** a hot path once the direct map exists.
  A slab allocator for `Task`, `Vmm`, `FileDesc` arrives in M4 where the
  allocation rate actually justifies it.
- Guard pages on both sides turn a linear overflow into an immediate page
  fault at a known address rather than silent corruption of the next region.
- `alloc_error_handler` panics with the requested size and layout, then dumps
  heap statistics — an OOM in the kernel is a bug report, not a shrug.

Heap statistics are exposed over OKI (`sys.heap`) and rendered by Orin Monitor.

---

## 6. Per-process memory (M4 — DESIGNED)

| Object | Contents |
|---|---|
| `Vmm` | Owns a PML4, a list of `Region`s, an ASLR seed, an RSS counter |
| `Region` | `{ base, size, perms, kind, backing }` where `kind ∈ {Code, Data, Stack, Heap, Mmap, Ipc, Device}` |
| `Backing` | `Anonymous` (zero-fill on demand) · `File { inode, offset }` · `Shared { ipc_id }` · `Frame(PhysFrame)` |

- **Demand paging:** regions are recorded without frames; a page fault
  allocates and maps. M1 maps eagerly because there is no fault handler that
  can recover — the M1 fault handler panics, which is correct for a kernel with
  no user space.
- **COW:** fork/exec in M4 marks code+data regions COW; the write fault clones.
- **ASLR:** base addresses randomised from a per-`Vmm` seed derived at process
  creation from the kernel's entropy pool (M14 for real entropy; M4 uses the
  PIT+RDRAND mix, labelled as *provisional* until M14).
- **Guards:** one page below every stack and around every IPC region.
- **Accounting:** `Vmm` tracks RSS and a hard limit from the process's
  resource caps; exceeding it delivers an `oom` event to the process and to
  `orin-logind`, never a silent kill.

---

## 7. Known limitations (tracked, not hidden)

| Limitation | Impact | Fix |
|---|---|---|
| Boot mapping covers 2 GiB | Machines with > 2 GiB usable below the top of RAM cannot use it in M1 | Extend PDPT entries in M4 alongside the direct map |
| Bitmap PMM has no contiguity guarantee | Cannot serve large physically-contiguous DMA buffers | Buddy allocator, M4 |
| No `invpcid` / PCID | Every `CR3` switch flushes the TLB | PCID tagging with per-process Vmm, M4 |
| No 1 GiB pages | Slightly more TLB pressure in the direct map | Direct map design, M4 |
| LA57 detected, not enabled | > 128 TiB user VA unavailable | Deliberate; revisit M14 |
| Heap is fixed 16 MiB | Kernel OOM under heavy use | Grow-on-demand once `vmalloc` exists, M4 |
| No KASLR | Kernel base is a constant | M14, with the entropy pool |
