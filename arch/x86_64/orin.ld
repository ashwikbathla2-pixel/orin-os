/* =============================================================================
   Orin OS — x86_64 kernel linker script
   arch/x86_64/orin.ld

   This file IS the kernel memory map. docs/MEMORY.md §2 documents the same
   layout; if they disagree, treat it as a bug and fix both.

   ---------------------------------------------------------------------------
   PROBLEM 1 — TWO ADDRESS SPACES IN ONE IMAGE
   ---------------------------------------------------------------------------
   The kernel is linked at the higher half (0xFFFFFFFF80000000) so user/kernel
   separation is one constant comparison. But GRUB enters us in 32-bit protected
   mode WITH PAGING DISABLED, where only physical addresses exist.

   So the image holds two kinds of content:

     (A) Boot-time content — Multiboot2 header, GDT, page tables, boot stack.
         The 32-bit stub addresses these ABSOLUTELY and PHYSICALLY. Must live low.
     (B) Kernel content — .text/.rodata/.data/.bss, addressed by Rust at
         higher-half virtual addresses.

   Solution: boot.asm builds page tables that alias physical 0..2 GiB to BOTH
   virtual 0..2 GiB and virtual KERNEL_VMA..KERNEL_VMA+2GiB, using 2 MiB large
   pages. Sections in (A) are laid out while `.` is still low; then `.` jumps to
   KERNEL_VMA for (B).

   ---------------------------------------------------------------------------
   PROBLEM 2 — SECTIONS MUST NOT SHARE A 2 MiB PAGE
   ---------------------------------------------------------------------------
   The VMM maps the kernel image at 4 KiB granularity with a different
   permission profile per section (.text R-X, .rodata R--, .data/.bss RW-).
   If two sections land in the same 2 MiB region, the VMM must pick ONE
   permission for the overlap. Therefore each section gets an EXPLICIT
   2 MiB-aligned VMA.

   ---------------------------------------------------------------------------
   PROBLEM 3 — VMA PADDING MUST NOT APPEAR IN THE FILE / PHYSADDR
   ---------------------------------------------------------------------------
   Reserving a whole 2 MiB per section would make the ELF huge if the padding
   were also loaded. The script tracks the physical load address in `_lma` and
   advances it by each section's REAL size only.

   GRUB additionally requires that no two PT_LOAD PhysAddr ranges overlap
   ("error: overlap detected"). A NOBITS (.bss) section whose VMA sits 2 MiB
   after .data is still merged into .data's PT_LOAD by default: MemSiz then
   spans the VMA gap and claims every LMA that falls in it. Fix: give every
   NOBITS section an explicit AT(_lma) AFTER all PROGBITS, so it gets its own
   PT_LOAD whose PhysAddr continues the packed LMA stream.

   ---------------------------------------------------------------------------
   PROBLEM 4 — BOOT SECTIONS: VMA MUST EQUAL LMA
   ---------------------------------------------------------------------------
   With paging disabled, GRUB loads at LMA and jumps to VMA. If they differ
   the stub executes whatever was at VMA already and faults before producing
   any output. Cause of the classic form: `ALIGN(n) : AT(_lma)` advances
   `.` without advancing `_lma`. Fix: do not use AT() for boot sections.
   ========================================================================== */

OUTPUT_ARCH(i386:x86-64)
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_boot_start)

KERNEL_VMA = 0xFFFFFFFF80000000;
HEAP_VMA   = 0xFFFFFFFF00000000;
HEAP_SIZE  = 16M;

/* 2 GiB. rust-lld rejects the `G` suffix, hence 2048M.
   Must match BOOT_MAPPED_BYTES in kernel/src/arch.rs. */
BOOT_MAPPED_BYTES = 2048M;

/* Cross-checked against boot.asm's assembly-time size of the resb block. */
EXPECTED_BOOT_BSS_SIZE = 64K;

SECTIONS
{
    /* Start at 1 MiB physical. Below this: IVT, BIOS data, VGA, option ROMs. */
    . = 1M;
    _image_phys_start = .;

    /* =================================================================
       (A) BOOT SECTIONS — VMA == LMA (paging is off at entry)
       ================================================================= */

    .multiboot_header ALIGN(8) : {
        KEEP(*(SORT_NONE(.multiboot_header)))
    }

    .boot_text ALIGN(16) : {
        *(.boot_text)
    }

    .boot_rodata ALIGN(16) : {
        *(.boot_rodata)
    }

    .boot_gdt ALIGN(16) : {
        *(.boot_gdt)
    }

    .boot_data ALIGN(16) : {
        *(.boot_data)
    }

    /* Boot .bss: page tables + boot stack + kernel stack. NOBITS.
       2 MiB aligned: the stub maps with large pages. */
    . = ALIGN(2M);
    .boot_bss ALIGN(2M) (NOLOAD) : {
        _boot_bss_phys_start = .;
        *(.boot_bss)
        . = ALIGN(4K);
        _boot_bss_phys_end = .;
    }
    _boot_bss_phys_size = _boot_bss_phys_end - _boot_bss_phys_start;

    . = ALIGN(2M);
    _image_phys_boot_end = .;

    /* =================================================================
       (B) KERNEL SECTIONS — higher-half VMA, packed LMA
       =================================================================
       PROGBITS first (LMA packed). NOBITS after, each with AT(_lma) so
       they do not merge into the preceding PROGBITS PT_LOAD.
       ================================================================= */

    _lma = _image_phys_boot_end;
    . = KERNEL_VMA;
    _kernel_virt_start = .;

    .text KERNEL_VMA + 0M : AT(_lma) {
        _kernel_text_start = .;
        KEEP(*(SORT_NONE(.text .text.*)))
        . = ALIGN(16);
        _kernel_text_end = .;
    }
    _lma += SIZEOF(.text);
    . = KERNEL_VMA + 2M;

    .rodata KERNEL_VMA + 2M : AT(_lma) {
        _kernel_rodata_start = .;
        KEEP(*(SORT_NONE(.rodata .rodata.*)))
        . = ALIGN(16);
        _kernel_rodata_end = .;
    }
    _lma += SIZEOF(.rodata);
    . = KERNEL_VMA + 4M;

    .data KERNEL_VMA + 4M : AT(_lma) {
        _kernel_data_start = .;
        KEEP(*(SORT_NONE(.data .data.*)))
        . = ALIGN(16);
        _kernel_data_end = .;
    }
    _lma += SIZEOF(.data);

    /* Unwind + GOT are PROGBITS: must take LMA before any NOBITS. */
    .eh_frame ALIGN(8) : AT(_lma) {
        _kernel_eh_frame_start = .;
        *(.eh_frame .eh_frame_hdr .eh_frame.*)
    }
    _lma += SIZEOF(.eh_frame);

    .gcc_except_table ALIGN(8) : AT(_lma) {
        *(.gcc_except_table .gcc_except_table.*)
    }
    _lma += SIZEOF(.gcc_except_table);

    .got ALIGN(8) : AT(_lma) {
        _kernel_got_start = .;
        *(.got .got.* .got.plt)
        . = ALIGN(8);
        _kernel_got_end = .;
    }
    _lma += SIZEOF(.got);

    /* Boot-params block. Physical address is what boot.asm passes in %rsi.
       VMA = phys + KERNEL_VMA so the bytes are readable through the boot
       identity map. Written as a section-VMA expression because rust-lld
       truncates `symbol + KERNEL_VMA` when evaluated as a free-standing
       absolute. Field order is the ABI with arch::BootParams. */
    _boot_params_phys = ALIGN(_lma, 8);
    .boot_params (_boot_params_phys + KERNEL_VMA) : AT(_boot_params_phys) {
        QUAD(_kernel_phys_start)     /* +0x00 */
        QUAD(_kernel_phys_end)       /* +0x08 */
        QUAD(_boot_bss_phys_start)   /* +0x10 */
        QUAD(_boot_bss_phys_end)     /* +0x18 */
        QUAD(_heap_phys_start)       /* +0x20 */
        QUAD(_heap_phys_end)         /* +0x28 */
    }
    _lma = _boot_params_phys + SIZEOF(.boot_params);

    /* .bss: own PT_LOAD via AT(_lma). VMA at the 2 MiB-aligned slot. */
    .bss KERNEL_VMA + 6M (NOLOAD) : AT(ALIGN(_lma, 16)) {
        _kernel_bss_start = .;
        KEEP(*(SORT_NONE(.bss .bss.*)))
        KEEP(*(COMMON))
        . = ALIGN(16);
        _kernel_bss_end = .;
    }
    _lma = LOADADDR(.bss) + SIZEOF(.bss);

    /* _kernel_virt_end must cover .eh_frame/.got as well as .bss: the VMM
       maps up to this point RW-NX and the panic handler walks .eh_frame. */
    _kernel_virt_end = MAX(ALIGN(_kernel_bss_end, 4K), ALIGN(_kernel_got_end, 4K));

    /* Heap: physical pages after .bss, virtual at HEAP_VMA. */
    _lma = ALIGN(_lma, 2M);
    _heap_phys_start = _lma;
    _heap_lma        = _lma;
    _heap_phys_end   = _heap_phys_start + HEAP_SIZE;
    _lma             = _heap_phys_end;

    .heap_region HEAP_VMA (NOLOAD) : AT(_heap_lma) {
        _heap_virt_start = .;
        . += HEAP_SIZE;
        _heap_virt_end = .;
    }

    _kernel_phys_start = _image_phys_start;
    _kernel_phys_end   = _lma;

    /* Stack-top high aliases for #PF diagnostics. rust-lld may truncate
       these; idt.rs also forms the alias at runtime if needed. */
    _boot_stack_top_hi   = _boot_stack_top   + KERNEL_VMA;
    _kernel_stack_top_hi = _kernel_stack_top + KERNEL_VMA;

    /* .debug_gdb_scripts is SHF_ALLOC (rustc) and MUST be discarded, or it
       becomes a PT_LOAD at a nonsense PhysAddr and GRUB reports overlap. */
    /DISCARD/ : {
        *(.note .note.*)
        *(.comment)
        *(.debug_gdb_scripts)
    }
}

/* =============================================================================
   LINK-TIME ASSERTIONS
   =============================================================================
   Boot-section VMA==LMA and PT_LOAD PhysAddr non-overlap are checked by
   tools/verify/verify_layout.py: rust-lld rejects nested ADDR/LOADADDR calls
   and cannot express "no two PT_LOAD ranges overlap" as an ASSERT.
   ============================================================================= */

ASSERT(_boot_bss_phys_size == EXPECTED_BOOT_BSS_SIZE,
       "orin.ld: .boot_bss size disagrees with boot.asm. Update EXPECTED_BOOT_BSS_SIZE and the resb block together.")

ASSERT(_image_phys_boot_end <= BOOT_MAPPED_BYTES,
       "orin.ld: boot image extends past the region boot.asm identity-maps.")

ASSERT(ADDR(.text)   == KERNEL_VMA + 0M, "orin.ld: .text VMA is not KERNEL_VMA + 0M.")
ASSERT(ADDR(.rodata) == KERNEL_VMA + 2M, "orin.ld: .rodata VMA is not KERNEL_VMA + 2M.")
ASSERT(ADDR(.data)   == KERNEL_VMA + 4M, "orin.ld: .data VMA is not KERNEL_VMA + 4M.")
ASSERT(ADDR(.bss)    == KERNEL_VMA + 6M, "orin.ld: .bss VMA is not KERNEL_VMA + 6M.")

ASSERT(_kernel_text_end   <= KERNEL_VMA + 2M, "orin.ld: .text exceeds its 2 MiB region.")
ASSERT(_kernel_rodata_end <= KERNEL_VMA + 4M, "orin.ld: .rodata exceeds its 2 MiB region.")
ASSERT(_kernel_data_end   <= KERNEL_VMA + 6M, "orin.ld: .data exceeds its 2 MiB region.")

ASSERT(LOADADDR(.multiboot_header) == _image_phys_start,
       "orin.ld: .multiboot_header is not at the physical start of the image.")
ASSERT(LOADADDR(.text) == _image_phys_boot_end,
       "orin.ld: .text LMA does not continue from the boot image end.")
ASSERT(LOADADDR(.rodata) >= LOADADDR(.text) + SIZEOF(.text),
       "orin.ld: .rodata LMA overlaps .text.")
ASSERT(LOADADDR(.data) >= LOADADDR(.rodata) + SIZEOF(.rodata),
       "orin.ld: .data LMA overlaps .rodata.")
ASSERT(LOADADDR(.eh_frame) >= LOADADDR(.data) + SIZEOF(.data),
       "orin.ld: .eh_frame LMA overlaps .data.")
ASSERT(LOADADDR(.got) >= LOADADDR(.eh_frame) + SIZEOF(.eh_frame),
       "orin.ld: .got LMA overlaps .eh_frame.")
ASSERT(LOADADDR(.boot_params) >= LOADADDR(.got) + SIZEOF(.got),
       "orin.ld: .boot_params LMA overlaps .got.")
ASSERT(LOADADDR(.bss) >= LOADADDR(.boot_params) + SIZEOF(.boot_params),
       "orin.ld: .bss LMA overlaps .boot_params.")
ASSERT(_heap_phys_start >= LOADADDR(.bss) + SIZEOF(.bss),
       "orin.ld: heap LMA overlaps .bss.")

ASSERT(_kernel_phys_end - _image_phys_start <= BOOT_MAPPED_BYTES,
       "orin.ld: kernel image exceeds the 2 GiB boot alias.")
ASSERT(_heap_phys_end <= BOOT_MAPPED_BYTES,
       "orin.ld: heap backing store is outside the boot alias.")
ASSERT(_heap_phys_start % 2M == 0,
       "orin.ld: heap physical base is not 2 MiB aligned.")

ASSERT(_heap_virt_start == 0xFFFFFFFF00000000,
       "orin.ld: HEAP_VMA disagrees with arch::HEAP_VIRT_START.")
ASSERT(_heap_virt_end - _heap_virt_start == 16M,
       "orin.ld: HEAP_SIZE disagrees with arch::HEAP_SIZE.")

ASSERT(SIZEOF(.boot_params) == 48,
       "orin.ld: .boot_params is not 48 bytes; must match arch::BootParams.")
ASSERT(_boot_params_phys % 8 == 0,
       "orin.ld: .boot_params is not 8-byte aligned.")
ASSERT(_boot_params_phys < 0x80000000,
       "orin.ld: .boot_params is more than 2 GiB into the image.")

ASSERT(_kernel_got_start >= KERNEL_VMA,
       "orin.ld: .got is not inside the kernel image.")
ASSERT(_kernel_got_end - _kernel_got_start < 2M,
       "orin.ld: .got grew past 2 MiB.")
