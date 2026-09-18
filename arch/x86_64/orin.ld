/* =============================================================================
   Orin OS — x86_64 kernel linker script
   arch/x86_64/orin.ld

   This file IS the kernel memory map. docs/MEMORY.md §2 documents the same
   layout; if they disagree, treat it as a bug and fix both.

   ---------------------------------------------------------------------------
   PROBLEM 1 — TWO ADDRESS SPACES IN ONE IMAGE
   ---------------------------------------------------------------------------
   Kernel linked higher-half; GRUB enters 32-bit protected mode, paging OFF.
   boot.asm identity-maps phys 0..2 GiB at BOTH va 0..2 GiB AND
   va KERNEL_VMA..KERNEL_VMA+2GiB (2 MiB large pages). Therefore:

       virt = phys + KERNEL_VMA     (boot alias, always)

   Every kernel section MUST satisfy VMA = LMA + KERNEL_VMA. If VMA is
   KERNEL_VMA+0 while LMA is 0x400000, the CPU fetches from phys 0 and #UDs.

   ---------------------------------------------------------------------------
   PROBLEM 2 — SECTIONS MUST NOT SHARE A 2 MiB PAGE (W^X)
   ---------------------------------------------------------------------------
   VMM maps each section with different permissions. Sections that share a
   2 MiB VA region cannot have different perms. Therefore each section's
   LMA is 2 MiB-aligned (and VMA = LMA + KERNEL_VMA is therefore also
   2 MiB-aligned and disjoint).

   ---------------------------------------------------------------------------
   PROBLEM 3 — BOOT SECTIONS: VMA == LMA
   ---------------------------------------------------------------------------
   Paging is off at entry. GRUB loads at LMA and jumps to VMA. Use no AT()
   for boot sections so LMA defaults to VMA.

   ---------------------------------------------------------------------------
   PROBLEM 4 — GRUB PT_LOAD PhysAddr ranges must not overlap
   ---------------------------------------------------------------------------
   NOBITS sections get explicit AT(_lma) after all PROGBITS so they are not
   merged into a prior PT_LOAD whose MemSiz would swallow later LMAs.
   .debug_gdb_scripts is SHF_ALLOC and must be discarded.
   ========================================================================== */

OUTPUT_ARCH(i386:x86-64)
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_boot_start)

KERNEL_VMA = 0xFFFFFFFF80000000;
HEAP_VMA   = 0xFFFFFFFF00000000;
HEAP_SIZE  = 16M;
BOOT_MAPPED_BYTES = 2048M;   /* 2 GiB; rust-lld rejects the G suffix */
EXPECTED_BOOT_BSS_SIZE = 144K;  /* 4*4K tables + 64K boot stack + 64K kernel stack */

SECTIONS
{
    . = 1M;
    _image_phys_start = .;

    /* =================================================================
       (A) BOOT SECTIONS — VMA == LMA
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
       (B) KERNEL SECTIONS
       VMA = LMA + KERNEL_VMA  (boot alias)
       LMA 2 MiB-aligned per section (W^X disjointness)
       ================================================================= */

    _lma = _image_phys_boot_end;   /* already 2 MiB-aligned */

    /* .text */
    .text (_lma + KERNEL_VMA) : AT(_lma) {
        _kernel_text_start = .;
        KEEP(*(SORT_NONE(.text .text.*)))
        . = ALIGN(16);
        _kernel_text_end = .;
    }
    ASSERT(SIZEOF(.text) <= 2M, "orin.ld: .text exceeds its 2 MiB region.")
    _lma = ALIGN(_lma + SIZEOF(.text), 2M);

    /* .rodata */
    .rodata (_lma + KERNEL_VMA) : AT(_lma) {
        _kernel_rodata_start = .;
        KEEP(*(SORT_NONE(.rodata .rodata.*)))
        . = ALIGN(16);
        _kernel_rodata_end = .;
    }
    ASSERT(SIZEOF(.rodata) <= 2M, "orin.ld: .rodata exceeds its 2 MiB region.")
    _lma = ALIGN(_lma + SIZEOF(.rodata), 2M);

    /* .data */
    .data (_lma + KERNEL_VMA) : AT(_lma) {
        _kernel_data_start = .;
        KEEP(*(SORT_NONE(.data .data.*)))
        . = ALIGN(16);
        _kernel_data_end = .;
    }
    ASSERT(SIZEOF(.data) <= 2M, "orin.ld: .data exceeds its 2 MiB region.")
    _lma = ALIGN(_lma + SIZEOF(.data), 2M);

    /* Unwind + GOT: still PROGBITS, pack tightly after .data's region.
       They share .data's permission class (R-- / RW- via VMM's bss extent)
       and must not start a new 2 MiB region requirement for W^X of code. */
    .eh_frame (_lma + KERNEL_VMA) : AT(_lma) {
        _kernel_eh_frame_start = .;
        *(.eh_frame .eh_frame_hdr .eh_frame.*)
    }
    _lma += SIZEOF(.eh_frame);

    .gcc_except_table (_lma + KERNEL_VMA) : AT(_lma) {
        *(.gcc_except_table .gcc_except_table.*)
    }
    _lma += SIZEOF(.gcc_except_table);

    _lma = ALIGN(_lma, 8);
    .got (_lma + KERNEL_VMA) : AT(_lma) {
        _kernel_got_start = .;
        *(.got .got.* .got.plt)
        . = ALIGN(8);
        _kernel_got_end = .;
    }
    _lma += SIZEOF(.got);

    /* Boot-params: VMA = phys + KERNEL_VMA (readable via boot alias). */
    _boot_params_phys = ALIGN(_lma, 8);
    .boot_params (_boot_params_phys + KERNEL_VMA) : AT(_boot_params_phys) {
        QUAD(_kernel_phys_start)
        QUAD(_kernel_phys_end)
        QUAD(_boot_bss_phys_start)
        QUAD(_boot_bss_phys_end)
        QUAD(_heap_phys_start)
        QUAD(_heap_phys_end)
    }
    _lma = _boot_params_phys + SIZEOF(.boot_params);

    /* .bss: own 2 MiB-aligned phys region + own PT_LOAD. */
    _lma = ALIGN(_lma, 2M);
    .bss (_lma + KERNEL_VMA) (NOLOAD) : AT(_lma) {
        _kernel_bss_start = .;
        KEEP(*(SORT_NONE(.bss .bss.*)))
        KEEP(*(COMMON))
        . = ALIGN(16);
        _kernel_bss_end = .;
    }
    _lma = LOADADDR(.bss) + SIZEOF(.bss);

    _kernel_virt_start = _kernel_text_start;
    /* Cover .bss and any PROGBITS that landed after .data in the same or next
       region (.eh_frame/.got). */
    _kernel_virt_end = MAX(ALIGN(_kernel_bss_end, 4K), ALIGN(_kernel_got_end, 4K));

    /* Heap: phys after .bss, virt at HEAP_VMA (separate PML4 subtree). */
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

    _boot_stack_top_hi   = _boot_stack_top   + KERNEL_VMA;
    _kernel_stack_top_hi = _kernel_stack_top + KERNEL_VMA;

    /DISCARD/ : {
        *(.note .note.*)
        *(.comment)
        *(.debug_gdb_scripts)
    }
}

/* =============================================================================
   LINK-TIME ASSERTIONS
   ============================================================================= */

ASSERT(_boot_bss_phys_size == EXPECTED_BOOT_BSS_SIZE,
       "orin.ld: .boot_bss size disagrees with boot.asm.")

ASSERT(_image_phys_boot_end <= BOOT_MAPPED_BYTES,
       "orin.ld: boot image past boot.asm identity map.")

/* Boot alias invariant: VMA == LMA + KERNEL_VMA for every kernel section. */
ASSERT(ADDR(.text)   == LOADADDR(.text)   + KERNEL_VMA, "orin.ld: .text VMA != LMA + KERNEL_VMA.")
ASSERT(ADDR(.rodata) == LOADADDR(.rodata) + KERNEL_VMA, "orin.ld: .rodata VMA != LMA + KERNEL_VMA.")
ASSERT(ADDR(.data)   == LOADADDR(.data)   + KERNEL_VMA, "orin.ld: .data VMA != LMA + KERNEL_VMA.")
ASSERT(ADDR(.bss)    == LOADADDR(.bss)    + KERNEL_VMA, "orin.ld: .bss VMA != LMA + KERNEL_VMA.")
ASSERT(ADDR(.got)    == LOADADDR(.got)    + KERNEL_VMA, "orin.ld: .got VMA != LMA + KERNEL_VMA.")
ASSERT(ADDR(.boot_params) == _boot_params_phys + KERNEL_VMA,
       "orin.ld: .boot_params VMA != phys + KERNEL_VMA.")

/* 2 MiB alignment of kernel section LMAs (and therefore VMAs). */
ASSERT(LOADADDR(.text)   % 2M == 0, "orin.ld: .text LMA not 2 MiB aligned.")
ASSERT(LOADADDR(.rodata) % 2M == 0, "orin.ld: .rodata LMA not 2 MiB aligned.")
ASSERT(LOADADDR(.data)   % 2M == 0, "orin.ld: .data LMA not 2 MiB aligned.")
ASSERT(LOADADDR(.bss)    % 2M == 0, "orin.ld: .bss LMA not 2 MiB aligned.")

/* LMA packing / non-overlap of PROGBITS. */
ASSERT(LOADADDR(.multiboot_header) == _image_phys_start,
       "orin.ld: .multiboot_header not at image start.")
ASSERT(LOADADDR(.text) == _image_phys_boot_end,
       "orin.ld: .text LMA does not continue from boot image end.")
ASSERT(LOADADDR(.rodata) >= LOADADDR(.text) + SIZEOF(.text),
       "orin.ld: .rodata LMA overlaps .text.")
ASSERT(LOADADDR(.data) >= LOADADDR(.rodata) + SIZEOF(.rodata),
       "orin.ld: .data LMA overlaps .rodata.")
ASSERT(LOADADDR(.eh_frame) >= LOADADDR(.data) + SIZEOF(.data),
       "orin.ld: .eh_frame LMA overlaps .data.")
ASSERT(LOADADDR(.boot_params) >= LOADADDR(.got) + SIZEOF(.got),
       "orin.ld: .boot_params LMA overlaps .got.")
ASSERT(LOADADDR(.bss) >= LOADADDR(.boot_params) + SIZEOF(.boot_params),
       "orin.ld: .bss LMA overlaps .boot_params.")
ASSERT(_heap_phys_start >= LOADADDR(.bss) + SIZEOF(.bss),
       "orin.ld: heap LMA overlaps .bss.")

ASSERT(_kernel_phys_end - _image_phys_start <= BOOT_MAPPED_BYTES,
       "orin.ld: kernel image exceeds 2 GiB boot alias.")
ASSERT(_heap_phys_end <= BOOT_MAPPED_BYTES,
       "orin.ld: heap outside boot alias.")
ASSERT(_heap_phys_start % 2M == 0,
       "orin.ld: heap phys base not 2 MiB aligned.")

ASSERT(_heap_virt_start == 0xFFFFFFFF00000000,
       "orin.ld: HEAP_VMA disagrees with arch::HEAP_VIRT_START.")
ASSERT(_heap_virt_end - _heap_virt_start == 16M,
       "orin.ld: HEAP_SIZE disagrees with arch::HEAP_SIZE.")

ASSERT(SIZEOF(.boot_params) == 48,
       "orin.ld: .boot_params is not 48 bytes.")
ASSERT(_boot_params_phys % 8 == 0,
       "orin.ld: .boot_params not 8-byte aligned.")
ASSERT(_boot_params_phys < 0x80000000,
       "orin.ld: .boot_params past 2 GiB.")
