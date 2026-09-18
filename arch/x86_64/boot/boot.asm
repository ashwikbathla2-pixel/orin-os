; =============================================================================
;  Orin OS — x86_64 boot stub
;  arch/x86_64/boot/boot.asm
;
;  Executed by GRUB 2 in 32-bit protected mode, paging DISABLED.
;  Responsibilities, in order:
;    1. validate we were entered by a Multiboot2-compliant loader
;    2. validate CPUID and long-mode support
;    3. validate the A20 gate is enabled
;    4. zero .bss
;    5. build boot page tables (identity + higher-half alias, 2 MiB pages)
;    6. PAE -> CR3 -> EFER.LME -> CR0.PG|WP
;    7. load a 64-bit GDT, far-jump into long mode
;    8. hand off to Rust: orin_kernel_main(multiboot_info_phys, boot_params_phys)
;
;  Any failed validation writes a 2-char code to the VGA text buffer in
;  white-on-red and halts. The QEMU boot test greps for these codes so a
;  failure reports WHY instead of looking like a hang.
;
;  Failure codes:  MB  not multiboot2     BI  bad info pointer
;                  CX  no CPUID           LM  no long mode
;                  A2  A20 gate disabled
;
;  NOTE 1: no RIP-relative addressing may be used before `bits 64` — we are in
;  32-bit mode until the far jump. All references here are absolute.
;
;  NOTE 2: labels are file-scope absolutes (`_fail_mb`), NOT NASM local labels
;  (`.fail_mb`). A local label binds to the most recent non-local label, and
;  `_boot_start` is declared `global`, so a `.fail_mb` reference before the
;  `.fail_mb:` definition resolves to `_boot_start.fail_mb` — a different
;  symbol — and assembly fails with "symbol not defined". Using absolute labels
;  removes the scoping hazard entirely.
; =============================================================================

; -----------------------------------------------------------------------------
; Multiboot2 header. Must be 8-byte aligned and within the first 32 KiB of the
; OS image; the linker script places this section first to guarantee both.
; -----------------------------------------------------------------------------
;  NASM section syntax: attributes are space-separated, NOT comma-separated.
;  `section .foo, align=8` silently creates a section literally NAMED
;  ".foo," — which the linker script's *(.multiboot_header) never matches, so
;  the header is dropped and GRUB reports "not a Multiboot2 image". Verified by
;  `make verify-header`, which checks the section name in the built object.
section .multiboot_header align=8
header_start:
    dd  0xE85250D6                                      ; magic
    dd  0                                               ; arch: i386 (prot32)
    dd  header_end - header_start                       ; header length
    dd  0x100000000 - (0xE85250D6 + 0 + (header_end - header_start))

    ; ---- header tag type 5: framebuffer request ---------------------------
    ;  (Header tag numbering per Multiboot2 spec section 3.1. Header tags and
    ;   information-structure tags use DIFFERENT number spaces; this is tag 5
    ;   in the header, and GRUB reports the result as info tag 9. Confusing the
    ;   two is a classic silent-boot-failure, hence the explicit note.)
    ;
    ;  width/height/depth = 0 with flags = 0 means "GRUB, choose a mode the
    ;  firmware supports and tell me what you chose". Orin reads the result at
    ;  runtime rather than hard-coding a mode it cannot know the display
    ;  supports. Requesting a fixed mode here would boot fine in QEMU and fail
    ;  on real hardware.
    align 8
    dw  5                                               ; type: framebuffer
    dw  0                                               ; flags: optional
    dd  24                                              ; size
    dd  0, 0, 0                                         ; width, height, depth
    dd  0                                               ; framebuffer type flags

    ; ---- header tag type 3: entry address (NON-optional) ------------------
    ;  Without this tag GRUB jumps to the ELF e_entry, which is the
    ;  higher-half VIRTUAL address 0xFFFFFFFF80100000 - unreachable with
    ;  paging disabled. This tag gives GRUB the physical entry point instead.
    align 8
    dw  3                                               ; type: entry_address
    dw  1                                               ; flags: NON-optional
    dd  12                                              ; size
    dd  _boot_start                                     ; entry (physical)

    ; ---- header tag type 1: information request ---------------------------
    ;  Requesting a tag makes GRUB FAIL THE BOOT rather than silently omit it.
    ;  A kernel that "just assumes" the memory map is present is a kernel that
    ;  corrupts memory on firmware that disagrees. We request exactly what we
    ;  parse, and nothing we would ignore:
    ;      1 = boot command line    2 = boot loader name
    ;      5 = framebuffer info     6 = memory map
    align 8
    dw  1                                               ; type: info_request
    dw  0                                               ; flags: optional
    dd  8 + (4 * 4)                                     ; size
    dd  1                                               ;   command line
    dd  2                                               ;   loader name
    dd  5                                               ;   framebuffer
    dd  6                                               ;   memory map

    ; ---- tag 0: END -------------------------------------------------------
    align 8
    dw  0
    dw  0
    dd  8
header_end:

; =============================================================================
section .boot_text progbits alloc exec align=16
global _boot_start
global _boot_bss_start
global _boot_bss_end
extern orin_kernel_main
; Defined by orin.ld, not by this file: it is the physical address of the
; `.boot_params` block the linker script fills with the values Rust needs but
; cannot reference as symbols (see that section's comment). Declaring it extern
; lets the 32-bit code below take its address with a plain absolute operand,
; which is exactly what 32-bit protected mode is good at and what the 64-bit
; kernel code model is not.
extern _boot_params_phys

bits 32
_boot_start:
    cli                                                 ; no IDT yet
    cld                                                 ; ABI: forward strings

    ; -- 1. Multiboot2 magic -------------------------------------------------
    ;  GRUB enters with:  eax = 0x36D76289, ebx = info structure physical addr.
    ;  BOTH must be saved/checked BEFORE eax is clobbered. A previous version
    ;  did `xor eax, eax` first "to clear a scratch register", which made the
    ;  magic compare always fail, wrote "MB" to VGA, and halted — with no
    ;  serial output, because serial is initialised by Rust after this point.
    ;  The QEMU boot test then reported an empty serial log and nothing else.
    ;  Save ebx first (the info pointer survives regardless of the magic
    ;  check's outcome, and the failure path may still want it), then compare
    ;  the live eax against the Multiboot2 magic.
    mov  [_boot_info_phys], ebx
    cmp  eax, 0x36D76289
    jne  _fail_mb

    ; -- 2. information pointer sanity --------------------------------------
    ;  Must be non-zero. Multiboot2 does NOT restrict the info structure to
    ;  the first 1 MiB (that was a Multiboot1 real-mode constraint); GRUB2
    ;  routinely places it above 1 MiB. Rejecting >= 1 MiB was a boot-stopper:
    ;  the magic check passed, this one failed, and the stub wrote "BI" to VGA
    ;  and halted with no serial output.
    ;
    ;  We do require it to sit inside the 2 GiB the stub identity-maps, so the
    ;  kernel can read it through the boot alias before the VMM is up. Anything
    ;  past that is unreachable and is a loader bug we cannot recover from.
    mov  eax, [_boot_info_phys]
    test eax, eax
    jz   _fail_bi
    cmp  eax, 0x80000000          ; 2 GiB = BOOT_MAPPED_BYTES
    jae  _fail_bi

    ; -- 3. CPUID available? (toggle the ID flag, bit 21 of EFLAGS) ---------
    pushfd
    pop  eax
    mov  ecx, eax
    xor  eax, 1 << 21
    push eax
    popfd
    pushfd
    pop  eax
    push ecx
    popfd
    xor  eax, ecx
    jz   _fail_cx                                       ; bit did not toggle

    ; -- 4. long mode supported? (extended leaf 0x80000001, EDX bit 29) -----
    mov  eax, 0x80000000
    cpuid
    cmp  eax, 0x80000001
    jb   _fail_lm
    mov  eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz   _fail_lm

    ; -- 5. A20 gate ---------------------------------------------------------
    ;  Write distinct values to 0x500 and 0x100500. If A20 is masked the two
    ;  addresses alias and the read-back matches: every address above 1 MiB
    ;  would silently wrap, and paging setup would corrupt memory in ways that
    ;  look random. Test, don't assume.
    mov  word [0x500],   0x0000
    mov  word [0x100500], 0x00FF
    movzx eax, word [0x500]
    cmp  eax, 0x0000
    jne  _fail_a20
    movzx eax, word [0x100500]
    cmp  eax, 0x00FF
    jne  _fail_a20

    ; -- 6. zero .bss --------------------------------------------------------
    ;  Page tables and the boot stack live here; they must start at zero
    ;  because the PDPT/PD fill loop below only ORs flag bits in.
    ;  PHYSICAL symbols: the boot page tables and boot stack live in .boot_bss,
    ;  which the linker script keeps below the higher-half jump so that this
    ;  32-bit code can address it directly.
    ;  Both labels live in THIS file's .boot_bss section, so their difference
    ;  is an assembly-time constant — no relocation, no dependency on the
    ;  linker script's `_boot_bss_phys_*` symbols. Deriving the size from
    ;  linker symbols instead would need a 64-bit immediate that NASM cannot
    ;  encode in 32-bit mode, for no benefit.
    mov  edi, _boot_bss_start
    mov  ecx, (_boot_bss_end - _boot_bss_start)
    shr  ecx, 2                                         ; dword count
    xor  eax, eax
    rep  stosd

    ; -- 7. build boot page tables ------------------------------------------
    ;  Address translation under 4-level paging, for the two halves we care
    ;  about (each PD covers 1 GiB with 512 x 2 MiB large pages):
    ;
    ;    identity 0 .. 2 GiB:
    ;      PML4[0]   -> PDPT
    ;      PDPT[0]   -> PD0   (phys 0 .. 1 GiB)
    ;      PDPT[1]   -> PD1   (phys 1 .. 2 GiB)
    ;
    ;    KERNEL_VMA = 0xFFFFFFFF80000000 .. +2 GiB:
    ;      PML4[511] -> same PDPT          (covers 0xFFFFFF8000000000 .. end)
    ;      PDPT[510] -> PD0                (VMA 0xFFFFFFFF80000000 .. +1 GiB)
    ;      PDPT[511] -> PD1                (VMA 0xFFFFFFFFC0000000 .. +1 GiB)
    ;
    ;  Why PDPT[510], not PDPT[0]: PML4[511] alone only selects the top 512 GiB
    ;  of the canonical higher half (0xFFFFFF8000000000 ..). KERNEL_VMA sits
    ;  510 GiB into that window, so it is PDPT entry 510, not 0. A previous
    ;  version installed only PDPT[0]/[1] and left [510]/[511] empty; the stub
    ;  then far-jumped into long mode, called orin_kernel_main at
    ;  0xFFFFFFFF80000020, took a #PF on the unmapped page, double-faulted
    ;  (no IDT yet), and triple-faulted — with no serial output, because Rust
    ;  never ran. QEMU's -d int log named CR2=0xFFFFFFFF80000020; that is how
    ;  this was found.
    ;
    ;  Both halves share the same PD0/PD1, so physical 0..2 GiB is reachable
    ;  from either VA. That alias is load-bearing: the far jump lands in the
    ;  higher half while the instruction bytes still live at low physical
    ;  addresses, and Rust later reads the Multiboot2 info structure and the
    ;  .boot_params block through the higher-half alias of those same pages.
    ;
    ;  Total boot coverage: 2 GiB. The frame allocator refuses frames past it.
    mov  edi, _boot_pml4
    mov  eax, _boot_pdpt
    or   eax, 0x3                                       ; PRESENT | WRITABLE
    mov  [edi + 0*8],   eax                             ; identity PML4[0]
    mov  [edi + 511*8], eax                             ; higher-half PML4[511]

    mov  edi, _boot_pdpt
    mov  eax, _boot_pd0
    or   eax, 0x3
    mov  [edi + 0*8],   eax                             ; identity  0..1 GiB
    mov  [edi + 510*8], eax                             ; KERNEL_VMA .. +1 GiB
    mov  eax, _boot_pd1
    or   eax, 0x3
    mov  [edi + 1*8],   eax                             ; identity  1..2 GiB
    mov  [edi + 511*8], eax                             ; KERNEL_VMA+1G .. +2G

    ;  PD0: entries 0..511 -> 0 .. 1 GiB
    mov  edi, _boot_pd0
    mov  eax, 0x83                                      ; P | W | PS (2 MiB)
    mov  ecx, 0
_fill_pd0:
    mov  [edi + ecx*8], eax
    add  eax, 0x200000
    inc  ecx
    cmp  ecx, 512
    jne  _fill_pd0

    ;  PD1: entries 0..511 -> 1 GiB .. 2 GiB
    mov  edi, _boot_pd1
    mov  eax, 0x40000083                                ; base = 1 GiB
    mov  ecx, 0
_fill_pd1:
    mov  [edi + ecx*8], eax
    add  eax, 0x200000
    inc  ecx
    cmp  ecx, 512
    jne  _fill_pd1

    ; -- 8. enable PAE, load CR3, enable long mode, enable paging -----------
    mov  eax, cr4
    or   eax, 1 << 5                                    ; CR4.PAE
    mov  cr4, eax

    mov  eax, _boot_pml4
    mov  cr3, eax

    mov  ecx, 0xC0000080                                ; MSR EFER
    rdmsr
    or   eax, 1 << 8                                    ; EFER.LME
    wrmsr

    mov  eax, cr0
    or   eax, (1 << 31) | (1 << 16)                     ; CR0.PG | CR0.WP
    mov  cr0, eax
    ;  CR0.WP is set HERE, in the first dozen instructions, not later in Rust.
    ;  Without WP the kernel can write to read-only pages, which silently
    ;  defeats every W^X guarantee the security model claims. Making it
    ;  structural means no future code path can forget it.

    ; -- 9. load 64-bit GDT and far-jump into long mode ---------------------
    lgdt [gdt64.pointer]
    jmp  0x08:_long_mode_start                          ; reloads CS

; =============================================================================
bits 64
_long_mode_start:
    ;  Reload all data segments with the 64-bit kernel data selector.
    mov  ax, 0x10
    mov  ds, ax
    mov  es, ax
    mov  fs, ax
    mov  gs, ax
    mov  ss, ax

    ;  Boot stack: the top of the 16 KiB stack boot.asm reserves in .boot_bss.
    ;  It is NOT in the 0x90000..0x9FFFF range the Multiboot2 spec suggests for
    ;  a loader-provided stack, because this stub allocates its own inside the
    ;  kernel image; orin.ld places .boot_bss at a 2 MiB-aligned physical
    ;  address and asserts its size matches what this file reserves.
    mov  rsp, _boot_stack_top
    and  rsp, ~0xF                                      ; SysV: 16-byte align

    ;  Hand off. Two arguments, both PHYSICAL addresses:
    ;    rdi = Multiboot2 information structure (GRUB left it in ebx)
    ;    rsi = `.boot_params`, the linker-filled block of physical addresses
    ;
    ;  rsi exists because the kernel is linked higher-half with
    ;  -C code-model=kernel, under which every symbol reference is RIP-relative
    ;  and reaches only +/-2 GiB. The physical addresses Rust needs (~0x200000
    ;  for the boot page tables, ~0x600000 for the heap) are about 2 GiB away in
    ;  the other direction, so they cannot be symbols at all — they have to
    ;  arrive as data. orin.ld writes them into .boot_params and this stub, which
    ;  runs in 32-bit mode where a low absolute address is the natural thing to
    ;  encode, passes the block's address along.
    ;
    ;  rust-lld cannot compute the higher-half alias for us either: it truncates
    ;  symbol arithmetic, so `_boot_params + KERNEL_VMA` in a linker script comes
    ;  out as a 32-bit value. That is why the alias is formed in Rust, at run
    ;  time, by arch::set_boot_params.
    ;
    ;  `mov esi, imm32` zero-extends into rsi in long mode, which is what makes
    ;  a 32-bit absolute operand usable as a 64-bit physical address here.
    mov  edi, [_boot_info_phys]
    mov  esi, _boot_params_phys
    mov  rax, qword orin_kernel_main
    call rax

    ;  orin_kernel_main never returns. If it ever does, that is a bug, and we
    ;  want it to be a *loud* bug rather than a silent reboot.
    mov  rax, qword _kpanic_halt
    call rax
_hang:
    cli
    hlt
    jmp  _hang

; =============================================================================
;  Failure paths. Write a 2-char code to the top-left of the VGA text buffer in
;  white-on-red, then halt. No serial here: the UART is not initialised yet.
; =============================================================================
bits 32
_fail_mb:
    mov  edi, fail_mb_code
    jmp  _die
_fail_bi:
    mov  edi, fail_bi_code
    jmp  _die
_fail_cx:
    mov  edi, fail_cx_code
    jmp  _die
_fail_lm:
    mov  edi, fail_lm_code
    jmp  _die
_fail_a20:
    mov  edi, fail_a20_code
_die:
    mov  esi, 0xB8000
    mov  ah, 0x4F                                       ; white on red
    mov  al, [edi]
    mov  [esi], ax
    mov  al, [edi + 1]
    mov  [esi + 2], ax
    mov  al, [edi + 2]
    mov  [esi + 4], ax
    mov  al, [edi + 3]
    mov  [esi + 6], ax
_halt32:
    cli
    hlt
    jmp  _halt32

; =============================================================================
section .boot_rodata progbits alloc align=16
fail_mb_code:  db "MB: not booted by a Multiboot2 loader", 0
fail_bi_code:  db "BI: bad Multiboot2 info pointer", 0
fail_cx_code:  db "CX: CPUID unavailable", 0
fail_lm_code:  db "LM: long mode unsupported", 0
fail_a20_code: db "A2: A20 gate disabled", 0
_msg_returned: db "orin_kernel_main returned", 0

; -----------------------------------------------------------------------------
;  64-bit GDT. Segment limits/bases are ignored in long mode; what matters is
;  the L (long) and D/B bits and the privilege level in the selector.
;    0x00  null
;    0x08  kernel code  ring 0  (L=1, D=0)
;    0x10  kernel data  ring 0
;    0x18  user data    ring 3  <- data BEFORE code for sysret compatibility
;    0x20  user code    ring 3  (L=1, D=0)
;    0x28  TSS          ring 0  (16 bytes, filled in at runtime by Rust)
; -----------------------------------------------------------------------------
section .boot_gdt progbits alloc align=16
gdt64:
    dq 0x0000000000000000                               ; 0x00 null
    dq 0x00209A0000000000                               ; 0x08 kcode
    dq 0x0000920000000000                               ; 0x10 kdata
    dq 0x0000F20000000000                               ; 0x18 udata
    dq 0x0020FA0000000000                               ; 0x20 ucode
gdt64.tss_slot:
    dq 0                                                ; 0x28 TSS low
    dq 0                                                ; 0x30 TSS high
gdt64.end:
gdt64.pointer:
    dw gdt64.end - gdt64 - 1
    dq gdt64

global gdt64.tss_slot
global gdt64.pointer

; =============================================================================
;  Boot-time mutable state. Physical addresses only — no virtual address is
;  valid yet.
; =============================================================================
section .boot_data progbits alloc write align=16
_boot_info_phys: dd 0

; =============================================================================
;  .bss: page tables (24 KiB) + boot stack (16 KiB) + kernel stack (32 KiB).
;  Zeroed by step 6 above. Marked NOBITS by the linker script.
; =============================================================================
section .boot_bss nobits alloc write align=4096
align 4096
_boot_bss_start:
global _boot_pml4
_boot_pml4:  resb 4096
align 4096
_boot_pdpt:  resb 4096
align 4096
_boot_pd0:   resb 4096
align 4096
_boot_pd1:   resb 4096
align 4096
_boot_stack_bottom: resb 16384
global _boot_stack_top
_boot_stack_top:
align 16
;  The kernel switches to this stack once the heap and VMM exist. It is
;  allocated in .bss rather than on the heap so that a heap failure during
;  early init still has somewhere to run.
global _kernel_stack_bottom
_kernel_stack_bottom: resb 32768
global _kernel_stack_top
_kernel_stack_top:
align 4096
_boot_bss_end:

; =============================================================================
;  Called from Rust if _kstart ever falls through. Declared here so the symbol
;  is resolvable without a second assembly pass.
; =============================================================================
section .boot_text progbits alloc exec align=16
bits 64
global _kpanic_halt
_kpanic_halt:
    cli
_halt64: hlt
    jmp _halt64
