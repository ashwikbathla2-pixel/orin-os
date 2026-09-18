# Orin OS — Boot Architecture

**Status:** M1 IMPLEMENTED (BIOS + UEFI via GRUB) · **Code:** [`boot/`](../boot), [`arch/x86_64/boot/boot.asm`](../arch/x86_64/boot/boot.asm)

---

## 1. The full pipeline

```text
 ①  Firmware (UEFI or BIOS/CSM)
        │  loads and executes the El Torito boot image / MBR
        ▼
 ②  GRUB 2                      boot/grub/grub.cfg
        │  parses multiboot2 header, loads kernel ELF segments,
        │  builds the multiboot2 information structure,
        │  enters 32-bit protected mode, jumps to header.entry_address
        ▼
 ③  arch/x86_64/boot/boot.asm   _boot_start  (32-bit)
        │  • verify multiboot2 magic, verify A20/protected mode
        │  • zero .bss
        │  • build boot page tables (2 MiB pages, first 1 GiB)
        │  • PAE → CR3 → EFER.LME → CR0.PG|WP
        │  • load 64-bit GDT, far-jump to long mode
        ▼
 ④  _long_mode_start            (64-bit)
        │  segments zeroed, boot stack set, multiboot info ptr → rdi
        ▼
 ⑤  _kstart → orin_kernel_main  (Rust, kernel/src/main.rs)
        │  see §4 for the ordered init sequence
        ▼
 ⑥  orin-init                   (M9) service supervision
        ▼
 ⑦  orin-displayd               (M8) compositor / window manager
        ▼
 ⑧  Orin Desktop → login screen → session
```

Steps ①–⑤ are real and tested today. Steps ⑥–⑧ are **DESIGNED**; the boot
test asserts ⑤ completed.

---

## 2. What GRUB gives the kernel

Orin uses the **Multiboot2** specification. GRUB is required to supply:

| Tag | Type | Use |
|---|---|---|
| Information structure base | — | passed in `%ebx`, page-aligned, valid ≥ 16 KiB |
| Boot command line | 1 | kernel parameters (`orin.log=debug`, `orin.single`, …) |
| Boot loader name | 2 | printed in the boot banner / crash reports |
| Memory map | 6 | **required** — drives the physical frame allocator |
| Framebuffer | 9 | **required** — physical address, size, pitch, bpp, colour mask |
| EFI memory map | 12 | used when booting UEFI; ignored otherwise |
| ACPI old/new RSDP | 14/15 | hardware discovery (M7) |
| Image load info | 3/4 | section addresses, used to compute the kernel's own extent |

Requesting a tag (`information_request`) makes GRUB **fail the boot** rather
than silently omitting it. Orin requests memory map, framebuffer, command line,
loader name and image load info. A silent "we'll just assume" is exactly the
kind of fake functionality Rule 1 forbids.

### 2.1 The multiboot2 header

Emitted by NASM into a dedicated, 8-byte-aligned section placed first by the
linker script:

```nasm
section .multiboot_header
header_start:
    dd  0xE85250D6                      ; multiboot2 magic
    dd  0                               ; architecture: i386 (32-bit protected mode)
    dd  header_end - header_start       ; total header length
    dd  0x100000000 - (0xE85250D6 + 0 + (header_end - header_start))   ; checksum

    ; -- optional: framebuffer (type 5) -----------------------------------
    dw  5 ; dw 0 ; dd 24
    dd 0  ; dd 0  ; dd 0    ; width/height/depth = 0 → GRUB picks text-or-gfx
    dd  0                   ; flags: 0 = let GRUB choose

    ; -- optional: entry address (type 3), NON-optional flag set -----------
    dw  3 ; dw 1 ; dd 12
    dd  _boot_start

    ; -- optional: information request (type 1) ---------------------------
    dw  1 ; dw 0 ; dd 8 + 5*4
    dd  1 ; dd 2 ; dd 6 ; dd 9 ; dd 3   ; cmdline, loader, mmap, framebuffer, load

    ; -- END (type 0) ------------------------------------------------------
    dw  0 ; dw 0 ; dd 8
header_end:
```

`make verify-header` disassembles and re-checks the emitted header's magic,
length and checksum from the built object file, so a hand-edit can't silently
produce an unbootable kernel that GRUB rejects with no explanation.

---

## 3. The 32 → 64 bit transition

This is the part most toy kernels skip by using a bootloader that does it for
them. Orin does it, because the kernel must understand the machine state it
inherits.

### 3.1 Boot page tables

Built statically in `.boot_page_tables` (4 KiB-aligned, zeroed by `.bss`
zeroing — the section is `NOBITS`):

```text
_boot_pml4 (PML4)
  [0]   ──► _boot_pdpt      identity map      0x00000000 .. 0x3FFFFFFF
  [511] ──► _boot_pdpt      higher-half alias 0xFFFFFFFF80000000 ..
_boot_pdpt (PDPT)
  [0]   ──► _boot_pd0       1 GiB  (2 MiB pages)
  [1]   ──► _boot_pd1       1 GiB  (2 MiB pages)   ← covers the kernel image
_boot_pd0/_pd1 (PD)
  [i]   ──► physical i * 2 MiB,  PS=1, PRESENT|WRITABLE
```

Both PML4 entries point at the *same* PDPT, so `0x0000_0000_0010_0000` and
`0xFFFF_FFFF_8010_0000` are aliases of the same physical page. That aliasing
is what lets the far jump to the higher-half virtual address succeed while the
instruction fetch is still coming from the identity mapping.

**Total boot coverage: 2 GiB.** QEMU is started with ≤ 1 GiB in M1; the frame
allocator refuses to hand out frames beyond the boot-mapped range and logs the
limit. Extending coverage is a PDPT-entry change, tracked as a known
limitation in [`ROADMAP.md`](ROADMAP.md) rather than papered over.

### 3.2 Enable sequence (exact, in order)

```text
1.  cli                            ; no interrupts until the IDT exists
2.  mov cr4, PAE                   ; CR4.PAE  — mandatory for long mode
3.  mov cr3, _boot_pml4            ; page table base
4.  mov ecx, 0xC0000080            ; MSR_EFER
    rdmsr / or eax,1<<8 / wrmsr    ; EFER.LME = 1
5.  mov eax, cr0
    or  eax, (1<<31)|(1<<16)       ; CR0.PG = 1, CR0.WP = 1
    mov cr0, eax
6.  lgdt [gdt64.pointer]
7.  jmp 0x08:_long_mode_start      ; far jump: reloads CS with a 64-bit code seg
8.  [bits 64] reload DS/ES/FS/GS/SS = 0x10
```

`CR0.WP` is set *at boot*, not later. Without it, the kernel can write to
read-only pages — which silently defeats every W^X guarantee the security model
promises. Setting it in the first 10 instructions makes the guarantee
structural.

### 3.3 Validating assumptions rather than trusting them

`boot.asm` checks before proceeding, and halts with a distinct ASCII code on
the VGA text buffer if a check fails:

| Check | Failure code | Meaning |
|---|---|---|
| `%eax == 0x36AD7B00` | `MB` | not booted by a multiboot2-compliant loader |
| `%ebx` sane (non-zero, < 1 MiB) | `BI` | information structure pointer invalid |
| CPUID available (ID flag toggle) | `CX` | CPU too old / CPUID disabled |
| Extended CPUID leaf 0x80000001 EDX bit 29 | `LM` | long mode unsupported |
| A20 gate | `A2` | A20 line stuck (would alias memory at 1 MiB boundaries) |

The A20 test writes `0x0000` to `0x500` and `0xFF` to `0x100500` and verifies
they differ. If they don't, A20 is off and every address above 1 MiB is
aliased — booting further would corrupt memory in ways that look random.

A failed check writes a two-character code to `0xB8000` in white-on-red and
executes `cli; hlt`. The QEMU test harness greps for these codes, so a boot
failure reports *why*.

---

## 4. Kernel init sequence (`orin_kernel_main`)

Ordered, and each step logs to serial on entry and exit. Order is not
arbitrary — dependencies are noted.

| # | Step | Depends on | Why here |
|---|---|---|---|
| 1 | `serial::init()` | ports only | First possible output. Everything after is debuggable. |
| 2 | `vga::init()` | identity-mapped `0xB8000` | Human-visible console. |
| 3 | Log banner + `abi_info` | 1,2 | Records build id, git hash, toolchain. |
| 4 | `cpuid::detect()` | CPUID | Feature gates for later steps (SSE2, x2APIC, hypervisor). |
| 5 | `long_mode::verify()` | CR0/CR3/CR4/EFER | Assert we really are in 64-bit paging mode; dump CR values. |
| 6 | `multiboot::parse()` | `%ebx` | Produces `BootInfo`: mmap, framebuffer, cmdline, loader. |
| 7 | `pmm::init(BootInfo)` | 6 | Frame allocator; **must** precede any allocation. |
| 8 | `vmm::init_kernel_space()` | 7 | Kernel-owned PML4; switch `CR3` off the boot tables. |
| 9 | `vmm::harden_boot_map()` | 8 | Identity map → supervisor-only, **NX**. W^X from boot onward. |
| 10 | `heap::init()` | 7,8 | Kernel heap; enables `alloc` (Vec/String/Box) in-kernel. |
| 11 | `gdt::init()`, `tss::init()` | 10 | 64-bit GDT + TSS with IST stacks. |
| 12 | `idt::init()` | 11 | 256 vectors, exception + IRQ handlers. |
| 13 | `pic::remap()` | 12 | IRQ0–15 → vectors 32–47, avoiding exception overlap. |
| 14 | `pit::init(1000)` | 13 | 1 kHz tick: monotonic clock + future scheduler tick. |
| 15 | `keyboard::init()` | 13 | PS/2 controller self-test, scancode set 1, IRQ1. |
| 16 | `selftest::run()` | all | In-kernel tests; results on serial, gate the ISO's boot claim. |
| 17 | Banner + subsystem table | all | The "Orin booted" artefact. |
| 18 | `idle()` | — | `sti; hlt` loop. In M4 this becomes the idle thread. |

Note step 9: the identity map is **hardened, not removed**, in M1. Removing
`PML4[0]` requires the multiboot info, page tables and boot stack to all be
relocated into the higher half first. Hardening (drop user access, set NX,
keep supervisor RW) removes the *security* problem immediately; the *cleanliness*
problem is scheduled for M4 and recorded as such. Pretending the identity map
is gone would violate Rule 1.

---

## 5. Boot parameters

Parsed from the multiboot2 command line (`grub.cfg` sets `orin.log=info`):

```text
orin.log=<trace|debug|info|warn|error>   kernel log level
orin.console=<serial|vga|both>           output targets
orin.selftest=<on|off>                   run step 16
orin.panic=<halt|reboot|triple>          panic action
orin.single                              boot without SMP bring-up
orin.memlimit=<MiB>                      cap the frame allocator (test use)
orin.nx=<on|off>                         NX enforcement (default on; off = loud warning)
```

Unknown parameters are **logged and ignored**, never fatal: a typo in
`grub.cfg` must not brick the boot.

---

## 6. ISO construction

```bash
make iso
#  cargo build --release --target x86_64-unknown-none -Z build-std=...
#  →  build/orin_kernel.elf
#  nasm -f elf64 arch/x86_64/boot/boot.asm -o build/boot.o     (linked in)
#  mkdir -p build/isofiles/boot/grub
#  cp build/orin_kernel.elf build/isofiles/boot/orin_kernel.elf
#  cp boot/grub/grub.cfg     build/isofiles/boot/grub/grub.cfg
#  grub-mkrescue -o build/orin.iso build/isofiles
```

`grub-mkrescue` produces a **hybrid** image: El Torito for UEFI, and a bootable
MBR (`boot_hybrid.img` from `grub-pc-bin`) for BIOS. QEMU is started with
`-cdrom build/orin.iso` and boots via SeaBIOS by default; `make run-uefi` adds
`-bios OVMF.fd` when an OVMF image is present.

The kernel is loaded from `/boot/orin_kernel.elf` inside the ISO by
`multiboot2 /boot/orin_kernel.elf` in `grub.cfg`.

---

## 7. Later boot paths (DESIGNED)

| Path | Milestone | Notes |
|---|---|---|
| **Limine** protocol | M9 | Additive: a second `boot/limine.asm` entry producing the same `BootInfo`. Limine does the long-mode transition, which is convenient but must not be the *only* way in. |
| **Direct UEFI (no GRUB)** | M11 | Kernel becomes an EFI application; needs a PE/COFF section wrapper and `efi_main`. Removes a dependency on GRUB for Orin-installed systems. |
| **Secure Boot** | M14 | Requires a signed shim or an Orin-enrolled key; the ELF must be wrapped as PE/COFF. Blocked on the UEFI path. |
| **A/B slot boot + rollback** | M13 | Two kernel slots, `orin-updated` writes the inactive slot, `orinboot` marks it trial; a failed boot auto-reverts. |
| **Measured boot / TPM** | M14 | PCR extension at each stage; attestation via `orin-securityd`. |
| **Fast boot (kexec-style)** | M18 | Skip firmware re-init on reboot; requires the UEFI path first. |

Each is recorded with its blocker so nobody assumes it's "just not done yet".
