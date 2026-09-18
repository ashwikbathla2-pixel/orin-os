//! The M1 kernel init sequence.
//!
//! This module lives in the **library** crate, not in `src/main.rs`. The bin
//! target is a ~30-line linker shim (`fn main()` that calls
//! [`orin_kernel_main`]) because that is the only thing that must be in the bin:
//! the ELF entry symbol. Keeping the sequence here means it is compiled, type
//! checked and unit-testable as part of the lib, and `src/main.rs` stays small
//! enough to audit in one screen.
//!
//! ## Why [`kernel_main`] is an ordinary Rust function
//!
//! It is deliberately *not* `#[unsafe(no_mangle)] pub extern "C"`. It used to be,
//! and that produced a kernel that linked cleanly, passed every layout
//! assertion, and then died before its first instruction: `src/main.rs` exports
//! the ABI symbol `orin_kernel_main`, and this module exported one with the same
//! name. The linker merged them, so the shim's call resolved to *itself* —
//!
//! ```text
//! ffffffff80000020 <orin_kernel_main>:
//!     push %rbp ; mov %rsp,%rbp ; sub $0x10,%rsp
//!     mov  %rdi,-0x10(%rbp) ; mov %rsi,-0x8(%rbp)
//!     call ffffffff80000020 <orin_kernel_main>     <-- itself
//! ```
//!
//! Infinite recursion, stack overflow, double fault, no output. Nothing in the
//! build reports it, because a duplicate `no_mangle` symbol across a bin and its
//! own lib is not a Rust error — they are separate crates, and the collision is
//! resolved silently at link time.
//!
//! **Rule:** `src/main.rs` is the only file that may carry
//! `#[unsafe(no_mangle)]`. Everything in the library is reached through normal
//! Rust paths, which are namespaced by crate and therefore cannot collide.
//! `make verify-elf` disassembles the entry point and fails if it calls itself,
//! so a reintroduced collision is caught by the build rather than by a hang.
//!
//! The order of operations below is **not** arbitrary and is documented step by
//! step in `docs/BOOT.md` §4. Each step has dependencies that make its position
//! load-bearing; the comments say what breaks if you move it.
//!
//! M1 ends in an interactive loop rather than a bare `hlt`: it decodes
//! keystrokes and echoes them to both consoles. That is what makes the
//! milestone testable from the outside — `tests/test_boot.sh` drives QEMU's QMP
//! `send-key` interface and asserts the echoed characters appear on serial.
//! Kernel entry point and the M1 init sequence.
//!
//! The order of operations here is **not** arbitrary and is documented step by
//! step in `docs/BOOT.md` §4. Each step has dependencies that make its position
//! load-bearing; the comments say what breaks if you move it.
//!
//! M1 ends in an interactive loop rather than a bare `hlt`: it decodes
//! keystrokes and echoes them to both consoles. That is what makes the milestone
//! testable from the outside — `tests/test_boot.sh` drives QEMU's QMP `send-key`
//! interface and asserts the echoed characters appear on serial.

#[allow(dead_code)]

use crate::arch::{self, BOOT_MAPPED_BYTES, KERNEL_VMA};
use crate::console::{self, log, serial, vga};
use crate::cpu::{cpuid, msr};
use crate::drivers::keyboard::{self, KeyEvent};
use crate::interrupts;
use crate::memory::{heap, pmm, vmm};
use crate::multiboot::{self, BootInfo, BootParams};

/// Build identity, stamped into `$OUT_DIR/build_id.txt` by `build.rs` and pulled
/// in with `include_str!`.
///
/// A file rather than `env!` because `--cfg` cannot carry strings and
/// `cargo:rustc-env` would make every build non-reproducible unless the value is
/// content-derived. `build.rs` stamps version, git rev, rustc version and
/// profile — all deterministic — and includes a wall-clock timestamp only when
/// `ORIN_BUILD_TIMESTAMP=1` is set.
///
/// If it comes out empty the build did not supply it, and the banner says
/// "unknown" rather than printing a blank field that reads like a value.
pub const BUILD_ID: &str = include_str!(concat!(env!("OUT_DIR"), "/build_id.txt"));

/// Entry point called from `arch/x86_64/boot/boot.asm`.
///
/// `multiboot_info_phys` is the **physical** address GRUB left in `%ebx`. It is
/// valid only while the boot identity map is live, which is why parsing happens
/// early (step 6) and nothing retains the pointer afterwards.
pub fn kernel_main(multiboot_info_phys: u64, boot_params_phys: u64) -> ! {
    // -- step 0: record the boot parameter block --------------------------
    // Before step 1, and before anything that could log, because the physical
    // addresses the kernel needs are inside this block and no linker symbol can
    // supply them (see arch::BootParams). `set_boot_params` only stores a u64,
    // so it needs no console, no heap and no page tables of its own — which is
    // what makes it safe to run first.
    //
    // A zero here means we were not entered by boot.asm. Dereferencing it would
    // fault at address KERNEL_VMA with no output on any console, so stop now
    // with the reason on the serial port, which is the one thing that already
    // works at this point.
    if boot_params_phys == 0 {
        console::raw::set_serial_ok(true);
        console::raw::print(format_args!(
            "\r\nORIN-FATAL-BEGIN\r\n\
             fatal: entered without a boot parameter block (%rsi = 0).\r\n\
             Only arch/x86_64/boot/boot.asm supplies one, so this kernel was not\r\n\
             started by the Orin boot stub. Halting.\r\n\
             ORIN-FATAL-END\r\n"
        ));
        loop {
            crate::cpu::halt();
        }
    }
    arch::set_boot_params(boot_params_phys);

    // -- step 1: serial ---------------------------------------------------
    // First, before anything else, because it is the only output path that
    // works before the VGA window is known good and before the heap exists.
    // Everything after this point is debuggable.
    let serial_ok = {
        let mut s = serial::COM1_PORT.lock();
        s.init();
        s.present()
    };
    console::raw::set_serial_ok(serial_ok);

    // -- step 2: VGA text console -----------------------------------------
    {
        let mut w = vga::WRITER.lock();
        w.init();
    }

    // From here on, `kinfo!` works. Before here, only `serial_print!`/raw do.
    crate::kinfo!("==============================================================");
    crate::kinfo!(" Orin OS kernel (orink) — milestone 1");
    crate::kinfo!("==============================================================");
    crate::kinfo!("build id      : {}", trimmed_build_id());
    crate::kinfo!("serial COM1   : {}", if serial_ok { "present (loopback self-test passed)" } else { "NOT PRESENT — logs will not be captured" });
    if !serial_ok {
        // Say it plainly. A kernel whose serial port is absent produces no
        // capturable log, and `make test` would then fail for a reason that has
        // nothing to do with the kernel. Making that visible is the difference
        // between a confusing CI failure and a known environment problem.
        crate::kwarn!(
            "serial: the 16550 loopback self-test failed. On real hardware this usually \
             means no UART is wired to COM1. Kernel logging continues to VGA only."
        );
    }

    // -- step 3: CPU feature detection -------------------------------------
    // Before any code that depends on a feature. `cpuid::report` asserts the
    // hard requirements (SSE2, NX, SYSCALL) and warns on the soft ones (SMEP,
    // SMAP, invariant TSC).
    cpuid::report();
    let rdrand_suspect = cpuid::entropy_probe();
    let _ = rdrand_suspect;

    // -- step 4: EFER.NXE ---------------------------------------------------
    // Must precede `vmm::init`, because the VMM caches NX availability and
    // writes NX bits into every page-table entry. Setting NXE afterwards would
    // leave the tables correct but the hardware ignoring them — the exact
    // failure mode where a security property looks enforced in a dump and is
    // not enforced on the CPU.
    let nxe = interrupts::enable_nx();

    // -- step 5: verify long mode ------------------------------------------
    verify_long_mode();

    // -- step 6: zero kernel .bss -------------------------------------------
    // The boot stub zeroed `.boot_bss` (page tables, stacks) but NOT the kernel
    // `.bss`, because at that point the higher half was not mapped yet. Every
    // `static` in the kernel — the PMM bitmap, every `spin::Mutex`, the log
    // config — lives here, so this must run before any of them is touched.
    //
    // Reading/writing through the higher-half alias is valid: the boot page
    // tables map physical 0..2 GiB to both halves.
    zero_kernel_bss();

    // -- step 7: parse the boot information ---------------------------------
    let boot = match multiboot::read_from(multiboot_info_phys) {
        Ok(b) => b,
        Err(e) => {
            // A missing or malformed memory map means we cannot know which RAM is
            // usable. Guessing would violate Rule 1 and corrupt memory. Stop
            // with a specific message.
            crate::kcrit!("multiboot: {}", e.as_str());
            crate::kcrit!(
                "  GRUB was configured to fail the boot rather than omit the required \
                 tags (information_request in arch/x86_64/boot/boot.asm), so reaching \
                 this point means the loader violated the Multiboot2 protocol."
            );
            panic!("boot information unusable: {:?}", e);
        }
    };
    let params = report_boot_info(&boot);
    apply_params(&params);
    verify_load_address(&boot);

    // -- step 8: physical frame allocator -----------------------------------
    // Must precede everything that allocates a frame: the VMM's page tables.
    pmm::init(&boot);
    reserve_boot_memory(&boot);
    report_memory(&boot);

    // -- step 9: kernel address space ---------------------------------------
    let vmm_info = vmm::init();
    report_vmm(&vmm_info);

    // -- step 10: harden the boot identity map -------------------------------
    // After `vmm::init` and after the boot info has been consumed: from here the
    // identity map is supervisor-only and non-executable. Full removal is M4
    // (docs/MEMORY.md §4.3) — the self-test reports the state honestly.
    if params.nx {
        vmm::harden_boot_map();
    } else {
        crate::kwarn!(
            "vmm: boot identity map left EXECUTABLE because orin.nx=off was given. \
             This is a debugging mode; do not ship it."
        );
    }

    // -- step 11: kernel heap -------------------------------------------------
    // After the VMM has mapped the heap region. Before anything that needs
    // `Vec`/`String`/`Box` — including the self-test.
    let heap_bytes = heap::init();
    crate::kinfo!("heap: {} KiB at {:#x}", heap_bytes / 1024, heap::stats().base);

    // -- step 12: syscall MSRs (reserved, not enabled) ------------------------
    // `EFER.SCE` is deliberately NOT set in M1. Enabling `syscall` without a
    // dispatcher would let user code (which does not exist yet) enter the kernel
    // at an address we have not validated. The MSRs are *read* and reported so
    // the M5 work has a baseline, and the reserved vector is installed by
    // `idt::init` returning ENOSYS. See docs/SYSCALL.md.
    report_syscall_state();

    // -- step 13: GDT, TSS, IDT, PIC, PIT --------------------------------------
    // `interrupts::init` enforces the internal order and returns with interrupts
    // still DISABLED, so no handler can run before init completes.
    let int_info = interrupts::init();
    report_interrupts(&int_info);

    // -- step 14: PS/2 keyboard --------------------------------------------------
    // Last driver in M1. Never panics on absent hardware: a machine with no PS/2
    // controller is normal, and Orin must still boot on it.
    let kbd = keyboard::init();
    interrupts::pic::unmask(interrupts::pic::irq::KEYBOARD);

    // -- step 15: framebuffer discovery (M8 prerequisite) -------------------------
    report_framebuffer(&boot);

    // -- step 16: self-test ---------------------------------------------------------
    // Runs before interrupts are enabled globally, except inside
    // `test_timer_interrupt`, which enables them for a bounded window. That test
    // is the one that proves the whole interrupt chain works.
    let (pass, fail, skip) = if params.selftest {
        crate::selftest::report_boot_coverage();
        crate::selftest::run_all()
    } else {
        crate::kwarn!("selftest: SKIPPED by orin.selftest=off — this boot's claims are unverified");
        (0, 0, 0)
    };

    // -- step 17: banner ------------------------------------------------------------
    banner(&boot, &params, &vmm_info, nxe, kbd, pass, fail, skip);

    if fail > 0 {
        // A failed self-test means the kernel's documented invariants do not
        // hold. Continuing would mean running a system whose security claims are
        // known-false, so M1 stops. M4 relaxes this to "log and continue" for
        // specific non-security tests, with the classification recorded per test.
        crate::kcrit!(
            "selftest reported {} failure(s); the kernel's documented invariants do not hold. \
             Stopping rather than continuing in a known-bad state.",
            fail
        );
        panic!("boot self-test failed");
    }

    // -- step 18: interactive idle loop ---------------------------------------------
    idle(&params)
}

fn trimmed_build_id() -> &'static str {
    let t = BUILD_ID.trim();
    if t.is_empty() {
        "<not stamped by the build>"
    } else {
        t
    }
}

// ===========================================================================
//  Init steps
// ===========================================================================

/// Zero kernel `.bss`. See the comment at the call site for why the boot stub
/// cannot do this.
fn zero_kernel_bss() {
    // The symbols are declared in `arch.rs`; importing them locally keeps the
    // `linker_sym!` invocation (which expands to `addr_of!`) resolvable.
    extern "C" {
        static _kernel_bss_start: u8;
        static _kernel_bss_end: u8;
    }
    let start = crate::linker_sym!(_kernel_bss_start);
    let end = crate::linker_sym!(_kernel_bss_end);
    let len = end - start;

    // Sanity-check before writing: a wrong symbol here would zero arbitrary
    // kernel memory, and the failure would be spectacular and confusing.
    assert!(
        start >= KERNEL_VMA && end > start && len < 64 * 1024 * 1024,
        "kernel .bss range is implausible: {start:#x}..{end:#x} ({len} bytes)"
    );

    // SAFETY: `_kernel_bss_start.._kernel_bss_end` is .bss — zero-initialised by
    // definition, reached through the boot higher-half alias which maps it, and
    // written exactly once before any static is read.
    unsafe {
        core::ptr::write_bytes(start as *mut u8, 0, len as usize);
    }
    crate::kdebug!("bss: zeroed {} bytes at {:#x}..{:#x}", len, start, end);
}

/// Confirm the CPU is in the state the boot stub claims to have left it in.
///
/// Trusting `boot.asm` is exactly the kind of assumption that fails on real
/// hardware for reasons that are invisible in QEMU. Reading the control
/// registers costs nothing and turns "the machine reset" into "the machine
/// reset and here is which bit was wrong".
fn verify_long_mode() {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr4, Cr4Flags};
    use x86_64::registers::model_specific::{Efer, EferFlags};

    let cr0 = Cr0::read();
    let cr4 = Cr4::read();
    let efer = Efer::read();
    let cr3 = Cr3::read_raw().0.start_address().as_u64();

    crate::kinfo!(
        "cpu: cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x}",
        cr0.bits(), cr3, cr4.bits(), efer.bits()
    );

    let mut bad = false;
    let check = |ok: bool, what: &str, bad: &mut bool| {
        if !ok {
            crate::kerror!("long mode: {} is NOT set", what);
            *bad = true;
        }
    };
    check(cr0.contains(Cr0Flags::PAGING), "CR0.PG (paging)", &mut bad);
    check(cr0.contains(Cr0Flags::WRITE_PROTECT), "CR0.WP (write protect)", &mut bad);
    check(cr0.contains(Cr0Flags::PROTECTED_MODE_ENABLE), "CR0.PE (protected mode)", &mut bad);
    check(cr4.contains(Cr4Flags::PHYSICAL_ADDRESS_EXTENSION), "CR4.PAE", &mut bad);
    check(efer.contains(EferFlags::LONG_MODE_ENABLE), "EFER.LME", &mut bad);
    check(efer.contains(EferFlags::LONG_MODE_ACTIVE), "EFER.LMA", &mut bad);

    if cr3 == 0 {
        crate::kerror!("long mode: CR3 is 0 — no page tables are loaded");
        bad = true;
    }
    if cr3 % 4096 != 0 {
        crate::kerror!("long mode: CR3 {cr3:#x} is not 4 KiB aligned");
        bad = true;
    }

    // SMEP/SMAP are enabled here rather than in boot.asm because they need a
    // CPUID check first, and boot.asm runs before we have one. Enabling SMEP on
    // a CPU without it would #GP immediately.
    let f = cpuid::detect();
    if f.smep {
        // SAFETY: CPUID confirmed SMEP support. Setting it means the kernel
        // faults instead of executing user-space code — strictly more secure,
        // and M1 has no user space to break.
        unsafe { Cr4::write(cr4 | Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION) };
        crate::kinfo!("cpu: CR4.SMEP enabled (kernel cannot execute user-space code)");
    }
    if f.smap {
        // SAFETY: CPUID confirmed SMAP support. Note this makes *implicit*
        // kernel access to user memory fault, so M4's `copy_from_user` must use
        // `stac`/`clac`. Enabling it now, before any such code exists, is the
        // safe order: the requirement is in place before the code that must
        // satisfy it.
        unsafe {
            Cr4::write(Cr4::read() | Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION);
        }
        crate::kinfo!("cpu: CR4.SMAP enabled (kernel cannot implicitly read user memory)");
    }

    if bad {
        panic!("CPU is not in the state boot.asm promised; see the errors above");
    }
    crate::kinfo!("long mode: verified (64-bit paging active, WP on, CR3 {cr3:#x})");
}

/// Cross-check GRUB's reported load address against the linker script.
///
/// If these disagree, the kernel is executing from somewhere other than where
/// it thinks it is, and every physical address it computes is wrong.
fn verify_load_address(boot: &BootInfo) {
    let script = arch::kernel_phys_start();
    match boot.load_base_addr {
        Some(reported) => {
            if (reported as u64) != script {
                crate::kwarn!(
                    "multiboot: GRUB reports load base {:#x} but the linker script says {:#x}. \
                     Using the linker script value. If these differ, the frame allocator's \
                     reservation of the kernel image is wrong.",
                    reported,
                    script
                );
            } else {
                crate::kdebug!("multiboot: load base {:#x} matches the linker script", script);
            }
        }
        None => crate::kdebug!(
            "multiboot: loader did not supply tag 20 (load base address); trusting the linker script ({script:#x})"
        ),
    }
}

/// Apply `orin.*=` boot parameters.
fn apply_params(params: &BootParams) {
    log::configure(params.log, params.console);
    crate::panic::set_panic_action(params.panic_action);
    if !params.unknown.is_empty() {
        // Unknown parameters are logged, never fatal: a typo in grub.cfg must
        // not brick the boot. But they must not be silent either, or a
        // misspelled `orin.nx=offf` would leave NX on while the operator
        // believes they disabled it.
        crate::kwarn!(
            "boot: unrecognised parameter(s): \"{}\" — ignored. See docs/BOOT.md §5 for the list.",
            params.unknown.as_str()
        );
    }
    if params.single {
        crate::kinfo!("boot: orin.single given; SMP bring-up will be skipped (M4)");
    }
}

/// Read `orin.memlimit=` from the already-parsed command line.
///
/// Kept as a helper because re-parsing the command line inside
/// `reserve_boot_memory` would mean two parsers that can disagree.
fn mem_limit_from(boot: &BootInfo) -> Option<u64> {
    let cl = boot.cmdline.as_ref().map(|c| c.as_str()).unwrap_or("");
    multiboot::parse_params(cl).mem_limit_mib
}

/// Reserve memory the kernel and firmware own, before any allocation.
///
/// Every range here is reserved for a stated reason. A range reserved "just in
/// case" is a range whose necessity nobody can ever verify, so each one names
/// what would break without it.
fn reserve_boot_memory(boot: &BootInfo) {
    // Real-mode interrupt vector table and BIOS data area. Writing here on a
    // BIOS-booted machine corrupts firmware state that may still be in use
    // (SMM, option ROMs).
    pmm::reserve_range(0x0, 0x1000);

    // Extended BIOS data area. Its location varies by firmware; reserving the
    // conventional window costs 1 KiB and removes a class of corruption that
    // only appears on specific hardware.
    pmm::reserve_range(0x9FC00, 0xA0000);

    // VGA memory window and option ROM area.
    pmm::reserve_range(0xA0000, 0xC0000);
    pmm::reserve_range(0xC0000, 0x100000);

    // The kernel image itself: text, rodata, data, bss and the boot stub's
    // page tables and stacks.
    let ks = arch::kernel_phys_start();
    let ke = arch::kernel_phys_end();
    pmm::reserve_range(ks, ke);
    crate::kdebug!("pmm: reserved kernel image [{ks:#x}..{ke:#x}) = {} KiB", (ke - ks) / 1024);

    // The boot stub's .bss is inside [ks, ke) by linker-script construction,
    // but assert it rather than assume: if a future linker change moved it out,
    // the page tables would become allocatable and the kernel would corrupt
    // its own address space.
    let (bs, be) = arch::boot_bss_phys_range();
    assert!(
        bs >= ks && be <= ke,
        "boot .bss [{bs:#x}..{be:#x}) is not inside the kernel image [{ks:#x}..{ke:#x}); \
         the linker script moved it and pmm::reserve_boot_memory must be updated"
    );

    // GRUB's information structure. Still needed? No — `BootInfo` copied out
    // everything we use. Reserved anyway, because it is firmware-owned memory
    // and reusing it would be indistinguishable from a bug if GRUB retained a
    // pointer. Cost: a few KiB.
    if boot.phys_addr != 0 {
        let end = boot.phys_addr + boot.total_size as u64;
        pmm::reserve_range(boot.phys_addr, end);
        crate::kdebug!("pmm: reserved multiboot info [{:#x}..{end:#x})", boot.phys_addr);
    }

    // The framebuffer. Reserving it is what stops a kernel allocation from
    // scribbling on the display in M8. Reserving it in M1 costs nothing and
    // means M8 cannot forget.
    if let Some(fb) = boot.framebuffer {
        if fb.fb_type != multiboot::info::fbtype::EGA_TEXT && fb.size > 0 {
            pmm::reserve_range(fb.address, fb.address + fb.size);
            crate::kdebug!(
                "pmm: reserved framebuffer [{:#x}..{:#x}) = {} KiB",
                fb.address,
                fb.address + fb.size,
                fb.size / 1024
            );
        }
    }

    // ACPI tables. Reserved so the M7 hardware-discovery code can read them;
    // reusing this memory would destroy the only description of the machine's
    // hardware that exists.
    if let Some(rsdp) = boot.acpi_rsdp {
        // RSDP v1 is 20 bytes, v2 is 36. Reserve a page: the RSDP points onward
        // to the XSDT/RSDT, whose locations are parsed in M7 and reserved then.
        pmm::reserve_range(rsdp & !0xFFF, (rsdp & !0xFFF) + 4096);
        crate::kdebug!(
            "pmm: reserved ACPI RSDP v{} page at {:#x}",
            boot.acpi_version,
            rsdp & !0xFFF
        );
    }

    // An explicit cap, if requested. Used by tests to make memory pressure
    // reproducible without depending on the host's RAM.
    if let Some(limit_mib) = mem_limit_from(boot) {
        let limit = limit_mib * 1024 * 1024;
        pmm::reserve_range(limit, BOOT_MAPPED_BYTES);
        crate::kwarn!(
            "pmm: orin.memlimit={} caps usable RAM at {} MiB; the rest is reserved for this boot",
            limit_mib,
            limit_mib
        );
    }
}

/// Report the framebuffer GRUB chose.
///
/// M1 does not draw to it — the text console is VGA-port-driven. But the
/// information is discovered now because M8 needs it, and because a boot log
/// that records the display mode makes "the screen is the wrong resolution"
/// answerable without a second boot.
fn report_framebuffer(boot: &BootInfo) {
    match boot.framebuffer {
        Some(fb) => {
            let kind = match fb.fb_type {
                multiboot::info::fbtype::INDEXED => "indexed colour",
                multiboot::info::fbtype::RGB => "RGB direct colour",
                multiboot::info::fbtype::EGA_TEXT => "EGA text",
                other => "unknown",
            };
            crate::kinfo!(
                "fb: {:#x} {}x{} bpp {} pitch {} ({} KiB, {})",
                fb.address, fb.width, fb.height, fb.bpp, fb.pitch, fb.size / 1024, kind
            );
            if fb.fb_type == multiboot::info::fbtype::EGA_TEXT {
                crate::kinfo!("fb: GRUB supplied a TEXT framebuffer; M8 needs a graphics mode (add `set gfxpayload=keep` to grub.cfg)");
            }
            if fb.address + fb.size > BOOT_MAPPED_BYTES {
                crate::kwarn!(
                    "fb: framebuffer at {:#x}+{:#x} is OUTSIDE the M1 boot mapping ({:#x}). \
                     M8 must extend the page tables before it can draw. Recorded here so the \
                     limitation is visible at boot rather than discovered as a fault.",
                    fb.address,
                    fb.size,
                    BOOT_MAPPED_BYTES
                );
            }
        }
        None => crate::kwarn!(
            "fb: GRUB supplied no framebuffer tag. M1 uses the VGA text console so this is \
             not fatal, but M8 cannot start without one."
        ),
    }
}

fn report_boot_info(boot: &BootInfo) -> BootParams {
    crate::kinfo!(
        "multiboot: {} bytes at {:#x}, {} tags walked",
        boot.total_size, boot.phys_addr, boot.tag_count
    );
    crate::kinfo!(
        "multiboot: loader \"{}\"",
        boot.loader_name.as_ref().map(|n| n.as_str()).unwrap_or("<not reported>")
    );
    let cmdline = boot.cmdline.as_ref().map(|c| c.as_str()).unwrap_or("");
    crate::kinfo!("multiboot: command line \"{}\"", cmdline);
    crate::kinfo!("multiboot: {} memory-map entries", boot.mmap.len());
    for e in boot.mmap.as_slice() {
        crate::kdebug!(
            "  mmap [{:#012x}..{:#012x}) {:>8} KiB type {}",
            e.base,
            e.base.saturating_add(e.length),
            e.length / 1024,
            e.mem_type
        );
    }
    if let Some(rsdp) = boot.acpi_rsdp {
        crate::kinfo!("multiboot: ACPI RSDP v{} at {:#x}", boot.acpi_version, rsdp);
    } else {
        crate::kdebug!("multiboot: no ACPI RSDP supplied (normal for a BIOS-less QEMU config)");
    }
    multiboot::parse_params(cmdline)
}

fn report_memory(boot: &BootInfo) {
    let s = pmm::stats();
    let usable = (s.free_frames as u64) * 4096;
    let total_ram: u64 = boot.mmap.as_slice().iter().map(|e| e.length).sum();
    crate::kinfo!(
        "pmm: {} MiB usable / {} MiB reported by firmware; {} KiB reserved, {} KiB bad RAM",
        usable / (1024 * 1024),
        total_ram / (1024 * 1024),
        (s.reserved_frames as u64) * 4,
        (s.bad_frames as u64) * 4
    );
    if s.unmapped_bytes > 0 {
        crate::kwarn!(
            "pmm: {} MiB of RAM is present but ABOVE the M1 boot mapping ({:#x}) and is \
             unusable this milestone. M4 extends the page tables; see docs/MEMORY.md §7. \
             This is reported rather than silently ignored so the machine's real size is \
             never misrepresented.",
            s.unmapped_bytes / (1024 * 1024),
            BOOT_MAPPED_BYTES
        );
    }
}

fn report_vmm(i: &vmm::VmmInfo) {
    crate::kinfo!(
        "vmm: .text {} KiB of a {} KiB R-X region at {:#x}",
        i.text_content / 1024, i.text_mapped / 1024, i.text_va
    );
    crate::kinfo!(
        "vmm: .rodata {} KiB (R--), .data {} KiB (RW-), .bss {} KiB (RW-)",
        i.rodata_content / 1024, i.data_content / 1024, i.bss_content / 1024
    );
    crate::kinfo!(
        "vmm: {} page-table frames allocated; kernel PML4 at {:#x} (boot PML4 was {:#x})",
        i.pt_frames, i.kernel_pml4_phys, i.boot_pml4_phys
    );
    let wx = vmm::count_wx_violations();
    crate::kinfo!(
        "vmm: W^X audit — {} page(s) writable AND executable{}",
        wx,
        if wx == 0 { " (as required)" } else { " — POLICY VIOLATED" }
    );
}

fn report_interrupts(i: &interrupts::InterruptInfo) {
    crate::kinfo!(
        "int: {} vectors installed; PIT divisor {} -> {}/{} Hz exact; unmasked IRQ mask {:#06x}",
        i.vectors_installed,
        i.pit_divisor,
        i.tick_hz_num,
        i.tick_hz_den,
        i.unmasked_irqs
    );
    crate::kinfo!(
        "int: GDT selectors kcode={:#x} kdata={:#x} udata={:#x} ucode={:#x} tss={:#x}",
        i.selectors.kernel_code, i.selectors.kernel_data,
        i.selectors.user_data, i.selectors.user_code, i.selectors.tss
    );
    crate::kinfo!(
        "int: IST stacks {} x {} KiB = {} KiB, each with a guard page",
        crate::interrupts::gdt::ist::COUNT,
        16,
        crate::interrupts::gdt::ist_total_bytes() / 1024
    );
    crate::kinfo!("int: NXE active = {}", i.nxe_enabled);
}

/// Report the syscall ABI state: reserved and documented, not implemented.
///
/// Read-only MSR inspection here. Nothing is programmed, because programming
/// `LSTAR` without a validated entry stub would create a way into the kernel
/// that no test has exercised. That is M5's job and M5's risk to take.
fn report_syscall_state() {
    let f = cpuid::detect();
    crate::kinfo!(
        "syscall: CPU supports SYSCALL/SYSRET = {}; ABI is DESIGNED (docs/SYSCALL.md) and \
         NOT IMPLEMENTED until M5. Vector {:#04x} returns ENOSYS.",
        f.syscall,
        crate::interrupts::idt::SYSCALL_VECTOR
    );
    // SAFETY: reading EFER, STAR and LSTAR is side-effect-free and all three
    // exist on any CPU that reports SYSCALL support (checked above).
    unsafe {
        if f.syscall {
            let efer = msr::read(msr::addr::EFER);
            let star = msr::read(msr::addr::STAR);
            let lstar = msr::read(msr::addr::LSTAR);
            crate::kdebug!(
                "syscall: baseline MSRs — EFER={efer:#x} (SCE={}) STAR={star:#x} LSTAR={lstar:#x}",
                efer & msr::efer::SCE != 0
            );
            if efer & msr::efer::SCE != 0 {
                crate::kwarn!(
                    "syscall: EFER.SCE is already set by firmware/bootloader but Orin has no \
                     LSTAR entry point programmed. M5 must program STAR/LSTAR/SFMASK before \
                     enabling user space, or a `syscall` from ring 3 would jump to whatever \
                     LSTAR currently holds."
                );
            }
        }
    }
}

// ===========================================================================
//  Banner
// ===========================================================================

fn banner(
    boot: &BootInfo,
    params: &BootParams,
    vmm_info: &vmm::VmmInfo,
    nxe: bool,
    kbd: keyboard::Presence,
    pass: usize,
    fail: usize,
    skip: usize,
) {
    let f = cpuid::detect();
    crate::kinfo!("==============================================================");
    crate::kinfo!(" Orin OS — M1 boot complete");
    crate::kinfo!("==============================================================");
    crate::kinfo!(" build         : {}", trimmed_build_id());
    crate::kinfo!(" abi           : orink x86_64, OKI ABI v{}", crate::OKI_ABI_VERSION);
    crate::kinfo!(" cpu           : {}", cpuid::cstr(&f.vendor));
    crate::kinfo!(" environment   : {}", if f.hypervisor_present {
        cpuid::cstr(&f.hypervisor_vendor)
    } else {
        "bare metal"
    });
    crate::kinfo!(" loader        : {}", boot.loader_name.as_ref().map(|n| n.as_str()).unwrap_or("?"));
    let ps = pmm::stats();
    crate::kinfo!(
        " memory        : {} MiB usable of {} MiB boot-mapped ({} MiB RAM present)",
        (ps.free_frames as u64 * 4096) / (1024 * 1024),
        BOOT_MAPPED_BYTES / (1024 * 1024),
        boot.mmap.as_slice().iter().map(|e| e.length).sum::<u64>() / (1024 * 1024)
    );
    crate::kinfo!(
        " kernel image  : {:#x}..{:#x} ({:.1} KiB text)",
        vmm_info.text_va,
        vmm_info.text_va + vmm_info.text_mapped,
        vmm_info.text_content as f64 / 1024.0
    );
    crate::kinfo!(" heap          : {} KiB", vmm_info.heap_size / 1024);
    // WP/SMEP/SMAP are READ, not assumed: the banner is a claim about this
    // machine, and a claim we did not measure is a claim that can be wrong.
    use x86_64::registers::control::{Cr0, Cr4, Cr0Flags, Cr4Flags};
    let cr0 = Cr0::read();
    let cr4 = Cr4::read();
    crate::kinfo!(
        " protection    : WP={} NXE={} SMEP={} SMAP={} W^X violations={}",
        yes(cr0.contains(Cr0Flags::WRITE_PROTECT)),
        yes(nxe),
        yes(cr4.contains(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION)),
        yes(cr4.contains(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION)),
        vmm::count_wx_violations()
    );
    crate::kinfo!(" keyboard      : {:?}", kbd);
    crate::kinfo!(
        " self-test     : {} passed, {} failed, {} skipped{}",
        pass, fail, skip,
        if params.selftest { "" } else { " (disabled by boot parameter)" }
    );
    crate::kinfo!(" log level     : requested {:?}, effective {}", params.log, log::effective_level());
    crate::kinfo!("--------------------------------------------------------------");
    crate::kinfo!(" M1 scope: boot, long mode, memory, interrupts, PS/2 input.");
    crate::kinfo!(" No processes, no syscalls, no filesystem, no graphics, no");
    crate::kinfo!(" networking. Those are M4/M5/M6/M8/M11 — see docs/ROADMAP.md.");
    crate::kinfo!(" Type on the keyboard: input is echoed below and to serial.");
    crate::kinfo!("==============================================================");
}

fn yes(b: bool) -> &'static str {
    if b { "on " } else { "OFF" }
}

// ===========================================================================
//  Idle loop — the M1 "shell"
// ===========================================================================

/// Echo typed characters to both consoles.
///
/// This is a *driver test harness*, not a shell. It exists so that:
///
/// * a human running `make run` gets immediate proof that input works, and
/// * `tests/test_boot.sh` can drive QEMU's QMP `send-key`, then assert the
///   echoed characters appear in the serial log.
///
/// `orinsh` — the real shell — is M10 and runs in user space, not here. Putting
/// a shell in the kernel would violate the layering in `docs/ARCHITECTURE.md`
/// §2, and this loop deliberately does no parsing, no history and no
/// completion, so nobody mistakes it for one.
fn idle(params: &BootParams) -> ! {
    crate::kinfo!("idle: entering the M1 input echo loop");
    vga_print_prompt();

    // Interrupts on. Every handler is installed and the self-test has already
    // verified the timer path, so this is the safe point to enable them — and
    // enabling them *last* is what makes that true.
    crate::cpu::enable_interrupts();

    let mut events: [KeyEvent; 16] = [KeyEvent {
        code: keyboard::KeyCode::None,
        pressed: false,
        shift: false,
        ctrl: false,
        alt: false,
        tick: 0,
        ch: None,
    }; 16];

    loop {
        let n = keyboard::drain(&mut events);
        for ev in events.iter().take(n) {
            handle_key(*ev);
        }
        if n == 0 {
            // No input pending: halt until the next interrupt rather than
            // spinning. `hlt` with interrupts enabled is the correct idle
            // primitive — it burns no cycles and resumes on any IRQ.
            crate::cpu::halt();
        }
        // Periodically report liveness at trace level so a long idle boot still
        // shows in a trace log that interrupts are being taken.
        let t = crate::interrupts::pit::ticks_since_boot();
        if t > 0 && t % 5000 == 0 {
            crate::ktrace!(
                "idle: uptime {}s, {} key events, {} scancodes pending, {} dropped",
                crate::interrupts::pit::seconds_since_boot(),
                keyboard::event_count(),
                keyboard::pending(),
                keyboard::dropped_count()
            );
        }
        let _ = params;
    }
}

fn vga_print_prompt() {
    use core::fmt::Write;
    let mut w = vga::WRITER.lock();
    w.set_color(vga::Color::LightCyan, vga::Color::Black);
    let _ = write!(w, "orin m1> ");
    w.set_color(vga::Color::LightGray, vga::Color::Black);
}

fn handle_key(ev: KeyEvent) {
    if !ev.pressed {
        return;
    }
    use keyboard::KeyCode;

    // Ctrl+C is the one chord worth handling in a test harness: it prints the
    // counter state, which is how you check whether interrupts are still being
    // delivered without rebooting.
    if ev.ctrl && matches!(ev.code, KeyCode::C) {
        let (ticks, keys, spurious, exceptions, unassigned, syscalls) =
            crate::interrupts::idt::counters();
        crate::kinfo!(
            "counters: ticks={} keys={} spurious={} exceptions={} unassigned={} syscalls={}",
            ticks, keys, spurious, exceptions, unassigned, syscalls
        );
        crate::kinfo!(
            "keyboard: {} events, {} pending, {} dropped (ring capacity {})",
            keyboard::event_count(),
            keyboard::pending(),
            keyboard::dropped_count(),
            256
        );
        return;
    }

    let Some(ch) = ev.ch else {
        // A key with no character (arrow, function key, modifier). Report it by
        // name so the log shows the driver decoded it correctly rather than
        // appearing to have ignored it.
        crate::kdebug!("key: {:?} (no character)", ev.code);
        return;
    };

    match ch {
        '\n' => {
            // Emit a distinct serial marker per newline. The test harness types
            // a known string followed by Enter and asserts on the marker, so a
            // partial line cannot be mistaken for a complete one.
            crate::console::serial::print(format_args!("\r\n"));
            vga_print_prompt();
        }
        '\u{8}' => {
            crate::console::serial::print(format_args!("\u{8} \u{8}"));
            let mut w = vga::WRITER.lock();
            use core::fmt::Write;
            let _ = write!(w, "\u{8}");
        }
        '\u{1b}' => {
            crate::kinfo!("key: Escape — no M1 binding (orinsh arrives in M10)");
        }
        c => {
            // Echo to serial in the structured format so the harness can grep
            // it, and to VGA as plain text so a human sees what they typed.
            crate::console::serial::print(format_args!("ORIN|K|ECHO|{}\r\n", c));
            let mut w = vga::WRITER.lock();
            use core::fmt::Write;
            let _ = write!(w, "{}", c);
        }
    }
    // A dropped-scancode count means the consumer fell behind. Surface it the
    // moment it happens rather than leaving it in a counter nobody reads.
    if keyboard::dropped_count() > 0 {
        crate::kwarn!(
            "keyboard: {} scancode(s) dropped — the echo loop is not keeping up with input",
            keyboard::dropped_count()
        );
    }
}
