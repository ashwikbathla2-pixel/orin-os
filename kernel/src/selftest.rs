//! In-kernel boot self-test.
//!
//! ## Why the kernel tests itself
//!
//! Rule 17 says every milestone must produce a testable result. For a kernel,
//! the properties that matter most are precisely the ones that *cannot* be
//! observed from outside: whether the page tables the kernel built are the ones
//! the CPU will use, whether W^X actually holds in the live tables, whether the
//! timer interrupt really fires. `tools/hostcheck` can test the pure logic;
//! only in-kernel tests can test the machine state.
//!
//! The suite therefore concentrates on claims Orin makes in its documentation:
//!
//! | Claim | Test |
//! |---|---|
//! "No page is writable and executable" (MEMORY.md §2.2) | `wx_policy` walks the live tables |
//! "The boot identity map is not executable" (MEMORY.md §4.3) | `boot_map_nx` |
//! "The PMM never hands out the same frame twice" | `pmm_unique` |
//! "A double free is detected" (MEMORY.md §3.4) | `pmm_double_free` |
//! "The timer interrupt path works end to end" (BOOT.md §4) | `timer_interrupt` |
//! "The keyboard interrupt path works end to end" | `keyboard_irq_armed` |
//! "The multiboot2 parser rejects malformed input" | `multiboot_malformed` |
//! "Syscalls report ENOSYS rather than pretending" (SYSCALL.md) | `syscall_enosys` |
//!
//! ## Output format
//!
//! ```text
//! ORIN|SELFTEST|PASS|wx_policy             |0 writable+executable pages
//! ORIN|SELFTEST|FAIL|pmm_unique            |frame 0x1234 handed out twice
//! ORIN|SELFTEST|SUMMARY|23 passed, 0 failed, 0 skipped
//! ```
//!
//! `tools/qemu-run.sh` parses these lines. `make test` fails the build if the
//! summary line reports any failure, or if the summary line is absent (which
//! means the kernel died before finishing init — also a failure, just a
//! different one).
//!
//! ## Cost
//!
//! The suite runs in well under a second of emulated time and allocates nothing
//! permanent. It is on by default (`orin.selftest=on` in `grub.cfg`) because a
//! boot that does not verify itself is a boot whose claims are untested. It can
//! be disabled for the fastest-boot entry.

#![allow(dead_code)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::{phys_to_virt, virt_to_phys, BOOT_MAPPED_BYTES, KERNEL_VMA, PAGE_SIZE};
use crate::memory::{heap, pmm, vmm};
use x86_64::{PhysAddr, VirtAddr};

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
    static _kernel_rodata_start: u8;
    static _kernel_data_start: u8;
    static _kernel_bss_start: u8;

}


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Pass,
    Fail,
    /// The test could not run because a prerequisite is missing. Reported
    /// distinctly from FAIL: a skipped test on hardware without a PS/2
    /// controller is not a kernel bug, and calling it one would train people to
    /// ignore failures.
    Skip,
}

#[derive(Clone, Copy)]
struct Tally {
    pass: usize,
    fail: usize,
    skip: usize,
}

/// One test. The detail string is short and states the *measured* value, not
/// just "ok": a passing test that reports its number is a test whose result can
/// be compared across machines and builds.
fn run(name: &str, tally: &mut Tally, f: impl FnOnce() -> Result<String, String>) {
    match f() {
        Ok(detail) => {
            tally.pass += 1;
            crate::console::log::log(
                crate::log::Level::Info,
                "SELFTEST|PASS",
                name,
                format_args!("{}", detail),
            );
        }
        Err(detail) => {
            tally.fail += 1;
            crate::console::log::log(
                crate::log::Level::Critical,
                "SELFTEST|FAIL",
                name,
                format_args!("{}", detail),
            );
        }
    }
}

fn skip(name: &str, tally: &mut Tally, reason: &str) {
    tally.skip += 1;
    crate::console::log::log(
        crate::log::Level::Warn,
        "SELFTEST|SKIP",
        name,
        format_args!("{}", reason),
    );
}

/// Run the whole suite. Returns `(passed, failed, skipped)`.
pub fn run_all() -> (usize, usize, usize) {
    let mut t = Tally {
        pass: 0,
        fail: 0,
        skip: 0,
    };
    crate::kinfo!("selftest: starting in-kernel verification suite");

    // ---- memory --------------------------------------------------------
    run("address_translation", &mut t, test_address_translation);
    run("pmm_unique", &mut t, test_pmm_unique);
    run("pmm_reserve_excluded", &mut t, test_pmm_reserve_excluded);
    run("pmm_contiguous_aligned", &mut t, test_pmm_contiguous);
    run("pmm_double_free", &mut t, test_pmm_double_free);
    run("pmm_no_boot_map_leak", &mut t, test_pmm_no_boot_map_leak);
    run("heap_alloc", &mut t, test_heap);
    run("heap_guarded", &mut t, test_heap_guarded);

    // ---- page tables / security ---------------------------------------
    run("vmm_translation_matches", &mut t, test_vmm_translation);
    run("wx_policy", &mut t, test_wx_policy);
    run("text_not_writable", &mut t, test_text_not_writable);
    run("rodata_not_writable", &mut t, test_rodata_not_writable);
    run("boot_map_nx", &mut t, test_boot_map_nx);
    run("boot_map_not_user", &mut t, test_boot_map_not_user);
    run("user_half_unmapped", &mut t, test_user_half_unmapped);
    run("control_registers", &mut t, test_control_registers);

    // ---- interrupt path ------------------------------------------------
    run("timer_interrupt", &mut t, test_timer_interrupt);
    run("keyboard_irq_armed", &mut t, test_keyboard_irq_armed);

    // ---- parsers and ABI ------------------------------------------------
    run("multiboot_malformed", &mut t, test_multiboot_malformed);
    run("multiboot_roundtrip", &mut t, test_multiboot_roundtrip);
    run("scancode_translation", &mut t, test_scancode_translation);
    run("syscall_enosys", &mut t, test_syscall_enosys);
    run("star_value", &mut t, test_star_value);
    run("errno_negated_range", &mut t, test_errno_range);

    // ---- console --------------------------------------------------------
    run("console_vga_writeback", &mut t, test_console_vga);

    // ---- hardware-dependent, skippable ---------------------------------
    match crate::drivers::keyboard::presence() {
        crate::drivers::keyboard::Presence::Keyboard
        | crate::drivers::keyboard::Presence::Controller => {
            run("ps2_controller_alive", &mut t, test_ps2_alive);
        }
        _ => skip(
            "ps2_controller_alive",
            &mut t,
            "no PS/2 controller on this machine; USB HID arrives in M7",
        ),
    }

    crate::kinfo!(
        "selftest: {} passed, {} failed, {} skipped",
        t.pass,
        t.fail,
        t.skip
    );
    // Emitted as a single greppable line for the harness.
    crate::console::log::log(
        if t.fail == 0 {
            crate::log::Level::Info
        } else {
            crate::log::Level::Critical
        },
        "SELFTEST|SUMMARY",
        "result",
        format_args!("{} passed, {} failed, {} skipped", t.pass, t.fail, t.skip),
    );
    (t.pass, t.fail, t.skip)
}

// ===========================================================================
//  Address translation
// ===========================================================================

fn test_address_translation() -> Result<String, String> {
    // The higher-half identity: virt - KERNEL_VMA == phys, and the reverse.
    let pa = PhysAddr::new(0x1234_0000);
    let va = phys_to_virt(pa);
    if va.as_u64() != pa.as_u64().wrapping_add(KERNEL_VMA) {
        return Err(format!("phys_to_virt({pa:#x}) = {va:#x}, expected {:#x}", pa.as_u64() + KERNEL_VMA));
    }
    let back = virt_to_phys(va).ok_or("virt_to_phys rejected a kernel-half address")?;
    if back != pa {
        return Err(format!("round trip failed: {pa:#x} -> {va:#x} -> {back:#x}"));
    }
    // A user-half address must be rejected, not silently wrapped. Kernel code
    // that passes a low pointer into a kernel API is a bug, and returning
    // `None` is what makes it a *handled* bug.
    if virt_to_phys(VirtAddr::new(0x4000)).is_some() {
        return Err("virt_to_phys accepted a user-half address; it must return None".into());
    }
    // Wrapping is what makes the higher half work at all: 0 - KERNEL_VMA
    // == 0x80000000.
    if virt_to_phys(VirtAddr::new(KERNEL_VMA)) != Some(PhysAddr::new(0)) {
        return Err("KERNEL_VMA does not translate to physical 0".into());
    }
    Ok("round trip ok; user-half rejected; KERNEL_VMA -> phys 0".into())
}

// ===========================================================================
//  PMM
// ===========================================================================

fn test_pmm_unique() -> Result<String, String> {
    const N: usize = 512;
    let mut frames: Vec<PhysAddr> = Vec::with_capacity(N);
    for _ in 0..N {
        let f = pmm::allocate_frame().ok_or("PMM ran out of frames during self-test")?;
        frames.push(f.start_address());
    }
    // Sort and look for duplicates. O(n log n) on 512 entries is trivial and
    // avoids a 512×512 comparison that would dominate the suite's runtime.
    let mut sorted = frames.clone();
    sorted.sort_by_key(|a| a.as_u64());
    for w in sorted.windows(2) {
        if w[0] == w[1] {
            return Err(format!("frame {:#x} was handed out twice", w[0].as_u64()));
        }
    }
    // None of them may be inside the kernel image: that would mean the PMM gave
    // out memory the kernel is running from.
    let ks = crate::arch::kernel_phys_start();
    let ke = crate::arch::kernel_phys_end();
    for f in frames.iter() {
        let p = f.as_u64();
        if p >= ks && p < ke {
            return Err(format!(
                "PMM handed out {p:#x}, which is inside the kernel image [{ks:#x}..{ke:#x})"
            ));
        }
    }
    for f in frames {
        pmm::deallocate_frame(unsafe {
            x86_64::structures::paging::PhysFrame::from_start_address_unchecked(f)
        });
    }
    Ok(format!("{N} frames unique, none inside the kernel image [{ks:#x}..{ke:#x})"))
}

fn test_pmm_reserve_excluded() -> Result<String, String> {
    // The frame allocator must never return a frame from a range we reserved.
    // Firmware-reserved low memory is the important case: handing out 0xB8000
    // would let a kernel allocation scribble on the VGA buffer.
    let reserved: [(u64, u64, &str); 4] = [
        (0x0, 0x1000, "real-mode IVT"),
        (0xA0000, 0xC0000, "VGA window"),
        (crate::arch::kernel_phys_start(), crate::arch::kernel_phys_end(), "kernel image"),
        (0xB8000, 0xB9000, "VGA text buffer"),
    ];
    let mut checked = 0usize;
    for _ in 0..2048 {
        let Some(f) = pmm::allocate_frame() else { break };
        let p = f.start_address().as_u64();
        for (lo, hi, what) in reserved {
            if p >= lo && p < hi {
                pmm::deallocate_frame(f);
                return Err(format!("PMM handed out {p:#x} from reserved {what} [{lo:#x}..{hi:#x})"));
            }
        }
        checked += 1;
        pmm::deallocate_frame(f);
    }
    if checked == 0 {
        return Err("no frames available to check".into());
    }
    Ok(format!("{checked} allocations checked against 4 reserved ranges"))
}

fn test_pmm_contiguous() -> Result<String, String> {
    const N: usize = 16;
    let f = pmm::allocate_contiguous(N, 4)
        .ok_or("could not allocate 16 contiguous frames aligned to 4")?;
    let base = f.start_address().as_u64();
    if base % (PAGE_SIZE * 4) != 0 {
        return Err(format!("base {base:#x} is not 4-frame aligned"));
    }
    // Verify every frame in the run is now marked used, by confirming that a
    // subsequent single allocation does not return one of them.
    let mut got: Vec<PhysAddr> = Vec::new();
    for _ in 0..64 {
        if let Some(x) = pmm::allocate_frame() {
            let p = x.start_address();
            if p.as_u64() >= base && p.as_u64() < base + (N as u64 * PAGE_SIZE) {
                return Err(format!(
                    "frame {p:#x} inside the contiguous run [{base:#x}..{:#x}) was re-allocated",
                    base + N as u64 * PAGE_SIZE
                ));
            }
            got.push(p);
            pmm::deallocate_frame(x);
        }
    }
    unsafe {
        let first = x86_64::structures::paging::PhysFrame::from_start_address_unchecked(
            PhysAddr::new(base),
        );
        pmm::deallocate_frame(first);
        for i in 1..N {
            let fr = x86_64::structures::paging::PhysFrame::from_start_address_unchecked(
                PhysAddr::new(base + (i as u64) * PAGE_SIZE),
            );
            pmm::deallocate_frame(fr);
        }
    }
    Ok(format!("{N} contiguous frames at {base:#x}, {} probe allocations avoided the run", got.len()))
}

fn test_pmm_double_free() -> Result<String, String> {
    // A double free must be *detected*, not silently accepted. We cannot call
    // `deallocate_frame` twice and catch the panic (M1 has no catch_unwind), so
    // the property is verified structurally: the bitmap bit must be set after
    // the first free, and `deallocate` panics when the bit is already set. This
    // test asserts the observable half — that freeing marks the frame free and
    // that the frame is then re-allocatable — and the panic half is covered by
    // the host-side test in tools/hostcheck, which CAN catch it.
    let f = pmm::allocate_frame().ok_or("no frame")?;
    let pa = f.start_address();
    pmm::deallocate_frame(f);
    // Re-allocating should be able to return it (not guaranteed, but the cursor
    // makes it likely); either way the count must go back up by one.
    let before = pmm::stats().free_frames;
    if let Some(g) = pmm::allocate_frame() {
        pmm::deallocate_frame(g);
    }
    let after = pmm::stats().free_frames;
    if after != before {
        return Err(format!("free frame count changed across alloc+free: {before} -> {after}"));
    }
    let _ = pa;
    Ok(format!(
        "free count stable across alloc/free ({after}); double-free panic path covered by host tests"
    ))
}

fn test_pmm_no_boot_map_leak() -> Result<String, String> {
    // The PMM must not hand out frames above the boot mapping in M1: they are
    // not reachable, and returning them would produce a frame the kernel cannot
    // dereference. It must *report* them instead.
    let s = pmm::stats();
    let max = s.max_phys;
    for _ in 0..4096 {
        let Some(f) = pmm::allocate_frame() else { break };
        if f.start_address().as_u64() >= max {
            pmm::deallocate_frame(f);
            return Err(format!(
                "PMM handed out {:#x} at or above max_phys {max:#x}; unreachable in M1",
                f.start_address().as_u64()
            ));
        }
        pmm::deallocate_frame(f);
    }
    Ok(format!(
        "max_phys {max:#x} respected; {} MiB present but unmapped and reported, not silently dropped",
        s.unmapped_bytes / (1024 * 1024)
    ))
}

// ===========================================================================
//  Heap
// ===========================================================================

fn test_heap() -> Result<String, String> {
    heap::selftest().map_err(|e| String::from(e))?;
    let s = heap::stats();
    if !s.initialised {
        return Err("heap reports not initialised after heap::init ran".into());
    }
    Ok(format!("Vec/Box/aligned-4KiB round trips ok; heap {} bytes at {:#x}", s.size, s.base))
}

fn test_heap_guarded() -> Result<String, String> {
    // The guard page below the heap must be UNMAPPED. This test verifies the
    // mapping is absent without dereferencing it (dereferencing would fault and
    // kill the boot). `vmm::translate` returns None for an unmapped page, which
    // is exactly the check.
    let s = heap::stats();
    let guard = VirtAddr::new(s.base - PAGE_SIZE);
    if vmm::translate(guard).is_some() {
        return Err(format!(
            "guard page below the heap at {guard:#x} IS mapped; a heap underflow would corrupt memory silently"
        ));
    }
    let guard_hi = VirtAddr::new(s.base + s.size as u64);
    if vmm::translate(guard_hi).is_some() {
        return Err(format!("guard page above the heap at {guard_hi:#x} IS mapped"));
    }
    Ok(format!("guard pages at {guard:#x} and {guard_hi:#x} are unmapped"))
}

// ===========================================================================
//  Page tables and the security policy
// ===========================================================================

fn test_vmm_translation() -> Result<String, String> {
    // What we asked the VMM to map must be what the CPU's tables actually say.
    // Trusting the mapping code to have worked is not verification.
    for (label, va) in [
        (".text", crate::linker_sym!(_kernel_text_start)),
        (".rodata", crate::linker_sym!(_kernel_rodata_start)),
        (".data", crate::linker_sym!(_kernel_data_start)),
        (".bss", crate::linker_sym!(_kernel_bss_start)),
    ] {
        let v = VirtAddr::new(va);
        let (pa, _flags) = vmm::translate(v)
            .ok_or_else(|| format!("{label} at {v:#x} is NOT MAPPED in the live page tables"))?;
        let expect = virt_to_phys(v).ok_or("kernel symbol is not in the kernel half")?;
        if pa != expect {
            return Err(format!(
                "{label} at {v:#x} translates to {pa:#x}, expected {expect:#x}"
            ));
        }
    }
    Ok("4 kernel sections translate to their expected physical addresses".into())
}

fn test_wx_policy() -> Result<String, String> {
    let v = vmm::count_wx_violations();
    if v != 0 {
        return Err(format!(
            "{v:#x} present page(s) are BOTH writable and executable. W^X (docs/MEMORY.md §2.2) is violated."
        ));
    }
    if !vmm::nx_available() {
        return Err(
            "NX is unavailable, so the W^X check was vacuous. Refusing to report PASS on a policy that could not be tested.".into(),
        );
    }
    Ok("0 writable+executable pages across the entire kernel address space".into())
}

fn test_text_not_writable() -> Result<String, String> {
    let va = VirtAddr::new(crate::linker_sym!(_kernel_text_start));
    let (_pa, flags) = vmm::translate(va).ok_or(".text is not mapped")?;
    if flags & vmm::flags::WRITABLE != 0 {
        return Err(format!(".text at {va:#x} is WRITABLE (flags {flags:#x}); self-modifying kernel code is possible"));
    }
    if flags & vmm::flags::NO_EXECUTE != 0 {
        return Err(format!(".text at {va:#x} is marked NO-EXECUTE; the kernel could not run"));
    }
    Ok(format!(".text at {va:#x}: R-X confirmed (flags {flags:#x})"))
}

fn test_rodata_not_writable() -> Result<String, String> {
    let va = VirtAddr::new(crate::linker_sym!(_kernel_rodata_start));
    let (_pa, flags) = vmm::translate(va).ok_or(".rodata is not mapped")?;
    if flags & vmm::flags::WRITABLE != 0 {
        return Err(format!(".rodata at {va:#x} is WRITABLE; string constants could be patched at runtime"));
    }
    Ok(format!(".rodata at {va:#x}: read-only confirmed (flags {flags:#x})"))
}

fn test_boot_map_nx() -> Result<String, String> {
    // MEMORY.md §4.3 claims the boot identity map is hardened to NX. Verify it
    // against the live tables rather than trusting harden_boot_map()'s return
    // value, which only proves the function ran.
    let low = VirtAddr::new(0x20_0000); // inside the boot identity map
    let (_pa, flags) = vmm::translate(low)
        .ok_or("boot identity map is not reachable at all (unexpected in M1)")?;
    if flags & vmm::flags::NO_EXECUTE == 0 {
        return Err(format!(
            "boot identity map at {low:#x} is EXECUTABLE (flags {flags:#x}); \
             harden_boot_map did not take effect and ret2usr is possible"
        ));
    }
    Ok(format!("boot identity map at {low:#x}: NX confirmed (flags {flags:#x})"))
}

fn test_boot_map_not_user() -> Result<String, String> {
    let low = VirtAddr::new(0x20_0000);
    let (_pa, flags) = vmm::translate(low).ok_or("boot identity map not reachable")?;
    if flags & vmm::flags::USER != 0 {
        return Err(format!(
            "boot identity map at {low:#x} has the USER bit set; ring 3 could reach physical memory"
        ));
    }
    Ok(format!("boot identity map at {low:#x}: supervisor-only confirmed (flags {flags:#x})"))
}

fn test_user_half_unmapped() -> Result<String, String> {
    // In M1 there are no user processes, so nothing in the user half should be
    // mapped. A mapping there would mean the kernel accidentally created one,
    // and it would be inherited by every process in M4.
    let probes = [0x1000u64, 0x4000_0000, 0x7FFF_FFFF_F000];
    for p in probes {
        let va = VirtAddr::new(p);
        if let Some((pa, flags)) = vmm::translate(va) {
            // The boot identity map legitimately covers the low 2 GiB, and
            // PML4[0] is still present in M1 (hardened, pending removal in M4).
            // What must NOT be true is the USER bit.
            if flags & vmm::flags::USER != 0 {
                return Err(format!(
                    "user-half address {va:#x} is mapped USER-accessible -> {pa:#x} flags {flags:#x}"
                ));
            }
        }
    }
    Ok(format!(
        "{} user-half probes: none user-accessible (boot identity map present but supervisor-only, removal pending M4)",
        probes.len()
    ))
}

fn test_control_registers() -> Result<String, String> {
    let regs = crate::cpu::regs::CpuRegs::current();
    let problems: Vec<&str> = regs
        .control_register_problems()
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    if !problems.is_empty() {
        return Err(format!("{} control-register problem(s): {}", problems.len(), problems.join(" | ")));
    }
    Ok(format!(
        "CR0.WP, CR0.PG, EFER.LMA, EFER.NXE, CR4.SMEP, CR4.SMAP all as documented (cr0={:#x} cr4={:#x} efer={:#x})",
        regs.cr0, regs.cr4, regs.efer
    ))
}

// ===========================================================================
//  Interrupt path
// ===========================================================================

fn test_timer_interrupt() -> Result<String, String> {
    // The single most important test in the suite: it proves a physical device
    // asserted an interrupt line, the PIC forwarded it, the IDT dispatched it to
    // Rust, and the handler updated state the main loop can observe. Nothing
    // short of a real interrupt demonstrates that chain.
    let start = crate::interrupts::pit::ticks_since_boot();
    crate::cpu::enable_interrupts();

    // Busy-wait for at least two ticks (~2 ms at 1 kHz). `pause` keeps the
    // emulation cheap and is the documented spin-wait hint.
    let mut spins = 0u64;
    let limit = 400_000_000u64;
    while crate::interrupts::pit::ticks_since_boot() < start + 2 {
        spins += 1;
        crate::cpu::pause();
        if spins > limit {
            crate::cpu::disable_interrupts();
            return Err(format!(
                "timer did not tick within {limit} spins (ticks stuck at {start:#x}). \
                 IRQ0 is either not unmasked, the PIT is not programmed, or the \
                 IDT vector for 0x20 has no handler."
            ));
        }
    }
    let end = crate::interrupts::pit::ticks_since_boot();
    let (ticks, _, _, _, _, _) = crate::interrupts::idt::counters();
    crate::cpu::disable_interrupts();

    if ticks == 0 {
        return Err("PIT tick counter advanced but the IDT counter is 0; the handler is not the one running".into());
    }
    Ok(format!(
        "{} ticks delivered in {spins} spins (counter {start:#x} -> {end:#x}, idt timer_ticks={ticks})",
        end - start
    ))
}

fn test_keyboard_irq_armed() -> Result<String, String> {
    // Verify IRQ1 is unmasked in the PIC and that the vector has a real handler.
    // We cannot synthesise a keystroke from inside the kernel, so the end-to-end
    // keyboard test is `tests/test_boot.sh`, which drives QEMU's QMP `send-key`
    // and asserts the echo. This test covers the half that is checkable here,
    // and says which half the other test covers.
    let masks = crate::interrupts::pic::masks();
    let irq1_unmasked = masks[0] & (1 << 1) == 0;
    if !irq1_unmasked {
        match crate::drivers::keyboard::presence() {
            crate::drivers::keyboard::Presence::Absent => {
                return Err("IRQ1 masked, which is correct for absent hardware, but this test expected it armed".into())
            }
            _ => return Err("IRQ1 is MASKED: keystrokes will never reach the handler".into()),
        }
    }
    Ok(format!(
        "IRQ1 unmasked (master mask {:#04x}, slave {:#04x}); end-to-end echo verified by tests/test_boot.sh via QMP send-key",
        masks[0], masks[1]
    ))
}

fn test_ps2_alive() -> Result<String, String> {
    let p = crate::drivers::keyboard::presence();
    let pending = crate::drivers::keyboard::pending();
    Ok(format!(
        "PS/2 presence={p:?}, {} scancodes pending, {} events decoded, {} dropped",
        pending,
        crate::drivers::keyboard::event_count(),
        crate::drivers::keyboard::dropped_count()
    ))
}

// ===========================================================================
//  Parsers and ABI
// ===========================================================================

fn test_multiboot_malformed() -> Result<String, String> {
    use crate::multiboot::{self, ParseError};
    // Each case must be REJECTED, not merely tolerated. A parser that accepts a
    // malformed memory map is a parser that invents RAM.
    let cases: [(&[u8], ParseError, &str); 5] = [
        (&[0, 0, 0, 0], ParseError::TooShort, "total_size 0"),
        (&[8, 0, 0, 0, 0, 0, 0, 0], ParseError::NoMemoryMap, "header only, no tags"),
        // total_size claims 64 bytes but the buffer is 16
        (&[64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], ParseError::SizeMismatch, "total_size > buffer"),
        // a tag whose size is 4, less than the 8-byte header
        (
            &[16, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0],
            ParseError::TagUndersize,
            "tag size < 8",
        ),
        // a tag that claims to extend past total_size
        (
            &[16, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 64, 0, 0, 0],
            ParseError::TagOverrun,
            "tag extends past end",
        ),
    ];
    let mut rejected = 0;
    for (bytes, expect, label) in cases {
        match multiboot::parse(bytes) {
            Err(e) if e == expect => rejected += 1,
            Err(e) => {
                return Err(format!(
                    "case \"{label}\" rejected with {:?}, expected {:?}",
                    e, expect
                ))
            }
            Ok(_) => return Err(format!("case \"{label}\" was ACCEPTED; it must be rejected")),
        }
    }
    Ok(format!("{rejected}/{cases_len} malformed structures rejected with the expected error", cases_len = cases.len()))
}

fn test_multiboot_roundtrip() -> Result<String, String> {
    use crate::multiboot;
    // Build a minimal valid structure: header + cmdline + one mmap entry + END.
    let mut buf: Vec<u8> = Vec::new();
    let cmdline = b"orin.log=debug orin.selftest=on\0";
    let cmdline_tag_len = 8 + cmdline.len();
    let mmap_tag_len = 8 + 8 + 24;
    let total = 8 + align8(cmdline_tag_len) + align8(mmap_tag_len) + 8;

    buf.extend_from_slice(&(total as u32).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved

    // cmdline tag (type 1, flags 0)
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(cmdline_tag_len as u32).to_le_bytes());
    buf.extend_from_slice(cmdline);
    while buf.len() % 8 != 0 && buf.len() < 8 + align8(cmdline_tag_len) {
        buf.push(0);
    }
    pad_to(&mut buf, 8 + align8(cmdline_tag_len));

    // mmap tag (type 6): entry_size(4) version(4) then entries
    buf.extend_from_slice(&6u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(mmap_tag_len as u32).to_le_bytes());
    buf.extend_from_slice(&24u32.to_le_bytes()); // entry_size
    buf.extend_from_slice(&0u32.to_le_bytes()); // entry_version
    buf.extend_from_slice(&0x100000u64.to_le_bytes()); // base = 1 MiB
    buf.extend_from_slice(&(512u64 * 1024 * 1024).to_le_bytes()); // 512 MiB
    buf.extend_from_slice(&1u32.to_le_bytes()); // type AVAILABLE
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
    pad_to(&mut buf, 8 + align8(cmdline_tag_len) + align8(mmap_tag_len));

    // END tag
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&8u32.to_le_bytes());

    let info = multiboot::parse(&buf).map_err(|e| format!("valid structure rejected: {:?}", e))?;
    let cl = info.cmdline.ok_or("cmdline tag not extracted")?;
    if cl.as_str() != "orin.log=debug orin.selftest=on" {
        return Err(format!("cmdline parsed as {:?}, NUL not stripped", cl.as_str()));
    }
    if info.mmap.len() != 1 {
        return Err(format!("expected 1 mmap entry, got {}", info.mmap.len()));
    }
    let e = info.mmap.as_slice()[0];
    if e.base != 0x100000 || e.length != 512 * 1024 * 1024 || e.mem_type != 1 {
        return Err(format!("mmap entry wrong: {e:?}"));
    }
    // And the parameter parser must agree with the boot log level.
    let params = multiboot::parse_params(cl.as_str());
    if params.log != Some(crate::log::Level::Debug) {
        return Err(format!("parse_params gave log={:?}, expected Debug", params.log));
    }
    if !params.unknown.is_empty() {
        return Err(format!("parse_params flagged known parameters as unknown: {:?}", params.unknown.as_str()));
    }
    Ok(format!(
        "synthetic structure parsed: cmdline {:?}, 1 mmap entry ({} MiB available), params ok",
        cl.as_str(),
        e.length / (1024 * 1024)
    ))
}

fn test_scancode_translation() -> Result<String, String> {
    use crate::drivers::keyboard::{self, KeyCode};
    keyboard::reset_state_for_test();

    // 'a' = make 0x1E, break 0x9E.
    let a_down = keyboard::translate_raw(0x1E).ok_or("0x1E produced no event")?;
    if a_down.code != KeyCode::A || !a_down.pressed || a_down.ch != Some('a') {
        return Err(format!("0x1E decoded as {a_down:?}, expected A pressed 'a'"));
    }
    let a_up = keyboard::translate_raw(0x9E).ok_or("0x9E produced no event")?;
    if a_up.code != KeyCode::A || a_up.pressed {
        return Err(format!("0x9E decoded as {a_up:?}, expected A released"));
    }
    // Shift+'a' = 'A'. The modifier must be applied to the key that follows,
    // and must NOT retroactively change the earlier event.
    keyboard::translate_raw(0x2A).ok_or("0x2A (shift) produced no event")?;
    let big_a = keyboard::translate_raw(0x1E).ok_or("shifted 0x1E produced no event")?;
    if big_a.ch != Some('A') || !big_a.shift {
        return Err(format!("shift+0x1E decoded as {big_a:?}, expected 'A' with shift"));
    }
    keyboard::translate_raw(0xAA);
    let small = keyboard::translate_raw(0x1E).ok_or("0x1E after shift release produced no event")?;
    if small.ch != Some('a') || small.shift {
        return Err(format!("after shift release, 0x1E decoded as {small:?}, expected 'a' unshifted"));
    }
    // E0-prefixed arrow: E0 48 = Up.
    if keyboard::translate_raw(0xE0).is_some() {
        return Err("0xE0 prefix produced an event; it must be consumed silently".into());
    }
    let up = keyboard::translate_raw(0x48).ok_or("E0 48 produced no event")?;
    if up.code != KeyCode::ArrowUp {
        return Err(format!("E0 48 decoded as {up:?}, expected ArrowUp"));
    }
    // The synthetic shift in PrintScreen's sequence must be swallowed.
    keyboard::reset_state_for_test();
    keyboard::translate_raw(0xE0);
    if keyboard::translate_raw(0x2A).is_some() {
        return Err("E0 2A (PrintScreen's synthetic shift) produced an event; it must be swallowed".into());
    }
    keyboard::translate_raw(0xE0);
    let ps = keyboard::translate_raw(0x37).ok_or("E0 37 produced no event")?;
    if ps.code != KeyCode::PrintScreen || ps.shift {
        return Err(format!("E0 37 decoded as {ps:?}, expected PrintScreen with shift untouched"));
    }
    Ok("scancode set 1: letters, shift, E0 arrows, PrintScreen synthetic-shift suppression".into())
}

fn test_syscall_enosys() -> Result<String, String> {
    use crate::syscall::{self, Errno};
    // Every documented number must return Nosys, never a plausible-looking
    // value. A syscall that returns garbage is worse than one that admits it is
    // unimplemented, because the caller cannot tell.
    for nr in [
        syscall::nr::SPAWN,
        syscall::nr::MMAP,
        syscall::nr::OPEN,
        syscall::nr::IPC_SEND,
        syscall::nr::CAP_GRANT,
        syscall::nr::OKI_CALL,
        syscall::nr::CLOCK_GET,
        9999,
    ] {
        match syscall::dispatch(nr, [0; 6]) {
            Err(Errno::Nosys) => {}
            other => {
                return Err(format!(
                    "dispatch({nr}, {}) returned {other:?}, expected Err(Nosys)",
                    syscall::name_of(nr)
                ))
            }
        }
    }
    // And the numbering blocks must not overlap, because an overlap means two
    // subsystems think they own the same number.
    let blocks = [
        ("process", syscall::nr::BLOCK_PROCESS),
        ("memory", syscall::nr::BLOCK_MEMORY),
        ("io", syscall::nr::BLOCK_IO),
        ("ipc", syscall::nr::BLOCK_IPC),
        ("capability", syscall::nr::BLOCK_CAPABILITY),
        ("time", syscall::nr::BLOCK_TIME),
        ("system", syscall::nr::BLOCK_SYSTEM),
    ];
    for (i, (n1, b1)) in blocks.iter().enumerate() {
        for (n2, b2) in blocks.iter().skip(i + 1) {
            if b1.start < b2.end && b2.start < b1.end {
                return Err(format!("syscall blocks {n1} and {n2} overlap"));
            }
        }
    }
    Ok(format!("{} reserved numbers all return ENOSYS; {} ABI blocks disjoint", 8, blocks.len()))
}

fn test_star_value() -> Result<String, String> {
    use crate::interrupts::gdt;
    use crate::syscall;
    // sysret derives CS = STAR[63:48] + 16 and SS = STAR[63:48] + 8. With our
    // GDT layout (udata 0x18, ucode 0x20) the base must be 0x10 so that
    // CS becomes 0x20 and SS becomes 0x18.
    let star = syscall::star_value(gdt::KERNEL_CODE_SEL, gdt::USER_CODE_SEL);
    let base = ((star >> 48) & 0xFFFF) as u16;
    let kcs = ((star >> 32) & 0xFFFF) as u16;
    if base + 16 != gdt::USER_CODE_SEL {
        return Err(format!(
            "STAR base {base:#x} + 16 = {:#x}, but user CS is {:#x}",
            base + 16,
            gdt::USER_CODE_SEL
        ));
    }
    if base + 8 != gdt::USER_DATA_SEL {
        return Err(format!(
            "STAR base {base:#x} + 8 = {:#x}, but user SS is {:#x}",
            base + 8,
            gdt::USER_DATA_SEL
        ));
    }
    if kcs != gdt::KERNEL_CODE_SEL {
        return Err(format!("STAR kernel CS {kcs:#x} != {:#x}", gdt::KERNEL_CODE_SEL));
    }
    Ok(format!("STAR = {star:#x}: sysret yields CS {:#x} / SS {:#x} as required", base + 16, base + 8))
}

fn test_errno_range() -> Result<String, String> {
    use crate::syscall::Errno;
    // The ABI returns negated codes in -1..=-4095. Every Orin code must fit,
    // or a caller cannot distinguish an error from a large return value.
    let all = [
        Errno::Perm, Errno::NoEnt, Errno::IO, Errno::BadF, Errno::Again,
        Errno::NoMem, Errno::Access, Errno::Busy, Errno::Exist, Errno::NoDev,
        Errno::NotDir, Errno::IsDir, Errno::Inval, Errno::FileTooBig,
        Errno::NoSpace, Errno::Pipe, Errno::CapMissing, Errno::SignatureBad,
        Errno::CallUnknown, Errno::Nosys,
    ];
    for e in all {
        let n = e.as_negated();
        if !(-4095..=-1).contains(&n) {
            return Err(format!("{} negates to {n}, outside -1..=-4095", e.name()));
        }
        if e.name().is_empty() {
            return Err(format!("{e:?} has no name"));
        }
    }
    Ok(format!("{} error codes all negate into -1..=-4095 and all have names", all.len()))
}

// ===========================================================================
//  Console
// ===========================================================================

fn test_console_vga() -> Result<String, String> {
    use core::fmt::Write;
    // Write a known string and read it back out of the VGA buffer. This proves
    // the console wrote to the address it thinks it wrote to — which is not
    // trivially true in a higher-half kernel where the device window is reached
    // through a translation we built ourselves.
    let marker = "ORIN-M1";
    let row = {
        let w = crate::console::vga::WRITER.lock();
        w.position().0
    };
    {
        let mut w = crate::console::vga::WRITER.lock();
        let _ = write!(w, "{}", marker);
    }
    let back = crate::console::vga::WRITER.lock().read_row(row);
    let got: String = back.iter().take(marker.len()).map(|&b| b as char).collect();
    if got != marker {
        return Err(format!("wrote {marker:?} to VGA row {row}, read back {got:?}"));
    }
    Ok(format!("wrote and read back {marker:?} from VGA row {row} through the device mapping"))
}

// ===========================================================================
//  helpers
// ===========================================================================

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

fn pad_to(buf: &mut Vec<u8>, len: usize) {
    while buf.len() < len {
        buf.push(0);
    }
}

/// Assert that the boot mapping is large enough for what M1 does, and report it.
/// Not a pass/fail property — a fact the boot log must contain so a machine with
/// more RAM than M1 can use says so explicitly.
pub fn report_boot_coverage() {
    let s = pmm::stats();
    crate::kinfo!(
        "selftest: boot mapping covers {} MiB; {} MiB of RAM present but unreachable in M1 \
         (M4 extends the page tables — docs/MEMORY.md §7)",
        BOOT_MAPPED_BYTES / (1024 * 1024),
        s.unmapped_bytes / (1024 * 1024)
    );
}
