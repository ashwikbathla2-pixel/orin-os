//! Kernel panic handler.
//!
//! A kernel panic is the last diagnostic the system will ever produce about
//! itself, so it is engineered like one: it must work when the thing that broke
//! is the console, the heap, or the page tables, and it must say enough that the
//! bug can be found without reproducing it.
//!
//! ## Constraints this code is written under
//!
//! * It may run on an IST stack with the normal kernel stack already blown.
//! * It may run with the heap exhausted — so **no allocation** anywhere on this
//!   path. Everything is fixed-size or `format_args!` straight to a writer.
//! * It may run with interrupts enabled or disabled; it disables them, because a
//!   panic that is itself interrupted produces interleaved output nobody can
//!   read.
//! * **It must not take any lock.** `console::log` writes through mutex-guarded
//!   consoles, and a plausible cause of the panic is that we panicked *while
//!   holding one*. `spin::Mutex` is not re-entrant, so calling into the log
//!   layer from here would deadlock and produce zero output — strictly worse
//!   than the panic itself. All output therefore goes through
//!   [`crate::console::raw`], which touches only port I/O and the VGA buffer.
//! * It must be re-entrancy safe: if the panic handler panics, the second panic
//!   must not recurse into the first and consume the IST stack. A flag turns
//!   recursion into an immediate halt with the marker `ORIN|P|RECURSIVE`.
//!
//! ## The marker lines
//!
//! `ORIN-PANIC-BEGIN` / `ORIN-PANIC-END` bracket the report on serial. The QEMU
//! test harness greps for them, which is how `make test` distinguishes "booted
//! and idled" from "booted, printed a nice banner, then panicked" — a
//! distinction a human watching a window makes by eye and an automated build
//! cannot make any other way.


use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::cpu::regs::CpuRegs;
use crate::multiboot::PanicAction;
use crate::raw_println;

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

}


static PANICKING: AtomicBool = AtomicBool::new(false);
static PANIC_COUNT: AtomicU64 = AtomicU64::new(0);

/// Configured panic action, set from `orin.panic=` during init.
static ACTION: AtomicU64 = AtomicU64::new(PanicAction::Halt as u64);

pub fn set_panic_action(a: PanicAction) {
    ACTION.store(a as u64, Ordering::Relaxed);
}

pub fn panic_action() -> PanicAction {
    let v = ACTION.load(Ordering::Relaxed);
    if v == PanicAction::Reboot as u64 {
        PanicAction::Reboot
    } else if v == PanicAction::Triple as u64 {
        PanicAction::Triple
    } else {
        PanicAction::Halt
    }
}

pub fn panic_count() -> u64 {
    PANIC_COUNT.load(Ordering::Relaxed)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Interrupts off first. A panic interrupted by a timer tick produces two
    // interleaved reports on one serial line, which destroys the evidence.
    x86_64::instructions::interrupts::disable();

    let n = PANIC_COUNT.fetch_add(1, Ordering::Relaxed) + 1;

    // Re-entrancy guard. If we are already inside a panic, the handler itself is
    // what broke; recursing would consume the IST stack and triple-fault, losing
    // the original message.
    if PANICKING.swap(true, Ordering::Relaxed) {
        raw_println!("ORIN|P|RECURSIVE|panic handler panicked; halting");
        raw_println!("ORIN-PANIC-END");
        action();
    }

    raw_println!("\nORIN-PANIC-BEGIN");
    raw_println!("ORIN|P|PANIC|{}", info.message());
    if let Some(loc) = info.location() {
        raw_println!("ORIN|P|PANIC|  at {}:{}:{}", loc.file(), loc.line(), loc.column());
    }

    // Register dump. This is the *current* register state, not a faulting
    // instruction's — from a `panic!` there is no fault, so "current" is the
    // correct and only available answer. (In `idt.rs`, where an interrupted
    // frame exists, that frame is used instead.)
    let regs = current_regs();
    raw_println!(
        "ORIN|P|PANIC|  rip {:#018x}  rsp {:#018x}  rflags {:#018x}  cs {:#x}  ss {:#x}",
        regs.rip, regs.rsp, regs.rflags, regs.cs, regs.ss
    );
    raw_println!("ORIN|P|PANIC|{}", regs.format_general());
    raw_println!("ORIN|P|PANIC|{}", regs.format_control());

    // Control-register problems are reported even during a panic: a panic caused
    // by missing SMEP/NXE/WP is a panic whose root cause is invisible in the
    // register values themselves.
    for problem in regs.control_register_problems() {
        if !problem.is_empty() {
            raw_println!("ORIN|P|PANIC|  SECURITY: {}", problem);
        }
    }

    // Where in the kernel image? An offset from .text plus the exact `addr2line`
    // invocation makes the report actionable from a serial log alone — no
    // debugger, no core dump.
    let rip = regs.rip;
    if rip >= crate::arch::KERNEL_VMA {
        let text_start = crate::linker_sym!(_kernel_text_start);
        raw_println!("ORIN|P|PANIC|  rip offset from .text: {:#x}", rip.wrapping_sub(text_start));
        raw_println!(
            "ORIN|P|PANIC|  resolve: llvm-addr2line -e build/orin_kernel.elf -f -C -i {:#x}",
            rip
        );
    } else {
        raw_println!(
            "ORIN|P|PANIC|  rip {:#x} is BELOW the kernel half — execution left kernel \
             space. Corrupted return address or a jump through a bad function pointer, \
             not an ordinary kernel bug.",
            rip
        );
    }

    // Backtrace via frame pointers. `.cargo/config.toml` sets
    // `force-frame-pointers=yes` precisely so this works without unwinding
    // tables: .eh_frame is exactly the thing most likely to be corrupt in a
    // memory-corruption panic.
    raw_println!("ORIN|P|PANIC|  --- backtrace (frame pointers) ---");
    backtrace(regs.rbp);

    // Subsystem state, so a panic can be correlated with what had actually
    // initialised. A panic before `pmm::init` and one after have completely
    // different sets of possible causes.
    raw_println!("ORIN|P|PANIC|  --- subsystem state ---");
    raw_println!("ORIN|P|PANIC|  pmm initialised: {}", crate::memory::pmm::is_initialised());
    let ps = crate::memory::pmm::stats();
    raw_println!(
        "ORIN|P|PANIC|  pmm: {} free / {} total frames, {} reserved, {} bad, {} MiB unmapped",
        ps.free_frames, ps.total_frames, ps.reserved_frames, ps.bad_frames,
        ps.unmapped_bytes / (1024 * 1024)
    );
    let hs = crate::memory::heap::stats();
    raw_println!("ORIN|P|PANIC|  heap: {} bytes at {:#x}, initialised={}", hs.size, hs.base, hs.initialised);
    let (ticks, keys, spurious, exceptions, unassigned, syscalls) = crate::interrupts::idt::counters();
    raw_println!(
        "ORIN|P|PANIC|  interrupts: ticks={} keys={} spurious={} exceptions={} unassigned={} syscalls={}",
        ticks, keys, spurious, exceptions, unassigned, syscalls
    );
    raw_println!(
        "ORIN|P|PANIC|  keyboard: presence={:?} events={} pending={} dropped={}",
        crate::drivers::keyboard::presence(),
        crate::drivers::keyboard::event_count(),
        crate::drivers::keyboard::pending(),
        crate::drivers::keyboard::dropped_count()
    );
    let (emitted, filtered) = crate::console::log::stats();
    raw_println!("ORIN|P|PANIC|  log: {} records emitted, {} filtered", emitted, filtered);
    raw_println!("ORIN|P|PANIC|  panic #{}", n);

    raw_println!("ORIN-PANIC-END");
    action()
}

// ---------------------------------------------------------------------------
// Register capture
// ---------------------------------------------------------------------------

fn current_regs() -> CpuRegs {
    let mut r = CpuRegs::default();
    use x86_64::registers::control::{Cr0, Cr2, Cr3, Cr4};
    use x86_64::registers::model_specific::Efer;

    macro_rules! reg {
        ($field:ident, $name:literal) => {
            // SAFETY: reads a named general register. No side effects, no memory
            // access, no flags modified.
            unsafe {
                core::arch::asm!(
                    concat!("mov {}, ", $name),
                    lateout(reg) r.$field,
                    options(nostack, nomem, preserves_flags)
                );
            }
        };
    }
    reg!(rax, "rax");
    reg!(rbx, "rbx");
    reg!(rcx, "rcx");
    reg!(rdx, "rdx");
    reg!(rsi, "rsi");
    reg!(rdi, "rdi");
    reg!(rbp, "rbp");
    reg!(r8, "r8");
    reg!(r9, "r9");
    reg!(r10, "r10");
    reg!(r11, "r11");
    reg!(r12, "r12");
    reg!(r13, "r13");
    reg!(r14, "r14");
    reg!(r15, "r15");

    // These four cannot be expressed by `reg!`: `mov rax, rip` is not
    // encodable, and the segment/flags registers need different forms.
    // SAFETY: `lea rax, [rip]` reads the instruction pointer.
    unsafe {
        core::arch::asm!("lea {}, [rip]", lateout(reg) r.rip, options(nostack, nomem, preserves_flags));
    }
    // SAFETY: `pushfq; pop rax` reads RFLAGS. Pushing is safe because the panic
    // handler runs on a valid stack (the normal kernel stack or an IST stack).
    unsafe {
        core::arch::asm!("pushfq", "pop {}", lateout(reg) r.rflags, options(nostack, nomem));
    }
    // SAFETY: `mov rax, cs` / `mov rax, ss` zero-extend the 16-bit selectors.
    unsafe {
        core::arch::asm!("mov {0:x}, cs", lateout(reg) r.cs, options(nostack, nomem, preserves_flags));
        core::arch::asm!("mov {0:x}, ss", lateout(reg) r.ss, options(nostack, nomem, preserves_flags));
    }

    r.cr0 = Cr0::read_raw();
    r.cr2 = Cr2::read_raw();
    r.cr3 = Cr3::read_raw().0.start_address().as_u64();
    r.cr4 = Cr4::read_raw();
    r.efer = Efer::read_raw();
    r
}

// ---------------------------------------------------------------------------
// Backtrace
// ---------------------------------------------------------------------------

/// Walk the frame-pointer chain and print return addresses.
///
/// Bounded, and every frame pointer is validated *before* dereference. A
/// backtrace through a corrupted stack must not itself fault, or the panic
/// handler becomes the second failure and the first is lost. Validation is
/// "in the kernel half, 16-byte aligned, strictly increasing" — cheap, and it
/// catches every shape of stack corruption that matters.
fn backtrace(mut rbp: u64) {
    let text_start = crate::linker_sym!(_kernel_text_start);
    let text_end = crate::linker_sym!(_kernel_text_end);
    const MAX_FRAMES: usize = 24;

    for depth in 0..MAX_FRAMES {
        if !valid_frame_pointer(rbp) {
            raw_println!(
                "ORIN|P|PANIC|  #{:<2} frame pointer {:#x} is not a plausible kernel stack \
                 address; stopping rather than faulting inside the panic handler",
                depth, rbp
            );
            return;
        }
        // SAFETY: `valid_frame_pointer` established that `rbp` is inside the
        // kernel half (hence mapped — the whole kernel image is) and 16-byte
        // aligned, so `rbp` and `rbp+8` are readable. A stack corrupt enough to
        // break that is caught by the validation, not by this read.
        let (saved_rbp, ret_addr) = unsafe {
            let p = rbp as *const u64;
            (*p, *p.add(1))
        };

        let in_text = ret_addr >= text_start && ret_addr < text_end;
        raw_println!(
            "ORIN|P|PANIC|  #{:<2} {:#018x}{} (rbp {:#x})",
            depth, ret_addr, if in_text { "" } else { " [NOT in .text]" }, saved_rbp
        );
        if !in_text {
            raw_println!(
                "ORIN|P|PANIC|       -> return address outside .text [{:#x}..{:#x}): \
                 corrupted stack, or an indirect call through a bad pointer",
                text_start, text_end
            );
            return;
        }
        // Frame pointers must increase as we walk outward. One that does not
        // means the chain is a cycle; walking further would print the same
        // frames until MAX_FRAMES, which is noise, not information.
        if saved_rbp <= rbp {
            raw_println!("ORIN|P|PANIC|       -> frame pointer did not increase; chain corrupt, stopping");
            return;
        }
        rbp = saved_rbp;
    }
    raw_println!("ORIN|P|PANIC|  truncated at MAX_FRAMES={}", MAX_FRAMES);
}

fn valid_frame_pointer(rbp: u64) -> bool {
    // Kernel half, 16-byte aligned (the x86_64 ABI requires this at call
    // boundaries), and not so close to the top of the address space that `+8`
    // would wrap.
    rbp >= crate::arch::KERNEL_VMA && rbp % 16 == 0 && rbp < u64::MAX - 16
}

// ---------------------------------------------------------------------------
// Panic actions
// ---------------------------------------------------------------------------

/// Perform the configured panic action. Never returns.
fn action() -> ! {
    match panic_action() {
        PanicAction::Halt => {
            // Halt with interrupts disabled: the machine stays up so a human can
            // read the screen and a harness can read the serial log. This is the
            // default because it is the only action that preserves evidence.
            raw_println!("ORIN|P|PANIC|action=halt; system stopped, will not reboot");
            loop {
                x86_64::instructions::hlt();
            }
        }
        PanicAction::Reboot => {
            raw_println!("ORIN|P|PANIC|action=reboot; pulsing the keyboard-controller reset line");
            // The canonical reset: write 0xFE to the PS/2 system-control port,
            // which asks the controller to drive the CPU RESET line low. Works on
            // BIOS systems and most UEFI firmware in legacy mode. UEFI-only
            // machines may ignore it, which is why the triple-fault fallback
            // below is unconditional.
            //
            // SAFETY: writes to port 0x64. 0xFE is the documented
            // pulse-reset-line command; no other bit is set, so neither the A20
            // gate nor port enables are disturbed. The status poll first drains
            // the input buffer, because a controller with a full buffer may
            // ignore the command.
            unsafe {
                let mut st: x86_64::instructions::port::Port<u8> =
                    x86_64::instructions::port::Port::new(0x64);
                for _ in 0..16 {
                    if st.read() & 0x02 == 0 {
                        break;
                    }
                }
                st.write(0xFE);
            }
            for _ in 0..10_000_000u32 {
                crate::cpu::pause();
            }
            triple_fault()
        }
        PanicAction::Triple => {
            raw_println!("ORIN|P|PANIC|action=triple; deliberately inducing a triple fault");
            triple_fault()
        }
    }
}

/// Induce a triple fault, which resets the CPU.
///
/// Load an IDT whose base address is invalid, then trigger an exception. The CPU
/// tries to deliver the exception, faults reading the IDT, raises a double
/// fault, faults delivering *that*, and resets.
///
/// Not a hack: this is the architecturally guaranteed reset path on x86, and it
/// is why `PanicAction::Reboot` can promise a reboot even on firmware that
/// ignores the keyboard-controller reset.
fn triple_fault() -> ! {
    use x86_64::structures::DescriptorTablePointer;
    use x86_64::VirtAddr;

    let bad = DescriptorTablePointer {
        limit: 0,
        // A non-canonical base: even attempting to read the IDT faults.
        base: VirtAddr::new_truncate(0),
    };
    // SAFETY: intentionally loading an invalid IDT to force a triple fault.
    // This is the last thing the kernel does; there is no state left to
    // preserve and no return path, so the usual "must not corrupt machine state"
    // reasoning does not apply.
    unsafe {
        core::arch::asm!("lidt [{}]", in(reg) &bad, options(nostack, preserves_flags));
        // Any exception now triple-faults. Division by zero is used rather than
        // `int3` because `int3` would still be handled correctly if the `lidt`
        // had somehow not taken effect, and we need something unconditionally
        // fatal. `black_box` keeps the divisor opaque so rustc does not
        // constant-fold the division into a compile-time unconditional-panic
        // error.
        let zero = core::hint::black_box(0u32);
        let _ = core::hint::black_box(1u32 / zero);
        loop {
            x86_64::instructions::hlt();
        }
    }
}
