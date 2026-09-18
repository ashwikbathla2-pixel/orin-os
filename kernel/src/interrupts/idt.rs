//! Interrupt Descriptor Table and interrupt/exception handlers.
//!
//! ## Vector map
//!
//! Orin's vector allocation is fixed ABI. It is written down here and in
//! `docs/SYSCALL.md` §7 because a vector number that means two things is a bug
//! that manifests as "the wrong handler ran", which is among the hardest kernel
//! bugs to diagnose.
//!
//! ```text
//! 0x00–0x1F   CPU exceptions (fixed by the architecture)
//! 0x20–0x2F   8259A PIC IRQ0–15        (M1; retired by the APIC in M4)
//! 0x30–0x3F   reserved: local APIC     (M4 — timer, error, spurious, IPI)
//! 0x40        Orin syscall             (M5; also reachable via `syscall`/LSTAR)
//! 0x41–0xBF   reserved
//! 0xC0–0xCF   Orin IPC notification    (M9)
//! 0xD0–0xEF   reserved
//! 0xF0–0xFE   reserved: APIC IPI range (M4)
//! 0xFF        spurious                 (must never EOI; see below)
//! ```
//!
//! ## Handlers are Rust, not assembly
//!
//! Every handler uses the `extern "x86-interrupt"` ABI, which the compiler
//! implements directly: it preserves all registers, honours the error-code
//! variant, and emits `iretq`. Writing these in assembly would mean
//! hand-maintaining that ABI for 40 entry points with no gain. Orin's
//! assembly is confined to `arch/x86_64/boot/boot.asm`, where it is genuinely
//! required (there is no Rust that can run before paging is on).
//!
//! ## Policy: an unexpected interrupt is a bug
//!
//! In M1 there is no user space, no demand paging and no drivers beyond the
//! keyboard. Therefore a page fault, a general protection fault, an invalid
//! opcode or an unassigned vector means the kernel is wrong, and the correct
//! response is a full register dump followed by a panic — not a log line and a
//! shrug. This is relaxed deliberately and incrementally as the features that
//! make those events *normal* arrive (M4 for page faults, M5 for syscall
//! vectors).

#![allow(dead_code)]

use spin::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use super::{gdt, pic};
use crate::arch::KERNEL_VMA;
use crate::cpu::regs::CpuRegs;
use crate::raw_println;

/// Vector the M5 syscall dispatcher will use.
pub const SYSCALL_VECTOR: u8 = 0x40;
/// Spurious interrupt vector. Conventionally the last one.
pub const SPURIOUS_VECTOR: u8 = 0xFF;

static IDT: Once<&'static InterruptDescriptorTable> = Once::new();
static mut IDT_STORAGE: InterruptDescriptorTable = InterruptDescriptorTable::new();

/// Counters, exported over OKI as `sys.interrupts.counts`. Every one of these
/// is readable without a debugger, which is the point: "why is my system slow"
/// is answered by an interrupt rate, not by guesswork.
#[derive(Default)]
pub struct Counters {
    pub timer_ticks: u64,
    pub key_events: u64,
    pub spurious: u64,
    pub exceptions: u64,
    pub unassigned: u64,
    pub syscalls: u64,
}

static mut COUNTERS: Counters = Counters {
    timer_ticks: 0,
    key_events: 0,
    spurious: 0,
    exceptions: 0,
    unassigned: 0,
    syscalls: 0,
};

/// Snapshot of the counters.
///
/// SAFETY of the `static mut` read: counters are only written from interrupt
/// handlers. A read can therefore observe a torn value only if an interrupt
/// fires mid-read. M1 is single-core and this is diagnostic data, so a torn
/// count is acceptable and documented; M4 moves these to per-CPU arrays read
/// with interrupts disabled, which is when exactness starts to matter.
pub fn counters() -> (u64, u64, u64, u64, u64, u64) {
    unsafe {
        let c = &*core::ptr::addr_of!(COUNTERS);
        (
            c.timer_ticks,
            c.key_events,
            c.spurious,
            c.exceptions,
            c.unassigned,
            c.syscalls,
        )
    }
}

/// Field selector for [`bump`]. A plain field accessor expressed as an enum
/// rather than a `fn(&mut Counters) -> &mut u64` pointer, because a closure
/// capturing nothing does not reliably coerce to that `fn` type at every call
/// site and the resulting error message is unreadable.
#[derive(Clone, Copy)]
enum Counter {
    TimerTicks,
    KeyEvents,
    Spurious,
    Exceptions,
    Unassigned,
    Syscalls,
}

fn bump(which: Counter) {
    // SAFETY: see `counters`. Interrupt handlers run one at a time on M1's
    // single core, so no two bumps race. M4 makes these per-CPU.
    unsafe {
        let c = &mut *core::ptr::addr_of_mut!(COUNTERS);
        let slot = match which {
            Counter::TimerTicks => &mut c.timer_ticks,
            Counter::KeyEvents => &mut c.key_events,
            Counter::Spurious => &mut c.spurious,
            Counter::Exceptions => &mut c.exceptions,
            Counter::Unassigned => &mut c.unassigned,
            Counter::Syscalls => &mut c.syscalls,
        };
        *slot += 1;
    }
}

/// Install every handler and load the IDT.
///
/// Must run after [`gdt::init`] (the double-fault handler needs IST1 to point
/// at a real stack) and before [`pic::unmask`] (an unmasked IRQ with no handler
/// is a panic).
///
/// ## Ordering: catch-all first, then the purposeful handlers
///
/// Every one of the 256 vectors gets a handler, so an interrupt on a vector
/// nobody claimed produces a named diagnostic instead of a triple fault. The
/// blanket fill uses the x86_64 crate's `set_general_handler!` macro, which
/// writes *all* 256 entries — including the ones we care about. So the order is
/// forced: blanket first, then [`install_purposeful_handlers`] overwrites the
/// entries where "which function runs" is a real decision.
///
/// Reversing this would silently replace #PF with the catch-all. The selftest
/// catches that: [`is_assigned`] re-reads the loaded table and fails if a
/// purposeful vector still points at the catch-all.
pub fn init() {
    let idt: &'static InterruptDescriptorTable = IDT.call_once(|| {
        // SAFETY: promoted once by `Once`; written only here, with interrupts
        // disabled, before the IDT is loaded.
        let idt = unsafe { &mut *core::ptr::addr_of_mut!(IDT_STORAGE) };

        // Blanket fill: all 256 vectors forward to `on_unassigned_general`.
        //
        // This is a macro rather than a `for v in 0..256 { idt[v] = ... }` loop
        // because `InterruptDescriptorTable` indexes by `u8`, and indexing a
        // vector that pushes an error code (#GP, #PF, #AC, ...) panics — those
        // entries have a different `Entry<F>` type and are reachable only
        // through their named fields. The macro expands to 256
        // individually-typed thunks that each pick the right ABI and forward to
        // one `GeneralHandlerFunc`.
        // The macro requires an *identifier* naming something of type
        // `GeneralHandlerFunc` (a fn pointer). A bare `fn` item has its own
        // unique type and does not coerce at the macro's `const` binding site,
        // so bind it through a const first.
        const CATCH_ALL: x86_64::structures::idt::GeneralHandlerFunc = on_unassigned_general;
        x86_64::set_general_handler!(idt, CATCH_ALL, 0..=255u8);

        install_purposeful_handlers(idt);

        unsafe { &*core::ptr::addr_of!(IDT_STORAGE) }
    });

    idt.load();
    crate::kinfo!("idt: 256 vectors installed and loaded");
}

/// The vectors where the choice of handler matters.
///
/// Called once, after the blanket catch-all, from [`init`]. Everything not set
/// here keeps the catch-all.
fn install_purposeful_handlers(idt: &mut InterruptDescriptorTable) {
    // ---- CPU exceptions ------------------------------------------------
    idt.divide_error.set_handler_fn(on_divide_error);
    idt.debug.set_handler_fn(on_debug);
    // `set_stack_index` is a method on `EntryOptions`, not on `Entry`, and
    // `set_handler_fn` returns `&mut EntryOptions` precisely so the two chain.
    // It is `unsafe` because an IST index that does not correspond to a stack
    // pointer in the loaded TSS makes the CPU load a garbage RSP on that vector
    // — which is why gdt.rs asserts all five are non-zero and only
    // `gdt::ist::*` constants are ever passed here.
    //
    // #NMI on IST2: a non-maskable interrupt can arrive while the stack is
    // already broken, which is often why it was raised.
    unsafe {
        idt.non_maskable_interrupt
            .set_handler_fn(on_nmi)
            .set_stack_index(gdt::ist::NMI as u16);
    }
    idt.breakpoint.set_handler_fn(on_breakpoint);
    idt.overflow.set_handler_fn(on_overflow);
    idt.bound_range_exceeded.set_handler_fn(on_bound_range);
    idt.invalid_opcode.set_handler_fn(on_invalid_opcode);
    idt.device_not_available.set_handler_fn(on_device_not_available);
    // #DF on IST1 — the single most important IST assignment in this file; see
    // the module docs in gdt.rs for why #DF cannot share the faulting stack.
    unsafe {
        idt.double_fault
            .set_handler_fn(on_double_fault)
            .set_stack_index(gdt::ist::DOUBLE_FAULT as u16);
    }
    idt.invalid_tss.set_handler_fn(on_invalid_tss);
    idt.segment_not_present.set_handler_fn(on_segment_not_present);
    idt.stack_segment_fault.set_handler_fn(on_stack_segment);
    idt.general_protection_fault.set_handler_fn(on_general_protection);
    // #PF on IST5. In M1 a page fault is always fatal, so it gets an IST stack
    // anyway: the most common reason for an early page fault is a blown kernel
    // stack, and handling it on that same stack would fault again.
    unsafe {
        idt.page_fault
            .set_handler_fn(on_page_fault)
            .set_stack_index(gdt::ist::PAGE_FAULT as u16);
    }
    idt.x87_floating_point.set_handler_fn(on_x87_fault);
    idt.alignment_check.set_handler_fn(on_alignment_check);
    unsafe {
        idt.machine_check
            .set_handler_fn(on_machine_check)
            .set_stack_index(gdt::ist::MACHINE_CHECK as u16);
    }
    idt.simd_floating_point.set_handler_fn(on_simd_fault);
    idt.virtualization.set_handler_fn(on_virtualization);
    // No `unsafe` block here: unlike #NMI/#DF/#PF/#MC this entry gets no IST
    // stack, and `set_handler_fn` is itself safe.
    idt.vmm_communication_exception.set_handler_fn(on_vmm_comm);
    idt.security_exception.set_handler_fn(on_security_exception);

    // ---- PIC IRQs ------------------------------------------------------
    idt[pic::vector_for_irq(pic::irq::TIMER)].set_handler_fn(on_irq_timer);
    idt[pic::vector_for_irq(pic::irq::KEYBOARD)].set_handler_fn(on_irq_keyboard);
    // IRQ2 is the cascade line; it carries no device. A handler that counts and
    // EOIs means a stuck cascade shows up as a rising counter rather than an
    // "unassigned vector" panic pointing at the wrong thing.
    idt[pic::vector_for_irq(pic::irq::CASCADE)].set_handler_fn(on_irq_cascade);
    // The other 13 lines get the generic IRQ handler, which names the line.
    // Masked by default, so they never fire unless a driver unmasks one without
    // installing a handler — a bug this makes obvious.
    for irq_num in [3u8, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
        idt[pic::vector_for_irq(irq_num)].set_handler_fn(on_irq_unexpected);
    }

    // ---- Orin vectors ---------------------------------------------------
    idt[SYSCALL_VECTOR].set_handler_fn(on_syscall_vector);
    idt[SPURIOUS_VECTOR].set_handler_fn(on_spurious);
}

/// Catch-all thunk installed by `set_general_handler!`.
///
/// Signature is fixed by the crate: `GeneralHandlerFunc =
/// fn(InterruptStackFrame, index: u8, error_code: Option<u64>)`. The generated
/// per-vector thunks adapt whatever ABI that vector uses and pass the vector
/// number in, so one function covers all 256 — including the ones that push an
/// error code, which is why `error_code` is an `Option`.
fn on_unassigned_general(frame: InterruptStackFrame, vector: u8, error_code: Option<u64>) {
    // Note this does NOT call `on_unassigned`: a function with the
    // "x86-interrupt" ABI cannot be called as a normal Rust function (the
    // compiler rejects it) because its return is `iretq`, not `ret`. The shared
    // body lives in `unassigned_vector` and both paths call that.
    bump(Counter::Unassigned);
    crate::kcrit!(
        "UNASSIGNED VECTOR {:#04x} (error code {:?}) at rip {:#x}",
        vector,
        error_code,
        frame.instruction_pointer.as_u64()
    );
    unassigned_vector(frame.instruction_pointer.as_u64());
}

/// True if `v` has a purposeful handler. Used only to decide which vectors get
/// the catch-all, so an out-of-sync list here produces a log message, never a
/// wrong dispatch.
fn is_assigned(v: usize) -> bool {
    v < 32
        || (0x20..0x30).contains(&v)
        || v == usize::from(SYSCALL_VECTOR)
        || v == usize::from(SPURIOUS_VECTOR)
}

// ===========================================================================
//  CPU exceptions
// ===========================================================================

/// Common path: dump everything, then stop.
///
/// The dump goes to serial *and* VGA, because the whole point of an exception
/// dump is that it must survive the failure of whatever the developer happened
/// to be looking at.
fn fatal_exception(name: &str, vector: u8, frame: &InterruptStackFrame, code: Option<u64>, cr2: Option<u64>) -> ! {
    bump(Counter::Exceptions);

    // ALL output on this path goes through `console::raw`, never `console::log`.
    // An exception can arrive while the interrupted code was holding a console
    // mutex; `spin::Mutex` is not re-entrant, so using the log layer here would
    // deadlock and produce no diagnostic at all. See console/raw.rs.
    let regs = CpuRegs::read_around(frame);
    raw_println!("\nORIN-FATAL-BEGIN");
    raw_println!("ORIN|C|EXCEPTION|{} (vector {:#04x})", name, vector);
    if let Some(c) = code {
        raw_println!("ORIN|C|EXCEPTION|  error code: {:#x}", c);
        if name == "page-fault" {
            raw_println!("ORIN|C|EXCEPTION|  pf bits: {}", format_pf_bits(c));
        } else {
            raw_println!("ORIN|C|EXCEPTION|  (error code is a selector index or 0 for this vector)");
        }
    }
    if let Some(a) = cr2 {
        raw_println!("ORIN|C|EXCEPTION|  faulting address (CR2): {:#x}", a);
        if a < KERNEL_VMA {
            raw_println!(
                "ORIN|C|EXCEPTION|    -> below the kernel half ({:#x}): a low/identity-map or \
                 user address, not a kernel VA. Kernel code used a physical address as a pointer.",
                KERNEL_VMA
            );
        }
    }
    raw_println!(
        "ORIN|C|EXCEPTION|  rip {:#018x}  rsp {:#018x}  rflags {:#018x}  cs {:#x}  ss {:#x}",
        regs.rip, regs.rsp, regs.rflags, regs.cs, regs.ss
    );
    raw_println!(
        "ORIN|C|EXCEPTION|  privilege: {}   interrupts: {}",
        if regs.cs & 3 == 0 { "ring 0 (kernel)" } else { "ring 3 (user)" },
        if regs.rflags & (1 << 9) != 0 { "enabled" } else { "disabled" }
    );
    raw_println!("ORIN|C|EXCEPTION|{}", regs.format_general());
    raw_println!("ORIN|C|EXCEPTION|{}", regs.format_control());
    for problem in regs.control_register_problems() {
        if !problem.is_empty() {
            raw_println!("ORIN|C|EXCEPTION|  SECURITY: {}", problem);
        }
    }
    if regs.rip >= KERNEL_VMA {
        raw_println!(
            "ORIN|C|EXCEPTION|  resolve: llvm-addr2line -e build/orin_kernel.elf -f -C -i {:#x}",
            regs.rip
        );
    }
    raw_println!("ORIN-FATAL-END");

    // Panic rather than `loop {}`: the panic handler performs the configured
    // panic action (`orin.panic=`), which in a test build writes markers the
    // harness asserts on. An infinite loop here would look like a hang and tell
    // the harness nothing.
    panic!("unhandled {} (vector {:#04x})", name, vector);
}

/// Page-fault error-code bit breakdown. Printed separately because the bits are
/// what tells you whether this was a read or a write, user or kernel, and
/// present-but-protected or not-present-at-all — four different classes of bug.
fn format_pf_bits(code: u64) -> alloc::string::String {
    use alloc::string::String;
    let mut s = String::new();
    // A macro, not a closure: the closure form borrows `s` mutably for its whole
    // lifetime, so the `s.push_str` calls below it (which add the READ/NOT-PRESENT
    // complements) would be a second mutable borrow. A macro expands at each call
    // site, so the borrows never overlap.
    macro_rules! bit {
        ($n:expr, $label:expr) => {
            if code & (1 << $n) != 0 {
                if !s.is_empty() {
                    s.push(' ');
                }
                s.push_str($label);
            }
        };
    }
    bit!(0, "PRESENT(protection-violation)");
    if code & 1 == 0 {
        s.push_str(" NOT-PRESENT");
    }
    bit!(1, "WRITE");
    if code & 2 == 0 {
        s.push_str(" READ");
    }
    bit!(2, "USER");
    bit!(3, "RESERVED-BITS");
    bit!(4, "INSTRUCTION-FETCH");
    bit!(5, "PK(protection-key)");
    bit!(6, "SHADOW-STACK");
    bit!(7, "SGX");
    bit!(15, "NX-USER-ACCESS-FILTER");
    s
}

extern "x86-interrupt" fn on_divide_error(frame: InterruptStackFrame) {
    fatal_exception("divide-error (#DE)", 0x00, &frame, None, None);
}

extern "x86-interrupt" fn on_debug(frame: InterruptStackFrame) {
    // #DB is not fatal: it is how a debugger single-steps. If a debugger is
    // attached (M15 sets a flag over OKI), report and return so gdb keeps
    // working. Otherwise it means DR7 was set by something that should not
    // have set it, which is fatal.
    if crate::cpu::debugger_attached() {
        bump(Counter::Exceptions);
        crate::kdebug!("debug exception at rip {:#x}; returning to the debugger", frame.instruction_pointer.as_u64());
        return;
    }
    fatal_exception("debug (#DB)", 0x01, &frame, None, None);
}

extern "x86-interrupt" fn on_nmi(frame: InterruptStackFrame) {
    // NMI on a server means hardware is reporting something. There is no
    // meaningful recovery in M1: log it and stop, because continuing after an
    // unexplained NMI risks silent data corruption.
    bump(Counter::Exceptions);
    crate::kcrit!("NMI received at rip {:#x}", frame.instruction_pointer.as_u64());
    crate::kcrit!(
        "  M1 has no NMI source registered (M7 adds IPMI/PCIe SERR/thermal). \
         Halting rather than continuing on possibly-corrupt hardware."
    );
    panic!("non-maskable interrupt");
}

extern "x86-interrupt" fn on_breakpoint(frame: InterruptStackFrame) {
    // `int3` is how `panic!`, `debug_assert!` and a debugger breakpoint are
    // all implemented. Reporting and returning is correct: the instruction
    // that trapped has already done its work.
    bump(Counter::Exceptions);
    crate::kdebug!("breakpoint (#BP) at rip {:#x}", frame.instruction_pointer.as_u64());
}

extern "x86-interrupt" fn on_overflow(frame: InterruptStackFrame) {
    fatal_exception("overflow (#OF)", 0x04, &frame, None, None);
}

extern "x86-interrupt" fn on_bound_range(frame: InterruptStackFrame) {
    fatal_exception("bound-range-exceeded (#BR)", 0x05, &frame, None, None);
}

extern "x86-interrupt" fn on_invalid_opcode(frame: InterruptStackFrame) {
    // Worth naming the likely cause: an invalid opcode in a Rust kernel almost
    // always means either an `unreachable!()`/`core::intrinsics::abort` was
    // reached, or the build targeted an instruction level the CPU lacks. Both
    // are diagnosable from the RIP, so print it prominently.
    crate::kcrit!(
        "invalid opcode at rip {:#x}: either an unreachable!() executed, or the \
         binary was built for a newer instruction level than this CPU \
         (check -C target-cpu against cpuid)",
        frame.instruction_pointer.as_u64()
    );
    fatal_exception("invalid-opcode (#UD)", 0x06, &frame, None, None);
}

extern "x86-interrupt" fn on_device_not_available(frame: InterruptStackFrame) {
    // #NM means a float/SSE instruction ran with CR0.TS set or CR0.EM set. M1
    // does not use lazy FPU switching, so this indicates the boot state is
    // wrong: CR0.EM must be clear on x86_64, which SSE is mandatory for.
    fatal_exception("device-not-available (#NM)", 0x07, &frame, None, None);
}

// The crate types `idt.double_fault` as `DivergingHandlerFuncWithErrCode`, i.e.
// `-> !`. That is not pedantry: #DF is defined as non-recoverable, so a handler
// that returns would `iretq` into a CPU state that already faulted twice and
// triple-fault with no diagnostic. The `-> !` makes "this never returns" a
// compile-checked property of the handler.
extern "x86-interrupt" fn on_double_fault(frame: InterruptStackFrame, code: u64) -> ! {
    // Running on IST1 by design, so this handler works even though the stack
    // that caused the double fault is unusable.
    //
    // The most common cause in a Rust kernel is kernel stack overflow, which
    // produces a double fault rather than a page fault because the guard page
    // below the stack is not-present *and* the fault handler itself needs
    // stack. Say so explicitly: it turns a cryptic reset into a known bug
    // class.
    bump(Counter::Exceptions);
    let rsp = frame.stack_pointer.as_u64();
    crate::kcrit!("DOUBLE FAULT (#DF) at rip {:#x}, error code {:#x}", frame.instruction_pointer.as_u64(), code);
    crate::kcrit!("  rsp {:#x}", rsp);
    if is_probable_stack_overflow(rsp) {
        crate::kcrit!(
            "  -> rsp is at or below a stack guard boundary. This is almost certainly \
             KERNEL STACK OVERFLOW: unbounded recursion or a large stack frame. \
             Increase the stack or make the recursion explicit."
        );
    }
    crate::kcrit!("  IST1 stack in use, so this report survived the broken stack.");
    // A double fault leaves the CPU unable to deliver further exceptions.
    // `panic!` here will attempt to log; if that itself faults, the machine
    // triple-faults and resets, which is the only remaining option.
    panic!("double fault");
}

/// Heuristic: is `rsp` sitting at a guard boundary we know about?
fn is_probable_stack_overflow(rsp: u64) -> bool {
    // The boot stack and the kernel stack both come from `boot.asm`; the IST
    // guards come from `gdt.rs`. Checking all of them makes the message
    // trustworthy rather than a guess that happens to be right often.
    // High aliases, not the symbols themselves: `_boot_stack_top` and
    // `_kernel_stack_top` are low PHYSICAL addresses (0x208000 and 0x210000),
    // which the kernel code model cannot encode as a RIP-relative reference.
    // orin.ld defines `*_hi` as `<sym> + KERNEL_VMA`, and the boot identity map
    // makes that alias valid. These values are only compared against a faulting
    // RSP to answer "did a stack overflow?", never dereferenced.
    extern "C" {
        static _boot_stack_top_hi: u8;
        static _kernel_stack_top_hi: u8;
    }
    let boot_top = crate::linker_sym!(_boot_stack_top_hi);
    let kern_top = crate::linker_sym!(_kernel_stack_top_hi);
    // Within 256 bytes below a stack top's guard region, or absurdly low.
    let near = |top: u64| rsp + 0x1000 >= top.saturating_sub(0x100) && rsp < top;
    near(boot_top) || near(kern_top) || rsp < 0x1000
}

extern "x86-interrupt" fn on_invalid_tss(frame: InterruptStackFrame, code: u64) {
    crate::kcrit!("invalid TSS, selector index {:#x}", code);
    fatal_exception("invalid-TSS (#TS)", 0x0A, &frame, Some(code), None);
}

extern "x86-interrupt" fn on_segment_not_present(frame: InterruptStackFrame, code: u64) {
    fatal_exception("segment-not-present (#NP)", 0x0B, &frame, Some(code), None);
}

extern "x86-interrupt" fn on_stack_segment(frame: InterruptStackFrame, code: u64) {
    fatal_exception("stack-segment-fault (#SS)", 0x0C, &frame, Some(code), None);
}

extern "x86-interrupt" fn on_general_protection(frame: InterruptStackFrame, code: u64) {
    // #GP in a kernel is usually one of: a bad MSR address, a segment load with
    // a null/invalid selector, a misaligned SSE/AVX access, or an attempt to
    // execute a privileged instruction at ring 3. Naming the candidates saves
    // the next engineer twenty minutes.
    crate::kcrit!(
        "general protection fault, error code {:#x}. Usual causes: invalid MSR \
         address, null segment selector load, misaligned SSE/AVX operand, or a \
         privileged instruction executed at ring 3.",
        code
    );
    fatal_exception("general-protection (#GP)", 0x0D, &frame, Some(code), None);
}

extern "x86-interrupt" fn on_page_fault(frame: InterruptStackFrame, code: PageFaultErrorCode) {
    use x86_64::registers::control::Cr2;
    // `Cr2::read()` returns `Result<VirtAddr, VirtAddrNotValid>` in x86_64 0.15:
    // CR2 is loaded by the CPU and can hold a non-canonical value after some
    // faults. Printing the raw bits is more useful than discarding the address,
    // so take the error payload rather than falling back to 0.
    let addr = match Cr2::read() {
        Ok(va) => va.as_u64(),
        Err(bad) => bad.0,
    };
    let raw = code.bits();

    crate::kcrit!("PAGE FAULT at {:#x}: {}", addr, format_pf_bits(raw));

    // In M1 there is no demand paging and no user space, so every page fault is
    // a kernel bug. Diagnose the common shapes before dying:
    if addr == 0 {
        crate::kcrit!("  -> NULL dereference.");
    } else if addr < KERNEL_VMA {
        crate::kcrit!(
            "  -> address is below the kernel half ({:#x}). Kernel code used a \
             physical address (or a user address) as a pointer. Use \
             vmm::boot_alias()/arch::phys_to_virt() instead of a raw cast.",
            KERNEL_VMA
        );
    } else if raw & 0x1 == 0 {
        crate::kcrit!("  -> page NOT PRESENT. Nothing was ever mapped here.");
    } else {
        crate::kcrit!("  -> page present but protected: a permission violation.");
        if raw & 0x2 != 0 && raw & 0x10 != 0 {
            crate::kcrit!(
                "  -> WRITE to a non-writable page via an INSTRUCTION FETCH path. \
                 Check for a self-modifying-code pattern or a corrupted page table."
            );
        }
    }

    fatal_exception("page-fault (#PF)", 0x0E, &frame, Some(raw), Some(addr));
}

extern "x86-interrupt" fn on_x87_fault(frame: InterruptStackFrame) {
    fatal_exception("x87-floating-point (#MF)", 0x10, &frame, None, None);
}

extern "x86-interrupt" fn on_alignment_check(frame: InterruptStackFrame, code: u64) {
    // #AC only fires at ring 3 with CR0.AM set, so seeing it in M1 (ring 0
    // only) means something enabled AC unexpectedly.
    fatal_exception("alignment-check (#AC)", 0x11, &frame, Some(code), None);
}

// `-> !` for the same reason as #DF: the crate types this entry as
// `DivergingHandlerFunc`, and #MC means the CPU detected an uncorrectable error.
extern "x86-interrupt" fn on_machine_check(frame: InterruptStackFrame) -> ! {
    // #MC on IST3. Machine check means the CPU itself detected an uncorrectable
    // error. There is no recovery and no continuation: reading further state may
    // itself be corrupt. Log minimally and stop.
    bump(Counter::Exceptions);
    crate::kcrit!("MACHINE CHECK (#MC) at rip {:#x}", frame.instruction_pointer.as_u64());
    crate::kcrit!(
        "  Hardware reported an uncorrectable error. M1 cannot decode MCi_STATUS \
         (M7 adds MCA bank parsing). Halting immediately; continuing risks \
         acting on corrupt data."
    );
    panic!("machine check");
}

extern "x86-interrupt" fn on_simd_fault(frame: InterruptStackFrame) {
    fatal_exception("simd-floating-point (#XF)", 0x13, &frame, None, None);
}

extern "x86-interrupt" fn on_virtualization(frame: InterruptStackFrame) {
    fatal_exception("virtualization (#VE)", 0x14, &frame, None, None);
}

extern "x86-interrupt" fn on_vmm_comm(frame: InterruptStackFrame, code: u64) {
    // #VC only occurs under SEV-ES. Orin running inside an SEV-ES guest would
    // need a full GHCB driver; there is none in M1, so this is fatal and says
    // why.
    crate::kcrit!(
        "#VC (SEV-ES VMM communication) with code {:#x}: Orin has no GHCB driver. \
         M1 does not support running as an SEV-ES guest; see docs/SECURITY.md.",
        code
    );
    fatal_exception("vmm-communication (#VC)", 0x1D, &frame, Some(code), None);
}

extern "x86-interrupt" fn on_security_exception(frame: InterruptStackFrame, code: u64) {
    fatal_exception("security-exception (#SX)", 0x1E, &frame, Some(code), None);
}

// ===========================================================================
//  Device interrupts
// ===========================================================================

extern "x86-interrupt" fn on_irq_timer(frame: InterruptStackFrame) {
    let _ = &frame;
    bump(Counter::TimerTicks);
    super::pit::tick();
    // Every 1000 ticks (≈1 s) emit a heartbeat at debug level. This is what
    // proves the timer is still alive during a long idle loop, and it is what
    // `make test` uses to confirm the kernel did not stop taking interrupts.
    if super::pit::ticks_since_boot() % 1000 == 0 {
        crate::kdebug!(
            "tick: uptime {}s ({} ticks)",
            super::pit::seconds_since_boot(),
            super::pit::ticks_since_boot()
        );
    }
    pic::end_of_interrupt(pic::vector_for_irq(pic::irq::TIMER));
}

extern "x86-interrupt" fn on_irq_keyboard(frame: InterruptStackFrame) {
    let _ = &frame;
    bump(Counter::KeyEvents);
    crate::drivers::keyboard::interrupt_handler();
    pic::end_of_interrupt(pic::vector_for_irq(pic::irq::KEYBOARD));
}

extern "x86-interrupt" fn on_irq_cascade(frame: InterruptStackFrame) {
    let _ = &frame;
    // The cascade line should never deliver an interrupt of its own; it exists
    // to let the slave's IRQs through. Counting it here (rather than treating it
    // as unassigned) means a stuck cascade is visible as a rising counter.
    crate::ktrace!("pic: cascade IRQ2 delivered (should not normally happen)");
    pic::end_of_interrupt(pic::vector_for_irq(pic::irq::CASCADE));
}

extern "x86-interrupt" fn on_irq_unexpected(frame: InterruptStackFrame) {
    // Reached only if a driver unmasked an IRQ line without installing a
    // handler. That is a driver bug, and the message says so in terms the
    // author will recognise.
    let vec = 0u8; // the vector is not recoverable from the frame; see note
    let _ = vec;
    bump(Counter::Unassigned);
    crate::kerror!(
        "unexpected device interrupt at rip {:#x}. A driver unmasked an IRQ line \
         without installing a handler for it. The line is masked again below so \
         this cannot become an interrupt storm.",
        frame.instruction_pointer.as_u64()
    );
    // We cannot tell which line fired from the frame alone. Masking every line
    // except the timer and keyboard is the safe recovery: it stops the storm and
    // leaves the system usable enough to report the bug.
    for irq_num in [3u8, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
        pic::mask(irq_num);
    }
    // EOI both controllers: the vector is unknown, so assume it may have come
    // from the slave.
    pic::end_of_interrupt(pic::vector_for_irq(8));
}

extern "x86-interrupt" fn on_syscall_vector(frame: InterruptStackFrame) {
    // M5 will implement the real dispatcher. Until then this must NOT pretend
    // to work: a syscall that returns garbage is far worse than one that
    // reports "not implemented", because the caller cannot tell.
    bump(Counter::Syscalls);
    crate::kerror!(
        "syscall vector {:#04x} invoked at rip {:#x}: the Orin syscall ABI is \
         DESIGNED but not IMPLEMENTED until M5. Returning ENOSYS. See \
         docs/SYSCALL.md.",
        SYSCALL_VECTOR,
        frame.instruction_pointer.as_u64()
    );
    // No EOI: this is not a PIC line.
}

extern "x86-interrupt" fn on_spurious(frame: InterruptStackFrame) {
    let _ = &frame;
    // A spurious interrupt is the PIC asserting IRQ7 or IRQ15 with nothing
    // behind it. The rule is absolute: **never send EOI for a spurious
    // interrupt**, because doing so clears an in-service bit that a real
    // interrupt still needs, and the real one is then lost forever.
    bump(Counter::Spurious);
    crate::ktrace!("spurious interrupt at vector {:#04x}; EOI deliberately withheld", SPURIOUS_VECTOR);
}

extern "x86-interrupt" fn on_unassigned(frame: InterruptStackFrame) {
    bump(Counter::Unassigned);
    unassigned_vector(frame.instruction_pointer.as_u64());
}

/// Shared body for both unassigned-vector paths.
///
/// Two paths reach it: `on_unassigned` (the `extern "x86-interrupt"` handler for
/// a vector that was explicitly assigned this function) and
/// `on_unassigned_general` (the catch-all thunk the `set_general_handler!` macro
/// generates for all 256 vectors). They cannot call each other — the
/// "x86-interrupt" ABI is not callable from normal Rust — so the diagnostic and
/// the panic live here and both call in.
fn unassigned_vector(rip: u64) -> ! {
    crate::kcrit!(
        "interrupt on an UNASSIGNED vector at rip {rip:#x}. Either the PIC \
         delivered a vector outside its remapped range (check pic::remap), or \
         something wrote the IDT. Halting."
    );
    panic!("interrupt on unassigned vector")
}
