//! Interrupt subsystem: descriptor tables, interrupt controllers, timers.
//!
//! ## Init order is load-bearing
//!
//! [`init`] performs five steps that must happen in this exact order, and each
//! has a failure mode that is painful to diagnose if the order is wrong:
//!
//! 1. `gdt::init()` — installs the GDT and TSS. **Must be first**, because the
//!    IDT's `#DF` entry names `IST1`, and an IST slot pointing at an
//!    uninitialised TSS means a double fault becomes a triple fault and a reset
//!    with no output.
//! 2. `idt::init()` — installs all 256 vectors and loads the IDT. Must follow
//!    the GDT for the reason above, and must precede any unmasking.
//! 3. `pic::remap()` — moves IRQ0–15 off vectors 0x08–0x0F, which on x86 are
//!    CPU exceptions. Until this completes, a timer tick is indistinguishable
//!    from a double fault.
//! 4. `pit::init()` — programs the 1 kHz tick.
//! 5. `pic::unmask(...)` — **only for lines that have a handler.** Unmasking a
//!    line with no handler delivers interrupts that hit `on_irq_unexpected`,
//!    which masks everything again and reports a driver bug. That is the right
//!    behaviour for a buggy driver and the wrong behaviour for boot, so the
//!    unmask list here is explicit and short.

pub mod gdt;
pub mod idt;
pub mod pic;
pub mod pit;

use x86_64::registers::model_specific::{Efer, EferFlags};

/// Result of [`init`], for the boot banner and `sys.interrupts` over OKI.
#[derive(Clone, Copy, Debug)]
pub struct InterruptInfo {
    pub selectors: gdt::Selectors,
    pub pit_divisor: u16,
    /// Numerator of the achieved channel-0 tick rate, in Hz. The real rate is
    /// `tick_hz_num / tick_hz_den` = 1 193 182 / 1193 = 1000.1525… Hz, stored
    /// as an exact rational rather than an f64 — see `pit::ACTUAL_TICK_HZ_NUM`.
    pub tick_hz_num: u64,
    /// Denominator of [`Self::tick_hz_num`].
    pub tick_hz_den: u64,
    pub unmasked_irqs: u16,
    pub nxe_enabled: bool,
    pub vectors_installed: usize,
}

/// Bring up the interrupt subsystem. Must run after `vmm::init`.
///
/// Interrupts remain **disabled** on return. The caller enables them once the
/// rest of init has completed, so that a timer tick cannot arrive while the
/// kernel is in a half-initialised state. "Enable interrupts as late as
/// possible" is not caution for its own sake: it means every handler that can
/// run has a fully initialised system to run on.
pub fn init() -> InterruptInfo {
    // -- EFER.NXE -------------------------------------------------------
    // Must be set before the VMM's NX bits mean anything, and before the IDT is
    // loaded so an exception during IDT setup is reported with correct state.
    // (The VMM already ran; it caches NX availability, which is why this is set
    // in main.rs before vmm::init — see the ordering note there. This call is
    // the idempotent confirmation.)
    let nxe_enabled = enable_nx();

    // -- 1. GDT + TSS ----------------------------------------------------
    let selectors = gdt::init();

    // -- 2. IDT ----------------------------------------------------------
    idt::init();

    // -- 3. PIC ----------------------------------------------------------
    pic::remap();

    // -- 4. PIT ----------------------------------------------------------
    pit::init();

    // -- 5. Unmask only the lines that have handlers --------------------
    let mut unmasked: u16 = 0;
    for irq_num in [pic::irq::TIMER, pic::irq::KEYBOARD] {
        pic::unmask(irq_num);
        unmasked |= 1 << irq_num;
    }

    InterruptInfo {
        selectors,
        pit_divisor: pit::DIVISOR,
        tick_hz_num: pit::ACTUAL_TICK_HZ_NUM,
        tick_hz_den: pit::ACTUAL_TICK_HZ_DEN,
        unmasked_irqs: unmasked,
        nxe_enabled,
        vectors_installed: 256,
    }
}

/// Set `EFER.NXE` if the CPU supports it. Returns whether NX is now active.
///
/// Without NXE, every NX bit in every page-table entry is *ignored* — the
/// hardware does not fault on execute-from-writable, so the W^X policy in
/// `docs/MEMORY.md` §2.2 would be a document with nothing behind it. This
/// function is therefore the single point where Orin either has W^X or loudly
/// admits it does not.
pub fn enable_nx() -> bool {
    let features = crate::cpu::cpuid::detect();
    if !features.nx {
        crate::kerror!(
            "cpu: no NX support (CPUID.80000001H:EDX[20] clear). Orin's W^X memory \
             policy CANNOT be enforced on this machine. Booting anyway, because a \
             machine without NX is a machine that should still be diagnosable, but \
             the security posture is REDUCED and every boot log says so."
        );
        crate::memory::vmm::set_nx_available(false);
        return false;
    }
    // SAFETY: EFER is readable/writable at ring 0, and setting NXE is legal
    // whenever CPUID reports NX support (checked above).
    unsafe {
        // `Efer::update` hands the closure `&mut EferFlags` and writes back
        // whatever is left in it, so the closure mutates rather than returns.
        Efer::update(|f| *f |= EferFlags::NO_EXECUTE_ENABLE);
    }
    let on = Efer::read().contains(EferFlags::NO_EXECUTE_ENABLE);
    crate::memory::vmm::set_nx_available(on);
    crate::kinfo!("cpu: EFER.NXE = {} (no-execute page protection active)", on);
    on
}
