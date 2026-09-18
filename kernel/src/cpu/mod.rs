//! CPU identification, feature gating and low-level register access.

pub mod cpuid;
pub mod msr;
pub mod regs;

use core::sync::atomic::{AtomicBool, Ordering};

/// Set by M15 when a debugger (gdbstub / Orin Developer Center) attaches.
///
/// Until it is set, a `#DB` debug exception is treated as fatal, because
/// nothing in M1 has any legitimate reason to raise one. Flipping the meaning
/// of an exception based on unverified state would be a security hole, so this
/// flag can only be set by ring-0 code that has already validated the debug
/// connection.
static DEBUGGER_ATTACHED: AtomicBool = AtomicBool::new(false);

pub fn set_debugger_attached(v: bool) {
    DEBUGGER_ATTACHED.store(v, Ordering::Release);
    crate::kinfo!(
        "cpu: debugger_attached = {} (changes #DB handling; see interrupts/idt.rs)",
        v
    );
}

pub fn debugger_attached() -> bool {
    DEBUGGER_ATTACHED.load(Ordering::Acquire)
}

/// Halt the CPU until the next interrupt.
///
/// `hlt` at ring 0 stops execution and waits for an interrupt, which is what an
/// idle kernel should do: it burns no power and no cycles. Pairing it with
/// `sti` inside a loop is the standard idiom — `sti` followed by `hlt` cannot
/// lose an interrupt, because the CPU defers interrupt recognition by one
/// instruction after `sti`.
pub fn halt() {
    x86_64::instructions::hlt();
}

/// Enable interrupts.
pub fn enable_interrupts() {
    x86_64::instructions::interrupts::enable();
}

/// Disable interrupts.
pub fn disable_interrupts() {
    x86_64::instructions::interrupts::disable();
}

/// True if interrupts are currently enabled.
///
/// `x86_64` 0.15 has no `interrupts::enabled()`, so RFLAGS.IF is read directly.
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    // SAFETY: `pushfq; pop rax` reads RFLAGS. Requires a valid stack, which
    // every ring-0 context in Orin has.
    unsafe {
        core::arch::asm!("pushfq", "pop {}", lateout(reg) flags, options(nostack, nomem));
    }
    flags & (1 << 9) != 0
}


/// Execute `f` with interrupts disabled, restoring the prior state afterwards.
///
/// Used for the read-modify-write sequences where a stray interrupt between two
/// instructions would leave inconsistent state.
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    x86_64::instructions::interrupts::without_interrupts(f)
}

/// `pause` — the spin-wait hint instruction.
///
/// Defined here rather than using `x86_64::instructions::pause` because that
/// helper does not exist in x86_64 0.15. Centralising it means one `asm!`
/// block with one documented SAFETY note instead of five copies.
///
/// # Safety contract
/// `pause` is a hint instruction with no architectural side effects: it delays
/// the next instruction by an implementation-defined short interval, improves
/// power efficiency in spin loops, and avoids the memory-order violation
/// pipeline flush a tight spin loop causes on Hyper-Threading cores. Safe to
/// call from anywhere at ring 0.
#[inline(always)]
pub fn pause() {
    // SAFETY: see the contract above; `pause` reads and writes nothing.
    unsafe {
        core::arch::asm!("pause", options(nomem, nostack, preserves_flags));
    }
}
