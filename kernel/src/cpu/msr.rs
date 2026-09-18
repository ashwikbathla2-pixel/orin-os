//! Model-Specific Register access.
//!
//! Thin, checked wrappers over `rdmsr`/`wrmsr`. The wrappers exist for two
//! reasons that a raw `asm!` at each call site would not provide:
//!
//! 1. **A bad MSR address raises #GP**, and in M1 #GP is fatal. `exists()` lets
//!    a caller probe before writing, which turns "mystery reset" into "this CPU
//!    does not have that MSR".
//! 2. **Every MSR write is logged at trace level with its address and value.**
//!    MSRs are where the security-relevant machine state lives (EFER.NXE,
//!    CR-adjacent controls, the syscall entry point). A boot log that shows the
//!    exact MSR writes is auditable; one that does not is not.

#![allow(dead_code)]

/// Well-known MSR addresses.
pub mod addr {
    /// Extended Feature Enable Register. Holds LME/LMA/NXE/SCE.
    pub const EFER: u32 = 0xC000_0080;
    /// `syscall`/`sysret` segment selectors. M5.
    pub const STAR: u32 = 0xC000_0081;
    /// `syscall` entry RIP. M5.
    pub const LSTAR: u32 = 0xC000_0082;
    /// IA32_CSTAR — 32-bit-mode syscall entry, unused on x86_64-only Orin.
    pub const CSTAR: u32 = 0xC000_0083;
    /// RFLAGS mask applied on `syscall`. M5.
    pub const SFMASK: u32 = 0xC000_0084;
    pub const FS_BASE: u32 = 0xC000_0100;
    pub const GS_BASE: u32 = 0xC000_0101;
    /// GS base swapped in by `swapgs` on kernel entry. M5.
    pub const KERNEL_GS_BASE: u32 = 0xC000_0102;
    /// Page Attribute Table. Controls the memory types used by PAT index bits
    /// in page-table entries. M8 needs this for the framebuffer (write-combining).
    pub const PAT: u32 = 0x0000_0277;
    /// APIC base address and enable bits. M4.
    pub const APIC_BASE: u32 = 0x0000_001B;
    /// Machine-check architecture banks. M7.
    pub const MCG_CAP: u32 = 0x0000_0179;
    /// Kernel stack pointer loaded by `syscall` when CET/IST is in play. M14.
    pub const U_CET: u32 = 0x0000_06A0;
    pub const S_CET: u32 = 0x0000_06A2;
    pub const PL0_SSP: u32 = 0x0000_06A4;
}

/// EFER bit positions.
pub mod efer {
    /// System Call Extensions — enables `syscall`/`sysret`.
    pub const SCE: u64 = 1 << 0;
    /// Long Mode Enable. Set by `boot.asm`; must stay set.
    pub const LME: u64 = 1 << 8;
    /// Long Mode Active. Read-only; set by the CPU when LME and CR0.PG are both on.
    pub const LMA: u64 = 1 << 10;
    /// No-Execute Enable. Without this, every NX bit in every page table entry
    /// is ignored and no page can be made non-executable.
    pub const NXE: u64 = 1 << 11;
    /// Secure VM extensions (AMD-V).
    pub const SVME: u64 = 1 << 12;
    /// Long Mode Segment Limit Enable.
    pub const LMSLE: u64 = 1 << 13;
    /// Fast FXSAVE/FXRSTOR.
    pub const FFXSR: u64 = 1 << 14;
}

/// Read an MSR.
///
/// # Safety
/// Reading most MSRs is side-effect-free, but not all: a few (notably some
/// performance counters and `IA32_TIME_STAMP_COUNTER`) change state on read,
/// and reading an MSR that does not exist on this CPU raises #GP, which in M1
/// is fatal. Callers must confirm availability via [`exists`] or CPUID first.
pub unsafe fn read(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: the caller's contract covers this; `rdmsr` needs ring 0 and a
    // valid MSR address, both of which the caller asserts.
    unsafe {
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nostack, nomem, preserves_flags),
    );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Write an MSR, and log it.
///
/// # Safety
/// As [`read`], plus: writing an MSR changes machine state, and several MSRs
/// (EFER, APIC_BASE, PAT) will fault or corrupt operation if given an invalid
/// value. Callers must know the value is legal for this CPU.
pub unsafe fn write(msr: u32, value: u64) {
    let lo = (value & 0xFFFF_FFFF) as u32;
    let hi = (value >> 32) as u32;
    crate::ktrace!("msr: write {:#x} <- {:#x}", msr, value);
    // SAFETY: the caller's contract covers this; `wrmsr` needs ring 0 and a
    // value that is legal for the MSR, which the caller asserts.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
}

/// Read-modify-write with a closure.
///
/// # Safety
/// As [`write`]. Not atomic with respect to interrupts: on a single core with
/// interrupts disabled during M1 init that is fine, but M4 must disable
/// interrupts around any RMW on a per-CPU MSR, or use the MSR's own locking
/// semantics. This is called out here because it is exactly the kind of
/// invariant that silently stops holding when SMP arrives.
pub unsafe fn update<F: FnOnce(u64) -> u64>(msr: u32, f: F) -> u64 {
    // SAFETY: the caller's contract covers both the read and the write; the
    // non-atomicity caveat is documented on this function and is the caller's
    // responsibility from M4 onwards.
    unsafe {
        let old = read(msr);
        let new = f(old);
        if new != old {
            write(msr, new);
        }
        new
    }
}

/// Probe whether an MSR exists, by attempting a read and catching the #GP.
///
/// Implemented by temporarily installing a #GP handler that skips the faulting
/// instruction — the standard technique. This is genuinely useful and not a
/// hack: there is no CPUID leaf that enumerates every MSR.
///
/// **Not usable in M1**, because installing a temporary IDT entry before the
/// real IDT exists would be worse than the problem it solves. M1 instead
/// gates MSR use on CPUID features (`nx` → EFER.NXE, `syscall` → LSTAR,
/// `x2apic` → APIC_BASE), which is both safer and sufficient. This function is
/// declared and documented so M7's driver probing has the right tool, and it
/// returns `Err` with an explanatory reason until then rather than pretending
/// to probe.
pub fn exists(msr: u32) -> Result<bool, &'static str> {
    Err("msr::exists requires a temporary #GP handler, which is unsafe before \
         idt::init; M1 gates MSR use on CPUID features instead. Implemented in M7.")
        .map_err(|_| {
            let _ = msr;
            "msr::exists is not implemented in M1 (see docs/DRIVERS.md §5); \
             gate MSR access on a CPUID feature bit instead"
        })
}
