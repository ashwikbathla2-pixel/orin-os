//! CPU register capture for exception reporting.
//!
//! Kept separate from `idt.rs` because it is the one piece of exception
//! handling that is genuinely arch-shaped and worth unit-testing on its own:
//! the *formatting* is exercised by host-side tests so a register dump cannot
//! regress into something unreadable.
//!
//! What we can and cannot recover: `extern "x86-interrupt"` gives us the pushed
//! `InterruptStackFrame` (RIP, CS, RFLAGS, RSP, SS) but **not** the general
//! registers, because the compiler preserves them for us rather than exposing
//! them. Reading them here yields the values *inside the handler*, which is
//! still useful for RSP/RBP/RAX but is **not** the faulting instruction's
//! register state. That distinction is stated in the dump, because a register
//! dump that silently lies about what it shows is worse than no dump.

#![allow(dead_code)]

use core::fmt;
use x86_64::structures::idt::InterruptStackFrame;

/// General-purpose registers captured inside a handler.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuRegs {
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cs: u64,
    pub ss: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
}

impl CpuRegs {
    /// Capture the current register state plus the interrupted frame.
    pub fn read_around(frame: &InterruptStackFrame) -> Self {
        use x86_64::registers::control::{Cr0, Cr2, Cr3, Cr4};
        use x86_64::registers::model_specific::Efer;

        let mut r = Self {
            rip: frame.instruction_pointer.as_u64(),
            rsp: frame.stack_pointer.as_u64(),
            rflags: frame.cpu_flags.bits(),
            // `InterruptStackFrame` stores segments as `SegmentSelector`
            // newtypes; `.0` is the raw 16-bit selector. Widened to u64 so the
            // register dump formats every field uniformly.
            cs: frame.code_segment.0 as u64,
            ss: frame.stack_segment.0 as u64,
            ..Self::default()
        };

        // SAFETY: each `reg!` reads one named register with `mov <reg>, rax`.
        // All are readable at ring 0, and reading them has no side effects.
        // `lateout` is used rather than `out` because the register's prior
        // value must not be assumed preserved.
        macro_rules! reg {
            ($field:ident, $name:literal) => {
                unsafe {
                    core::arch::asm!(concat!("mov {}, ", $name), lateout(reg) r.$field, options(nomem, nostack, preserves_flags));
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

        r.cr0 = Cr0::read_raw();
        r.cr2 = Cr2::read_raw();
        r.cr3 = Cr3::read_raw().0.start_address().as_u64();
        r.cr4 = Cr4::read_raw();
        r.efer = Efer::read_raw();
        r
    }

    /// Capture the register state at the point of the call.
    ///
    /// Used by the panic handler and the self-test, where there is no
    /// interrupted frame to report. `rip` is read with `lea` because
    /// `mov rax, rip` is not encodable.
    pub fn current() -> Self {
        use x86_64::registers::control::{Cr0, Cr2, Cr3, Cr4};
        use x86_64::registers::model_specific::Efer;

        let mut r = Self::default();
        macro_rules! reg {
            ($field:ident, $name:literal) => {
                // SAFETY: reads a named general register; no side effects.
                unsafe {
                    core::arch::asm!(concat!("mov {}, ", $name), lateout(reg) r.$field,
                                     options(nostack, nomem, preserves_flags));
                }
            };
        }
        reg!(rax, "rax"); reg!(rbx, "rbx"); reg!(rcx, "rcx"); reg!(rdx, "rdx");
        reg!(rsi, "rsi"); reg!(rdi, "rdi"); reg!(rbp, "rbp");
        reg!(r8, "r8"); reg!(r9, "r9"); reg!(r10, "r10"); reg!(r11, "r11");
        reg!(r12, "r12"); reg!(r13, "r13"); reg!(r14, "r14"); reg!(r15, "r15");

        // SAFETY: `lea rax, [rip]` reads the instruction pointer.
        unsafe { core::arch::asm!("lea {}, [rip]", lateout(reg) r.rip, options(nostack, nomem, preserves_flags)); }
        // SAFETY: `pushfq; pop rax` reads RFLAGS on a valid stack.
        unsafe { core::arch::asm!("pushfq", "pop {}", lateout(reg) r.rflags, options(nostack, nomem)); }
        // SAFETY: segment selector reads zero-extend into the destination.
        unsafe {
            core::arch::asm!("mov {0:x}, cs", lateout(reg) r.cs, options(nostack, nomem, preserves_flags));
            core::arch::asm!("mov {0:x}, ss", lateout(reg) r.ss, options(nostack, nomem, preserves_flags));
        }
        // SAFETY: `lea rsp, [rsp]` is the only way to read RSP without changing it.
        unsafe { core::arch::asm!("lea {}, [rsp]", lateout(reg) r.rsp, options(nostack, nomem, preserves_flags)); }

        r.cr0 = Cr0::read_raw();
        r.cr2 = Cr2::read_raw();
        r.cr3 = Cr3::read_raw().0.start_address().as_u64();
        r.cr4 = Cr4::read_raw();
        r.efer = Efer::read_raw();
        r
    }

    /// Format the general registers as a fixed-width grid.
    ///
    /// Deliberately 3 registers per line rather than 2 or 4: at 80 columns a
    /// `name=0x0000000000000000` group is 24 characters, so 3 fit with
    /// separators and the whole dump stays inside one VGA row per line. That is
    /// a real constraint when the output is also going to an 80×25 screen.
    pub fn format_general(&self) -> RegDump {
        RegDump { regs: *self }
    }

    /// Control-register state, with the bits that matter decoded.
    pub fn format_control(&self) -> alloc::string::String {
        use alloc::format;
        let mut s = alloc::string::String::new();
        s.push_str(&format!("  cr0 {:#018x} [", self.cr0));
        if self.cr0 & (1 << 0) != 0 { s.push_str("PE "); }
        if self.cr0 & (1 << 16) != 0 { s.push_str("WP "); }
        if self.cr0 & (1 << 29) != 0 { s.push_str("NW "); }
        if self.cr0 & (1 << 30) != 0 { s.push_str("CD "); }
        if self.cr0 & (1u64 << 31) != 0 { s.push_str("PG "); }
        s.push_str("]\n");

        s.push_str(&format!("  cr4 {:#018x} [", self.cr4));
        if self.cr4 & (1 << 5) != 0 { s.push_str("PAE "); }
        if self.cr4 & (1 << 7) != 0 { s.push_str("PGE "); }
        if self.cr4 & (1 << 11) != 0 { s.push_str("UMIP "); }
        if self.cr4 & (1 << 16) != 0 { s.push_str("FSGSBASE "); }
        if self.cr4 & (1 << 17) != 0 { s.push_str("PCIDE "); }
        if self.cr4 & (1 << 20) != 0 { s.push_str("SMEP "); }
        if self.cr4 & (1 << 21) != 0 { s.push_str("SMAP "); }
        s.push_str("]\n");

        s.push_str(&format!("  efer {:#018x} [", self.efer));
        if self.efer & (1 << 0) != 0 { s.push_str("SCE "); }
        if self.efer & (1 << 8) != 0 { s.push_str("LME "); }
        if self.efer & (1 << 10) != 0 { s.push_str("LMA "); }
        if self.efer & (1 << 11) != 0 { s.push_str("NXE "); }
        if self.efer & (1 << 12) != 0 { s.push_str("SVME "); }
        s.push_str("]\n");

        s.push_str(&format!("  cr2 {:#018x}  cr3 {:#018x}", self.cr2, self.cr3));
        s
    }

    /// Security-relevant assertions about control registers, checked at boot.
    ///
    /// Returns a list of *problems*. An empty list means the machine state
    /// matches what `docs/SECURITY.md` claims — which is the only way that
    /// document can be trusted. Each entry names the bit and the consequence,
    /// because "CR0.WP is clear" tells an engineer nothing and "the kernel can
    /// write to read-only pages, so W^X does not hold" tells them everything.
    pub fn control_register_problems(&self) -> [&'static str; 6] {
        let mut out = [""; 6];
        let mut n = 0usize;

        macro_rules! add {
            ($cond:expr, $msg:literal) => {
                // `n` is read before it is written, so the last increment is
                // not dead. (The previous shape — `n < out.len()` in the guard,
                // unconditional `n += 1` in the body — left the final increment
                // unread and rustc said so.)
                if $cond {
                    if let Some(slot) = out.get_mut(n) {
                        *slot = $msg;
                        n += 1;
                    }
                }
            };
        }

        add!(
            self.cr0 & (1 << 16) == 0,
            "CR0.WP is CLEAR: the kernel can write to read-only pages, so W^X and .rodata protection do not hold"
        );
        add!(
            self.cr0 & (1u64 << 31) == 0,
            "CR0.PG is CLEAR: paging is off, so there is no memory protection at all"
        );
        add!(
            self.efer & (1 << 11) == 0,
            "EFER.NXE is CLEAR: NX bits in page tables are ignored, so no page can be made non-executable"
        );
        add!(
            self.efer & (1 << 10) == 0,
            "EFER.LMA is CLEAR: the CPU is not in long mode"
        );
        // SMEP/SMAP are soft requirements: they only exist on hardware that
        // advertises them. QEMU's default TCG cpu ("qemu64"/2.5+) does not, and
        // kmain already refused to set the bits after CPUID said no. Treating a
        // missing feature as a *boot failure* would make every TCG selftest red
        // for a documented, intentional degradation (docs/SECURITY.md §5).
        // Require the bit only when the CPU claimed the feature.
        let feats = crate::cpu::cpuid::detect();
        add!(
            feats.smep && self.cr4 & (1 << 20) == 0,
            "CR4.SMEP is CLEAR despite CPUID.SMEP: the kernel can execute user-space code, removing a major ret2usr mitigation"
        );
        add!(
            feats.smap && self.cr4 & (1 << 21) == 0,
            "CR4.SMAP is CLEAR despite CPUID.SMAP: the kernel can read user memory without an explicit copy_*_user, so a stray pointer is not caught"
        );
        out
    }
}

/// `Display` wrapper so the register grid can be passed straight to a log macro.
pub struct RegDump {
    pub regs: CpuRegs,
}

impl fmt::Display for RegDump {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let r = &self.regs;
        writeln!(f, "  --- registers as seen INSIDE the handler ---")?;
        writeln!(
            f,
            "  (the faulting instruction's own register state is NOT recoverable via\n   extern \"x86-interrupt\"; RIP/RSP/RFLAGS/CS/SS above ARE the interrupted values)"
        )?;
        writeln!(f, "  rax {:#018x}  rbx {:#018x}  rcx {:#018x}", r.rax, r.rbx, r.rcx)?;
        writeln!(f, "  rdx {:#018x}  rsi {:#018x}  rdi {:#018x}", r.rdx, r.rsi, r.rdi)?;
        writeln!(f, "  rbp {:#018x}  r8  {:#018x}  r9  {:#018x}", r.rbp, r.r8, r.r9)?;
        writeln!(f, "  r10 {:#018x}  r11 {:#018x}  r12 {:#018x}", r.r10, r.r11, r.r12)?;
        writeln!(f, "  r13 {:#018x}  r14 {:#018x}  r15 {:#018x}", r.r13, r.r14, r.r15)
    }
}
