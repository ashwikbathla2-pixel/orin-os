//! CPUID feature detection.
//!
//! Every hardware-dependent decision in the kernel is gated on a bit read here
//! at boot, and the result is logged. The alternative — assuming a feature
//! exists because the emulator has it — is how a kernel boots in QEMU and
//! triple-faults on real hardware, which is the single most common failure mode
//! in hobby OS development and the reason `make test-hardware` exists as a
//! separate target from `make test`.

#![allow(dead_code)]

use spin::Once;

/// Raw CPUID result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Execute CPUID.
///
/// # Safety
/// CPUID is unprivileged and side-effect-free on every x86 CPU that has it.
/// Availability is verified by the boot stub (`boot.asm` toggles the EFLAGS ID
/// bit and refuses to continue if it cannot), so by the time Rust runs, CPUID
/// is guaranteed present.
pub fn raw(leaf: u32, subleaf: u32) -> CpuidResult {
    // `cpuid` clobbers RBX, and LLVM reserves RBX internally on x86_64, so
    // `lateout("ebx")` is rejected at compile time. The standard solution is to
    // preserve RBX across the instruction by exchanging it with another
    // scratch register — which is what the `xchg` pair below does. This is why
    // CPUID wrappers are always slightly uglier than they look like they should
    // be, and why the ugliness is not a mistake to "clean up".
    //
    // SAFETY: `cpuid` is unprivileged and side-effect-free. `xchg` with a
    // register operand touches nothing else. Availability was verified by the
    // boot stub, so by the time Rust runs, CPUID is guaranteed present.
    unsafe {
        let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "pop rbx",
            ebx = out(reg) ebx,
            inlateout("eax") leaf => eax,
            inlateout("ecx") subleaf => ecx,
            lateout("edx") edx,
            options(nostack, nomem, preserves_flags),
        );
        CpuidResult { eax, ebx, ecx, edx }
    }
}

/// What Orin needs to know about this CPU.
#[derive(Clone, Copy, Debug)]
pub struct CpuFeatures {
    /// 12-byte vendor string, NUL-terminated in place.
    pub vendor: [u8; 13],
    /// Family/model/stepping, useful in crash reports and for errata workarounds.
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    /// 48-byte brand string from leaves 0x80000002..4.
    pub brand: [u8; 49],
    /// Highest supported standard and extended leaf.
    pub max_leaf: u32,
    pub max_ext_leaf: u32,

    // --- Features Orin actually branches on -------------------------------
    /// NX / XD bit support (CPUID.80000001H:EDX[20]). Required for W^X.
    pub nx: bool,
    /// 1 GiB pages (CPUID.80000001H:EDX[26]). Used by the M4 direct map.
    pub pdpe1gb: bool,
    /// 5-level paging (CPUID.07H:ECX[16]). Detected, **not enabled** in M1;
    /// see docs/MEMORY.md §4.1 for why that is a deliberate deferral.
    pub la57: bool,
    /// Supervisor Mode Execution Prevention (CPUID.07H:EBX[7]).
    pub smep: bool,
    /// Supervisor Mode Access Prevention (CPUID.07H:EBX[20]).
    pub smap: bool,
    /// `invpcid` (CPUID.07H:EBX[10]). M4 uses this with PCIDs.
    pub invpcid: bool,
    /// `rdseed` (CPUID.07H:EBX[18]) and `rdrand` (CPUID.01H:ECX[30]).
    /// Entropy sources; M14 builds the real entropy pool on these.
    pub rdseed: bool,
    pub rdrand: bool,
    /// Hardware RNG quality caveat: `rdrand` on some AMD Zen 1/2 firmware
    /// revisions returns 0xFFFF... unconditionally, with CF set so the result
    /// *looks* valid. Detected by [`entropy_probe`], which stores its verdict
    /// in [`rdrand_suspect`] rather than in this struct — `CpuFeatures` is
    /// cached behind `spin::Once` and therefore immutable after detection.
    pub rdrand_present_but_unverified: bool,
    /// x2APIC (CPUID.01H:ECX[21]). M4 prefers this over the MMIO APIC.
    pub x2apic: bool,
    /// APIC present (CPUID.01H:EDX[9]).
    pub apic: bool,
    /// TSC present (CPUID.01H:EDX[4]) and invariant (CPUID.80000007H:EDX[8]).
    /// Only an *invariant* TSC may be used as a clocksource across cores and
    /// sleep states; see the note in `interrupts/pit.rs`.
    pub tsc: bool,
    pub tsc_invariant: bool,
    /// TSC rate from leaf 0x15, when the CPU provides it (many do not).
    pub tsc_khz: Option<u64>,
    /// Running under a hypervisor (CPUID.01H:ECX[31]).
    pub hypervisor_present: bool,
    /// Hypervisor vendor from leaf 0x40000000 ("KVMKVMKVM", "VMwareVMware",
    /// "Microsoft Hv", "XenVMMXenVMM", "QEMUQEMUQEMU", …).
    pub hypervisor_vendor: [u8; 13],
    /// SSE2 (CPUID.01H:EDX[26]). Architecturally mandatory on x86_64; checked
    /// anyway because a CPU that fails this check is not x86_64 and nothing
    /// else in the kernel can be trusted.
    pub sse2: bool,
    /// `syscall`/`sysret` (CPUID.80000001H:EDX[11]). Required for the M5 ABI.
    pub syscall: bool,
    /// FSGSBASE (CPUID.07H:EBX[0]), for per-thread segment bases in M4.
    pub fsgsbase: bool,
    /// AVX / AVX2, reported so the SDK can decide what to codegen for.
    pub avx: bool,
    pub avx2: bool,
}

static FEATURES: Once<CpuFeatures> = Once::new();

/// Detect and cache. Call once, early (init step 4).
pub fn detect() -> &'static CpuFeatures {
    FEATURES.call_once(|| {
        let leaf0 = raw(0, 0);
        let max_leaf = leaf0.eax;
        let mut vendor = [0u8; 13];
        vendor[0..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&leaf0.ecx.to_le_bytes());

        let leaf1 = if max_leaf >= 1 { raw(1, 0) } else { CpuidResult::default() };
        let leaf7 = if max_leaf >= 7 { raw(7, 0) } else { CpuidResult::default() };
        let leaf15 = if max_leaf >= 0x15 { raw(0x15, 0) } else { CpuidResult::default() };

        let ext = raw(0x8000_0000, 0);
        let max_ext_leaf = ext.eax;
        let ext1 = if max_ext_leaf >= 0x8000_0001 {
            raw(0x8000_0001, 0)
        } else {
            CpuidResult::default()
        };
        let ext7 = if max_ext_leaf >= 0x8000_0007 {
            raw(0x8000_0007, 0)
        } else {
            CpuidResult::default()
        };

        let mut brand = [0u8; 49];
        if max_ext_leaf >= 0x8000_0004 {
            for (i, leaf) in [0x8000_0002u32, 0x8000_0003, 0x8000_0004].iter().enumerate() {
                let r = raw(*leaf, 0);
                brand[i * 16..i * 16 + 4].copy_from_slice(&r.eax.to_le_bytes());
                brand[i * 16 + 4..i * 16 + 8].copy_from_slice(&r.ebx.to_le_bytes());
                brand[i * 16 + 8..i * 16 + 12].copy_from_slice(&r.ecx.to_le_bytes());
                brand[i * 16 + 12..i * 16 + 16].copy_from_slice(&r.edx.to_le_bytes());
            }
        }

        let hypervisor_present = leaf1.ecx & (1 << 31) != 0;
        let mut hypervisor_vendor = [0u8; 13];
        if hypervisor_present {
            let hv = raw(0x4000_0000, 0);
            hypervisor_vendor[0..4].copy_from_slice(&hv.ebx.to_le_bytes());
            hypervisor_vendor[4..8].copy_from_slice(&hv.ecx.to_le_bytes());
            hypervisor_vendor[8..12].copy_from_slice(&hv.edx.to_le_bytes());
        }

        // Display family/model per the Intel/AMD algorithm: for family 0xF the
        // displayed family is base + extended, and the model is
        // (extended << 4) + base. Getting this wrong makes crash reports name
        // the wrong CPU, which sends errata lookups down the wrong path.
        let base_family = (leaf1.eax >> 8) & 0xF;
        let ext_family = (leaf1.eax >> 20) & 0xFF;
        let family = if base_family == 0xF {
            base_family + ext_family
        } else {
            base_family
        };
        let base_model = (leaf1.eax >> 4) & 0xF;
        let ext_model = (leaf1.eax >> 16) & 0xF;
        let model = if base_family == 0x6 || base_family == 0xF {
            (ext_model << 4) + base_model
        } else {
            base_model
        };

        let rdrand = leaf1.ecx & (1 << 30) != 0;

        let tsc_khz = if leaf15.ebx != 0 && leaf15.eax != 0 {
            // leaf 0x15: eax = denominator, ebx = numerator, ecx = nominal Hz.
            let nominal = if leaf15.ecx != 0 { leaf15.ecx as u64 } else { 0 };
            if nominal != 0 {
                Some(nominal * leaf15.ebx as u64 / leaf15.eax as u64 / 1000)
            } else {
                None
            }
        } else {
            None
        };

        CpuFeatures {
            vendor,
            family,
            model,
            stepping: leaf1.eax & 0xF,
            brand,
            max_leaf,
            max_ext_leaf,
            nx: ext1.edx & (1 << 20) != 0,
            pdpe1gb: ext1.edx & (1 << 26) != 0,
            la57: leaf7.ecx & (1 << 16) != 0,
            smep: leaf7.ebx & (1 << 7) != 0,
            smap: leaf7.ebx & (1 << 20) != 0,
            invpcid: leaf7.ebx & (1 << 10) != 0,
            rdseed: leaf7.ebx & (1 << 18) != 0,
            rdrand,
            rdrand_present_but_unverified: rdrand,
            x2apic: leaf1.ecx & (1 << 21) != 0,
            apic: leaf1.edx & (1 << 9) != 0,
            tsc: leaf1.edx & (1 << 4) != 0,
            tsc_invariant: ext7.edx & (1 << 8) != 0,
            tsc_khz,
            hypervisor_present,
            hypervisor_vendor,
            sse2: leaf1.edx & (1 << 26) != 0,
            syscall: ext1.edx & (1 << 11) != 0,
            fsgsbase: leaf7.ebx & (1 << 0) != 0,
            avx: leaf1.ecx & (1 << 28) != 0,
            avx2: leaf7.ebx & (1 << 5) != 0,
        }
    })
}

/// NUL-terminate and convert one of the fixed-size CPUID strings.
pub fn cstr(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = &buf[..end];
    core::str::from_utf8(s).unwrap_or("<non-ascii>")
}

/// Verdict of [`entropy_probe`]: `true` if RDRAND appears broken.
///
/// Separate from `CpuFeatures` because that struct is immutable once cached.
static RDRAND_SUSPECT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// `true` if [`entropy_probe`] found RDRAND returning only degenerate values.
pub fn rdrand_suspect() -> bool {
    RDRAND_SUSPECT.load(core::sync::atomic::Ordering::Acquire)
}

/// Probe `rdrand` for the known-broken-firmware case.
///
/// Certain AMD AGESA revisions made `rdrand` return all-ones with CF set, i.e.
/// a value that *looks* valid. An entropy pool built on that would produce
/// predictable keys, and nothing downstream would ever notice — so the probe
/// runs at boot and the result is logged and cached.
///
/// Returns `true` if `rdrand` looks broken.
pub fn entropy_probe() -> bool {
    let f = detect();
    if !f.rdrand {
        return false;
    }
    let mut suspect = true;
    for _ in 0..8 {
        // SAFETY: RDRAND writes its destination and sets CF. Reading it has no
        // architectural side effect. The loop bound means a CPU that never sets
        // CF cannot hang the boot.
        let v: u64 = unsafe {
            let out: u64;
            let ok: u8;
            core::arch::asm!(
                "rdrand {out}",
                "setc {ok}",
                out = lateout(reg) out,
                ok = lateout(reg_byte) ok,
                options(nostack, nomem),
            );
            if ok == 0 {
                continue;
            }
            out
        };
        if v != u64::MAX && v != 0 {
            suspect = false;
            break;
        }
    }
    RDRAND_SUSPECT.store(suspect, core::sync::atomic::Ordering::Release);
    if suspect {
        crate::kwarn!(
            "cpuid: RDRAND returned only all-ones/all-zero across 8 probes. This matches the \
             known-broken AMD firmware case. M14's entropy pool will NOT use RDRAND on this \
             machine; key material must come from another source."
        );
    }
    suspect
}

/// Log the detected feature set.
///
/// Printed in full at boot because it is the single most useful piece of
/// information when a bug report says "works on my machine".
pub fn report() {
    let f = detect();
    crate::kinfo!("cpu: vendor \"{}\"", cstr(&f.vendor));
    if !f.brand.is_empty() && cstr(&f.brand).len() > 0 {
        crate::kinfo!("cpu: brand \"{}\"", cstr(&f.brand).trim());
    }
    crate::kinfo!(
        "cpu: family {:#x} model {:#x} stepping {:#x}, max leaf {:#x}, max ext leaf {:#x}",
        f.family,
        f.model,
        f.stepping,
        f.max_leaf,
        f.max_ext_leaf
    );
    if f.hypervisor_present {
        crate::kinfo!(
            "cpu: running under a hypervisor, vendor \"{}\"",
            cstr(&f.hypervisor_vendor)
        );
    } else {
        crate::kinfo!("cpu: bare metal (no hypervisor CPUID bit)");
    }

    let yesno = |b: bool| if b { "yes" } else { "NO" };
    crate::kinfo!(
        "cpu: nx={} smep={} smap={} syscall={} sse2={} apic={} x2apic={}",
        yesno(f.nx), yesno(f.smep), yesno(f.smap), yesno(f.syscall),
        yesno(f.sse2), yesno(f.apic), yesno(f.x2apic)
    );
    crate::kinfo!(
        "cpu: tsc={} invariant={} pdpe1gb={} la57={} invpcid={} fsgsbase={}",
        yesno(f.tsc), yesno(f.tsc_invariant), yesno(f.pdpe1gb),
        yesno(f.la57), yesno(f.invpcid), yesno(f.fsgsbase)
    );
    crate::kinfo!(
        "cpu: rdrand={} (suspect={}) rdseed={} avx={} avx2={}",
        yesno(f.rdrand), yesno(rdrand_suspect()), yesno(f.rdseed),
        yesno(f.avx), yesno(f.avx2)
    );
    if let Some(khz) = f.tsc_khz {
        crate::kinfo!("cpu: TSC nominal rate {} kHz (leaf 0x15)", khz);
    } else {
        crate::kdebug!("cpu: leaf 0x15 gives no TSC rate; M4 will calibrate against the PIT");
    }

    // Hard requirements. Failing these means the machine is not x86_64 as Orin
    // understands it, and continuing would produce faults with no explanation.
    assert!(f.sse2, "cpuid: SSE2 is mandatory on x86_64 but CPUID says otherwise");
    assert!(f.nx, "cpuid: NX support is required for Orin's W^X memory policy");
    assert!(f.syscall, "cpuid: SYSCALL/SYSRET is required for the M5 syscall ABI");

    // Soft requirements: log loudly, degrade explicitly.
    if !f.smep {
        crate::kwarn!(
            "cpuid: SMEP unavailable. The kernel can execute user-space code, so a \
             ret2usr mitigation is missing. Security posture is REDUCED on this machine; \
             docs/SECURITY.md §5 lists this as an explicit degradation."
        );
    }
    if !f.smap {
        crate::kwarn!(
            "cpuid: SMAP unavailable. The kernel can read user memory without an explicit \
             copy_*_user, so a stray pointer is not caught. Security posture is REDUCED."
        );
    }
    if !f.tsc_invariant && f.tsc {
        crate::kwarn!(
            "cpuid: TSC is not invariant. M4 will not use it as a clocksource across \
             cores; timing falls back to the LAPIC timer."
        );
    }
}
