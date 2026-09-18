//! Global Descriptor Table and Task State Segment.
//!
//! Long mode makes most of the GDT vestigial — segment bases and limits are
//! ignored for code and data — but three things still genuinely require it:
//!
//! 1. **Ring transitions.** `syscall`/`sysret` derive the user CS/SS from the
//!    kernel selectors by fixed arithmetic, so the *order* of the user data and
//!    user code descriptors is part of the ABI, not a style choice. M5 depends
//!    on it.
//! 2. **The TSS**, which is a GDT entry. It holds the IST stack pointers that
//!    make double-fault handling survivable, and the I/O permission bitmap that
//!    decides whether ring 3 may touch a given port.
//! 3. **FS/GS base** for per-CPU and thread-local data in M4.
//!
//! ## Why IST matters
//!
//! A double fault usually means the CPU could not deliver a fault, which often
//! means the *stack* is the problem. Switching to a normal kernel stack in that
//! situation faults again and triple-faults, resetting the machine with no
//! diagnostic at all. An IST entry makes the CPU load RSP from the TSS
//! unconditionally, so the handler runs on a stack known to be good — the
//! difference between a crash report and a mystery reboot.
//!
//! Orin gives a dedicated IST stack to every fault that can plausibly be caused
//! by a broken stack (`#DF`, `#NMI`, `#MC`, `#DB`, and `#PF` from M4 when page
//! faults become normal control flow). Each has an unmapped guard page below it,
//! so an overflowing IST stack faults into a known place rather than walking
//! into the neighbouring stack.

#![allow(dead_code)]

use spin::Once;
use x86_64::structures::gdt::{GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

use crate::arch::PAGE_SIZE;

// --- Selectors ---------------------------------------------------------------
// Values follow from the descriptor ORDER in `install()`. Do not reorder
// without updating docs/SYSCALL.md: `sysret`'s user-selector derivation
// requires user data to immediately precede user code.

pub const KERNEL_CODE_SEL: u16 = 0x08;
pub const KERNEL_DATA_SEL: u16 = 0x10;
pub const USER_DATA_SEL: u16 = 0x18;
pub const USER_CODE_SEL: u16 = 0x20;
pub const TSS_SEL: u16 = 0x28;

/// IST slot assignments. Slot indices are 1-based, matching the TSS field order.
pub mod ist {
    /// Double fault — the case IST exists for.
    pub const DOUBLE_FAULT: usize = 1;
    /// Non-maskable interrupt.
    pub const NMI: usize = 2;
    /// Machine check.
    pub const MACHINE_CHECK: usize = 3;
    /// Debug / single-step.
    pub const DEBUG: usize = 4;
    /// Page fault. Gets its own stack from M4, when page faults become a normal
    /// control-flow event (demand paging) instead of always meaning a bug.
    pub const PAGE_FAULT: usize = 5;
    /// Number of slots.
    pub const COUNT: usize = 5;
}

/// Usable bytes per IST stack. 16 KiB is generous for a handler whose job is to
/// print a register dump; the guard page is what actually bounds the risk.
const IST_STACK_SIZE: usize = 16 * 1024;

/// One IST slot: `[guard page][usable stack]`.
///
/// Contiguous layout makes the guard real — an overflow walks off the bottom of
/// its own stack into an unmapped page, not into the next slot's stack.
const SLOT_BYTES: usize = PAGE_SIZE as usize + IST_STACK_SIZE;

#[repr(C, align(4096))]
struct IstStacks {
    slots: [[u8; SLOT_BYTES]; ist::COUNT],
}

/// `static mut` because `TaskStateSegment` and `GlobalDescriptorTable` are not
/// writable through a shared reference after construction, and their fields
/// must be filled in during init.
///
/// Safety invariant: **written only inside `init()`, on a single core, with
/// interrupts disabled; read-only thereafter.** Recorded in the global-state
/// inventory (docs/KERNEL.md §7). M4 replaces this with per-CPU GDTs/TSSs,
/// which is when the invariant stops being trivially true.
static mut IST_STACKS: IstStacks = IstStacks {
    slots: [[0; SLOT_BYTES]; ist::COUNT],
};
static mut TSS_STORAGE: TaskStateSegment = TaskStateSegment::new();
static mut GDT_STORAGE: GlobalDescriptorTable = GlobalDescriptorTable::new();

static INIT_DONE: Once<()> = Once::new();

#[derive(Clone, Copy, Debug)]
pub struct Selectors {
    pub kernel_code: u16,
    pub kernel_data: u16,
    pub user_code: u16,
    pub user_data: u16,
    pub tss: u16,
}

/// Top-of-stack address for IST slot `slot` (1-based). Stacks grow down, so
/// "top" is the highest usable address.
fn ist_stack_top(slot: usize) -> VirtAddr {
    assert!((1..=ist::COUNT).contains(&slot), "ist: bad slot {slot}");
    // SAFETY: IST_STACKS lives in kernel .bss, mapped RW-NX by vmm::init.
    // Only address arithmetic here — no access. The first PAGE_SIZE bytes of
    // each slot are the guard, so top-of-stack never points into a guard.
    let base = unsafe { IST_STACKS.slots.as_ptr().add(slot - 1) as u64 };
    VirtAddr::new(base + SLOT_BYTES as u64)
}

/// Address of the guard page below IST slot `slot`.
fn ist_guard_addr(slot: usize) -> VirtAddr {
    let base = unsafe { IST_STACKS.slots.as_ptr().add(slot - 1) as u64 };
    VirtAddr::new(base)
}

/// Total bytes of IST storage, for the memory report.
pub fn ist_total_bytes() -> usize {
    core::mem::size_of::<IstStacks>()
}

/// Install the GDT and TSS, then reload every segment register.
///
/// Must run **before** `idt::init`: the IDT's double-fault entry needs `IST1`
/// to already point at a valid stack.
///
/// Idempotent — calling it twice returns the same selectors without rebuilding
/// the tables, because rebuilding a live GDT would invalidate the selectors the
/// CPU is currently using.
pub fn init() -> Selectors {
    INIT_DONE.call_once(|| {
        // -- report the guard pages -------------------------------------
        // They are unmapped (vmm::init does not map IST storage as accessible
        // below the stack), which on x86_64 means any access faults. That IS
        // the guard; we log the addresses so a stack-overflow panic can be
        // recognised as one.
        for slot in 1..=ist::COUNT {
            crate::kdebug!(
                "gdt: IST{} stack {:#x}..{:#x}, guard page at {:#x}",
                slot,
                ist_guard_addr(slot).as_u64() + PAGE_SIZE,
                ist_stack_top(slot).as_u64(),
                ist_guard_addr(slot).as_u64()
            );
        }

        // -- fill in the TSS --------------------------------------------
        // SAFETY: single-core boot, interrupts still disabled, and this is the
        // only code path that writes TSS_STORAGE. No aliasing of mutable state
        // survives this block: everything afterwards takes `&'static` refs.
        unsafe {
            let tss = core::ptr::addr_of_mut!(TSS_STORAGE);
            for slot in 1..=ist::COUNT {
                (*tss).interrupt_stack_table[slot - 1] = ist_stack_top(slot);
            }
            // I/O permission bitmap. Setting `iomap_base` to the TSS size means
            // "no bitmap present", which on x86_64 defers the decision to
            // CR4.IOPL. M1 runs at IOPL 0, so ring-3 port access faults — the
            // restrictive default. M9 installs a real bitmap so
            // orin-securityd can grant individual ports to named services
            // instead of granting "all ports" or "no ports".
            (*tss).iomap_base = core::mem::size_of::<TaskStateSegment>() as u16;
        }

        // -- fill in the GDT --------------------------------------------
        // SAFETY: as above; only writer, before interrupts.
        let sels = unsafe {
            let gdt = core::ptr::addr_of_mut!(GDT_STORAGE);
            let tss_ref = &*core::ptr::addr_of!(TSS_STORAGE);

            // Order is ABI. See the Selectors note above.
            let kcode = (*gdt).append(x86_64::structures::gdt::Descriptor::kernel_code_segment());
            let kdata = (*gdt).append(x86_64::structures::gdt::Descriptor::kernel_data_segment());
            let udata = (*gdt).append(x86_64::structures::gdt::Descriptor::user_data_segment());
            let ucode = (*gdt).append(x86_64::structures::gdt::Descriptor::user_code_segment());
            let tss_s = (*gdt).append(x86_64::structures::gdt::Descriptor::tss_segment(tss_ref));

            Selectors {
                kernel_code: kcode.0,
                kernel_data: kdata.0,
                user_data: udata.0,
                user_code: ucode.0,
                tss: tss_s.0,
            }
        };

        // -- load --------------------------------------------------------
        // SAFETY: GDT_STORAGE is a 'static kernel image address, mapped and
        // valid for the lifetime of the kernel.
        unsafe {
            (*core::ptr::addr_of!(GDT_STORAGE)).load();
            x86_64::instructions::tables::load_tss(SegmentSelector::new(sels.tss, x86_64::PrivilegeLevel::Ring0));
        }

        // -- reload segment registers ------------------------------------
        // The CPU is still using the boot GDT's descriptors (same selector
        // values, same flags — boot.asm chose them to match). Reloading is
        // still mandatory: after this function the boot GDT is no longer the
        // loaded table, so continuing to reference it would mean the running
        // segment state points at a table that `lgdt` has retired.
        //
        // SAFETY: the selectors name present, valid descriptors in the GDT we
        // just loaded, at the current privilege level.
        unsafe {
            // x86_64 0.15 exposes this as `Segment::set_reg`, an unsafe trait
            // method, rather than an inherent `::set`. CS is special: the crate
            // implements it as push-selector / push-return-address / `retfq`,
            // because AMD does not support 64-bit far jumps — so this is the
            // only portable way to reload CS at all.
            use x86_64::instructions::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
            let ring0 = x86_64::PrivilegeLevel::Ring0;
            CS::set_reg(SegmentSelector::new(sels.kernel_code, ring0));
            SS::set_reg(SegmentSelector::new(sels.kernel_data, ring0));
            DS::set_reg(SegmentSelector::new(sels.kernel_data, ring0));
            ES::set_reg(SegmentSelector::new(sels.kernel_data, ring0));
            FS::set_reg(SegmentSelector::new(sels.kernel_data, ring0));
            GS::set_reg(SegmentSelector::new(sels.kernel_data, ring0));
        }

        // Verify the selectors came out as the ABI requires. If they did not,
        // M5's sysret arithmetic will be wrong and the failure would surface as
        // a bizarre user-mode crash months later — so check it now.
        assert_eq!(
            sels.kernel_code, KERNEL_CODE_SEL,
            "gdt: kernel code selector is {:#x}, ABI requires {:#x}",
            sels.kernel_code, KERNEL_CODE_SEL
        );
        assert_eq!(sels.user_data, USER_DATA_SEL, "gdt: user data selector mismatch");
        assert_eq!(sels.user_code, USER_CODE_SEL, "gdt: user code selector mismatch");
        crate::kinfo!(
            "gdt: installed (kcode {:#x}, kdata {:#x}, udata {:#x}, ucode {:#x}, tss {:#x})",
            sels.kernel_code,
            sels.kernel_data,
            sels.user_data,
            sels.user_code,
            sels.tss
        );
        crate::kinfo!(
            "gdt: {} IST stacks, {} KiB total, each with a guard page",
            ist::COUNT,
            ist_total_bytes() / 1024
        );
    });

    Selectors {
        kernel_code: KERNEL_CODE_SEL,
        kernel_data: KERNEL_DATA_SEL,
        user_data: USER_DATA_SEL,
        user_code: USER_CODE_SEL,
        tss: TSS_SEL,
    }
}
