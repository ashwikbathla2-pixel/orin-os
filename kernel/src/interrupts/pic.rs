//! 8259A Programmable Interrupt Controller.
//!
//! ## Why a PIC in 2026
//!
//! Real x86_64 machines route interrupts through an APIC/IOAPIC (or MSI), and
//! Orin will too — that is M4, alongside SMP, because the LAPIC is also how
//! inter-processor interrupts are delivered and there is no point doing one
//! without the other.
//!
//! But a kernel that only has an APIC driver cannot boot on firmware that hands
//! over with the PIC live, and more importantly cannot be *tested* without one:
//! QEMU's default `q35`/`pc` machine starts with the 8259 enabled and the APIC
//! in a state that requires full bring-up. Supporting the PIC first means M1
//! has working timers and keyboard interrupts, and the APIC work in M4 is an
//! *upgrade* with a fallback rather than a prerequisite.
//!
//! ## The remap is mandatory, not cosmetic
//!
//! In its factory configuration the master PIC delivers IRQ0–7 on vectors
//! 0x08–0x0F. On x86 those vector numbers are **CPU exceptions**: 0x08 is
//! double fault, 0x0D is general protection, 0x0E is page fault. A timer tick
//! would therefore be indistinguishable from a double fault, and the handler
//! would do the wrong thing with no warning. This is a legacy of the 8086,
//! which had no exceptions.
//!
//! Orin remaps master → 0x20–0x27 and slave → 0x28–0x2F, the conventional
//! offsets, which sit clear of all 32 exception vectors.

#![allow(dead_code)]

use spin::Mutex;
use x86_64::instructions::port::Port;

/// Master PIC I/O ports.
const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
/// Slave PIC I/O ports.
const SLAVE_CMD: u16 = 0xA0;
const SLAVE_DATA: u16 = 0xA1;

/// Vector offset for the master's IRQ0–7.
pub const MASTER_OFFSET: u8 = 0x20;
/// Vector offset for the slave's IRQ8–15.
pub const SLAVE_OFFSET: u8 = 0x28;

// --- Initialisation command words -------------------------------------------
const ICW1_ICW4: u8 = 0x01; // we will send ICW4
const ICW1_INIT: u8 = 0x10; // begin initialisation sequence
const ICW4_8086: u8 = 0x01; // 8086 mode (as opposed to MCS-80/85 mode)

// --- Operational commands ----------------------------------------------------
const CMD_END_OF_INTERRUPT: u8 = 0x20;

/// Vector for an IRQ number 0–15.
pub fn vector_for_irq(irq: u8) -> u8 {
    if irq < 8 {
        MASTER_OFFSET + irq
    } else {
        SLAVE_OFFSET + (irq - 8)
    }
}

/// IRQ number for a vector, or `None` if the vector is not a PIC IRQ.
pub fn irq_for_vector(vec: u8) -> Option<u8> {
    match vec {
        0x20..=0x27 => Some(vec - MASTER_OFFSET),
        0x28..=0x2F => Some(8 + (vec - SLAVE_OFFSET)),
        _ => None,
    }
}

/// Well-known IRQ lines. Named so handlers read as `IRQ_KEYBOARD` rather than
/// a magic `1`, and so a future renumbering has one place to change.
pub mod irq {
    pub const TIMER: u8 = 0;
    pub const KEYBOARD: u8 = 1;
    /// Cascade line from slave to master. Never fires as a device interrupt.
    pub const CASCADE: u8 = 2;
    pub const COM2_COM4: u8 = 3;
    pub const COM1_COM3: u8 = 4;
    pub const LPT2: u8 = 5;
    pub const FLOPPY: u8 = 6;
    pub const LPT1: u8 = 7;
    pub const CMOS_RTC: u8 = 8;
    pub const LEGACY_9: u8 = 9;
    pub const LEGACY_10: u8 = 10;
    pub const LEGACY_11: u8 = 11;
    pub const PS2_MOUSE: u8 = 12;
    pub const FPU: u8 = 13;
    pub const ATA_PRIMARY: u8 = 14;
    pub const ATA_SECONDARY: u8 = 15;
}

/// Master/slave interrupt masks. A `1` bit means "masked" (ignored).
static MASKS: Mutex<[u8; 2]> = Mutex::new([0xFF, 0xFF]);

/// Whether the remap has been performed.
static REMAPPED: Mutex<bool> = Mutex::new(false);

/// Remap both PICs and mask every IRQ.
///
/// Masking everything first is deliberate: `idt::init` has not necessarily
/// installed every handler yet, and an unmasked IRQ with no handler would be
/// delivered as a spurious interrupt at best and as an unhandled-vector panic
/// at worst. Handlers unmask their own line once they exist
/// ([`unmask`]).
pub fn remap() {
    // SAFETY: writes to the 8259A command and data ports. The sequence below
    // is the documented ICW1–ICW4 initialisation; deviating from the order
    // (or omitting the reads of the data port on some hardware) leaves the
    // controller in an undefined state.
    unsafe {
        let mut mcmd: Port<u8> = Port::new(MASTER_CMD);
        let mut mdat: Port<u8> = Port::new(MASTER_DATA);
        let mut scmd: Port<u8> = Port::new(SLAVE_CMD);
        let mut sdat: Port<u8> = Port::new(SLAVE_DATA);

        // Save the current masks so a caller can restore them; on real hardware
        // the firmware may already have unmasked lines we care about.
        let saved_master = mdat.read();
        let saved_slave = sdat.read();

        // ICW1: start initialisation, cascade mode, ICW4 will follow.
        mcmd.write(ICW1_INIT | ICW1_ICW4);
        iowait();
        scmd.write(ICW1_INIT | ICW1_ICW4);
        iowait();

        // ICW2: vector offsets.
        mdat.write(MASTER_OFFSET);
        iowait();
        sdat.write(SLAVE_OFFSET);
        iowait();

        // ICW3: cascade wiring. Master: slave on IRQ2 (bit 2).
        // Slave: "I am cascade child 2".
        mdat.write(1 << irq::CASCADE);
        iowait();
        sdat.write(irq::CASCADE);
        iowait();

        // ICW4: 8086 mode.
        mdat.write(ICW4_8086);
        iowait();
        sdat.write(ICW4_8086);
        iowait();

        // Mask everything. Handlers unmask as they are installed.
        mdat.write(0xFF);
        iowait();
        sdat.write(0xFF);
        iowait();

        let _ = (saved_master, saved_slave);
    }

    *MASKS.lock() = [0xFF, 0xFF];
    *REMAPPED.lock() = true;
    crate::kinfo!(
        "pic: 8259A remapped IRQ0-7 -> vectors {:#x}-{:#x}, IRQ8-15 -> {:#x}-{:#x}; all lines masked",
        MASTER_OFFSET,
        MASTER_OFFSET + 7,
        SLAVE_OFFSET,
        SLAVE_OFFSET + 7
    );
}

/// ISA bus devices need a short delay between port writes. The canonical trick
/// is a read or write to an unused port; `0x80` is the POST code port, which no
/// device claims.
///
/// # Safety
/// Writing to port 0x80 has no architectural side effect on any x86 platform
/// Orin targets; it is the documented way to burn ~1 µs.
unsafe fn iowait() {
    // SAFETY: the caller's contract covers this — writing 0 to port 0x80 (the
    // POST code port) has no architectural side effect on any x86 platform Orin
    // targets.
    unsafe {
        let mut p: Port<u8> = Port::new(0x80);
        p.write(0);
    }
}

/// Unmask one IRQ line.
pub fn unmask(irq_num: u8) {
    let mut masks = MASKS.lock();
    let (port, bit) = if irq_num < 8 {
        (MASTER_DATA, irq_num)
    } else {
        (SLAVE_DATA, irq_num - 8)
    };
    if irq_num >= 8 {
        // An IRQ on the slave cannot be delivered unless the cascade line on
        // the master is unmasked. Forgetting this is the classic "my PS/2 mouse
        // never interrupts" bug.
        masks[0] &= !(1 << irq::CASCADE);
        // SAFETY: masking/unmasking the master data port.
        unsafe {
            let mut mdat: Port<u8> = Port::new(MASTER_DATA);
            mdat.write(masks[0]);
            iowait();
        }
    }
    masks[if irq_num < 8 { 0 } else { 1 }] &= !(1 << bit);
    // SAFETY: as above.
    unsafe {
        let mut d: Port<u8> = Port::new(port);
        d.write(masks[if irq_num < 8 { 0 } else { 1 }]);
        iowait();
    }
    crate::kdebug!("pic: unmasked IRQ{}", irq_num);
}

/// Mask one IRQ line.
pub fn mask(irq_num: u8) {
    let mut masks = MASKS.lock();
    let idx = if irq_num < 8 { 0 } else { 1 };
    let bit = if irq_num < 8 { irq_num } else { irq_num - 8 };
    masks[idx] |= 1 << bit;
    // SAFETY: as above.
    unsafe {
        let mut d: Port<u8> = Port::new(if irq_num < 8 { MASTER_DATA } else { SLAVE_DATA });
        d.write(masks[idx]);
        iowait();
    }
}

/// Send end-of-interrupt for `vec`.
///
/// Without EOI the PIC will not deliver another interrupt on that line, and the
/// system appears to hang after exactly one tick or one keystroke. If the
/// interrupt came from the slave, **both** controllers need EOI, slave first.
pub fn end_of_interrupt(vec: u8) {
    let Some(irq_num) = irq_for_vector(vec) else {
        // Not a PIC IRQ (e.g. an exception or the syscall vector). Sending EOI
        // here would clear an unrelated in-service bit and lose an interrupt.
        return;
    };
    // SAFETY: writing the EOI command to the PIC command ports.
    unsafe {
        if irq_num >= 8 {
            let mut scmd: Port<u8> = Port::new(SLAVE_CMD);
            scmd.write(CMD_END_OF_INTERRUPT);
            iowait();
        }
        let mut mcmd: Port<u8> = Port::new(MASTER_CMD);
        mcmd.write(CMD_END_OF_INTERRUPT);
        iowait();
    }
}

/// Current masks, for `sys.interrupts` over OKI.
pub fn masks() -> [u8; 2] {
    *MASKS.lock()
}

pub fn is_remapped() -> bool {
    *REMAPPED.lock()
}
