//! Programmable Interval Timer (8253/8254) — the M1 system tick.
//!
//! ## What it is for
//!
//! In M1 the PIT provides exactly two things:
//!
//! 1. A **monotonic clock**. Every kernel log record is timestamped from this
//!    counter, which is why the boot log can say how long init took.
//! 2. A **scheduler tick placeholder**. M4 replaces it with the LAPIC timer,
//!    which is per-core and does not require an 8254. Keeping the tick in a
//!    separate module means that swap touches one file.
//!
//! ## Why not the TSC
//!
//! `rdtsc` is faster and higher-resolution, and M4 will use it for fine-grained
//! timing. It is *not* used as the M1 clock because:
//!
//! * Its frequency is not discoverable from CPUID on all hardware; it must be
//!   calibrated against a known-rate source — which is the PIT.
//! * `Invariant TSC` (CPUID.8000_0007H:EDX[8]) is what makes it safe to read
//!   across cores and sleep states. Detecting and falling back is real work,
//!   and doing it half-way produces a clock that drifts under load.
//!
//! So: PIT for the tick and coarse time now, calibrated TSC for fine time in M4.
//!
//! ## Rate
//!
//! 1000 Hz. That is a 1 ms tick — fine enough for scheduler granularity and log
//! timestamps, coarse enough that interrupt overhead is negligible. The 8254
//! input clock is nominally 1.193182 MHz, so the divisor is 1193 (which gives
//! 1000.15 Hz; the error is 0.015% and is accounted for in `millis_since_boot`
//! rather than silently ignored).

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

const PIT_CHANNEL0_DATA: u16 = 0x40;
const PIT_CHANNEL2_DATA: u16 = 0x42;
const PIT_COMMAND: u16 = 0x43;

/// Nominally 1 193 182 Hz. Every 8254 datasheet and every OS uses this figure.
pub const PIT_INPUT_HZ: u64 = 1_193_182;

/// Channel 0, low byte then high byte, mode 3 (square wave generator), binary.
const CMD_CHANNEL0_MODE3: u8 = 0x36;

/// Ticks per second we request.
pub const TICK_HZ: u64 = 1000;

/// Divisor actually programmed. `PIT_INPUT_HZ / TICK_HZ` = 1193 (truncated).
pub const DIVISOR: u16 = (PIT_INPUT_HZ / TICK_HZ) as u16;

/// Real tick rate after integer truncation of the divisor, as an exact rational.
///
/// The 8254 counts down from `DIVISOR` at `PIT_INPUT_HZ`, so one channel-0 tick
/// is exactly `DIVISOR / PIT_INPUT_HZ` seconds. That is a rational number, and
/// it is stored as one.
///
/// It used to be `pub const ACTUAL_TICK_HZ: f64`. That is gone, deliberately:
/// `x86_64-unknown-none` is built `+soft-float,-sse2`, so an f64 division
/// becomes a call to `__divdf3`. Those intrinsics are only emitted by
/// `compiler_builtins` when its float routines are enabled, which
/// `-Z build-std-features=compiler-builtins-mem` does not do — so the kernel
/// failed to *link*, reporting the missing routine as
/// `relocation R_X86_64_GOTPCREL out of range ... references '__divdf3'`,
/// which names neither the cause nor the cure.
///
/// The exact rational is not a workaround that costs precision. It is strictly
/// better than the f64 was: `1000.1525…` is not representable in binary
/// floating point, so the old code accumulated a small representation error on
/// top of the divisor truncation it was trying to correct. Integer arithmetic on
/// the numerator and denominator is exact, and `make verify-elf` fails the build
/// if any soft-float routine is ever referenced again.
///
/// 1 193 182 / 1193 = 1000.1525… Hz, i.e. ~0.015% faster than the 1000 Hz asked
/// for. [`micros_since_boot`] accounts for it rather than letting a 10-minute
/// uptime report 90 ms of drift.
pub const ACTUAL_TICK_HZ_NUM: u64 = PIT_INPUT_HZ;
/// Denominator of [`ACTUAL_TICK_HZ_NUM`] — the programmed divisor.
pub const ACTUAL_TICK_HZ_DEN: u64 = DIVISOR as u64;

/// Ticks since boot. `u64` at 1 kHz wraps after ~584 million years, so no
/// wraparound handling is needed and none is written.
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Whether [`init`] has run. `tick` refuses to count before it, so a spurious
/// IRQ0 during early init cannot make the clock claim time that has not passed.
static ENABLED: Mutex<bool> = Mutex::new(false);

/// Program channel 0 for `TICK_HZ` and arm the tick counter.
///
/// Does **not** unmask IRQ0 — `interrupts::init` does that once the IDT has a
/// handler installed, because an unmasked timer with no handler is a spurious
/// interrupt storm.
pub fn init() {
    // SAFETY: writes to the 8254 command and channel-0 data ports. Channel 0's
    // output is wired to IRQ0; channel 1 (DRAM refresh on ancient hardware) and
    // channel 2 (speaker) are left alone.
    unsafe {
        let mut cmd: Port<u8> = Port::new(PIT_COMMAND);
        let mut ch0: Port<u8> = Port::new(PIT_CHANNEL0_DATA);

        cmd.write(CMD_CHANNEL0_MODE3);
        // Low byte then high byte, per the command word above.
        ch0.write((DIVISOR & 0xFF) as u8);
        ch0.write((DIVISOR >> 8) as u8);
    }
    *ENABLED.lock() = true;
    // The achieved rate is printed as the exact rational it is. Rendering it as
    // "1000.1525 Hz" would need the f64 division this module deliberately does
    // not perform (see ACTUAL_TICK_HZ_NUM), and a rounded decimal in a boot log
    // invites someone to treat the rounding as the real rate.
    crate::kinfo!(
        "pit: channel 0 programmed, divisor {} -> {}/{} Hz exact (requested {} Hz)",
        DIVISOR,
        ACTUAL_TICK_HZ_NUM,
        ACTUAL_TICK_HZ_DEN,
        TICK_HZ
    );
}

/// Called from the IRQ0 handler. Cheap and allocation-free by requirement: it
/// runs 1000 times per second on the interrupt stack.
pub fn tick() {
    if *ENABLED.lock() {
        TICKS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Ticks since boot.
pub fn ticks_since_boot() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Microseconds since boot, corrected for the divisor truncation.
///
/// This is the primitive; [`millis_since_boot`] and the log timestamp derive
/// from it. Microseconds rather than milliseconds because the log format prints
/// three decimal places of a second, and computing that from a millisecond
/// counter would quantise it.
///
/// Returns `0` before [`init`], which is the honest answer: there is no clock
/// yet. Log records emitted during init steps 1–13 therefore all read `0.000`,
/// and the boot banner says so rather than implying they were simultaneous.
///
/// ## The arithmetic
///
/// One tick is `DIVISOR / PIT_INPUT_HZ` seconds, so
///
/// ```text
/// micros = ticks * 1_000_000 * DIVISOR / PIT_INPUT_HZ
/// ```
///
/// done exactly, with no floating point. `ticks * 1_193_000_000_000` overflows
/// u64 at ~1.8e19, which at 1 kHz is about 584 years of uptime — but the
/// multiplication happens in `u128` anyway, so the intermediate cannot overflow
/// and the result is exact rather than exact-until-some-date.
///
/// ## Drift this does NOT correct
///
/// The 8254's input clock is itself only nominal: real hardware varies by a
/// fraction of a percent, and QEMU's is exact by construction. Correcting that
/// needs a calibrated reference, which is what M4's TSC calibration provides.
/// Until then this is exact with respect to the *programmed* rate and no more,
/// and the banner reports the tick rate so the reader knows which clock they are
/// looking at.
pub fn micros_since_boot() -> u64 {
    if !*ENABLED.lock() {
        return 0;
    }
    let ticks = ticks_since_boot() as u128;
    let micros = ticks * 1_000_000 * ACTUAL_TICK_HZ_DEN as u128 / ACTUAL_TICK_HZ_NUM as u128;
    // u128 -> u64 cannot truncate here: 2^64 microseconds is ~584 000 years.
    micros as u64
}

/// Whole milliseconds since boot. Truncates; use [`micros_since_boot`] when the
/// sub-millisecond part matters.
pub fn millis_since_boot() -> u64 {
    micros_since_boot() / 1000
}

/// Whole seconds since boot.
pub fn seconds_since_boot() -> u64 {
    micros_since_boot() / 1_000_000
}

/// Human-readable uptime for the banner and `orin system`.
pub fn uptime_string() -> Uptime {
    // Derived from micros_since_boot rather than `ticks / TICK_HZ` so that the
    // human-readable uptime and the log timestamps cannot disagree: both come
    // from the same drift-corrected value.
    let total = micros_since_boot() / 1_000_000;
    Uptime {
        days: (total / 86400) as u32,
        hours: ((total % 86400) / 3600) as u8,
        minutes: ((total % 3600) / 60) as u8,
        seconds: (total % 60) as u8,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uptime {
    pub days: u32,
    pub hours: u8,
    pub minutes: u8,
    pub seconds: u8,
}

impl core::fmt::Display for Uptime {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if self.days > 0 {
            write!(
                f,
                "{}d {:02}:{:02}:{:02}",
                self.days, self.hours, self.minutes, self.seconds
            )
        } else {
            write!(f, "{:02}:{:02}:{:02}", self.hours, self.minutes, self.seconds)
        }
    }
}

/// Busy-wait for approximately `micros` microseconds using channel 2.
///
/// Channel 2 is not wired to IRQ0, so polling it does not disturb the system
/// tick — which is exactly why short precise delays use channel 2 and not
/// channel 0. Used by `drivers/keyboard.rs` for the PS/2 controller's
/// command/settling delays, where "sleep until the next tick" would be up to
/// 1 ms and the controller's own timeout is shorter than that.
///
/// Only valid before interrupts matter for precision; M4 replaces it with a
/// proper `sleep_until` on the calibrated TSC.
pub fn spin_delay_us(micros: u32) {
    // SAFETY: programs PIT channel 2 in one-shot mode and polls its status bit.
    // Channel 2's gate is controlled via port 0x61; we set it, run the countdown,
    // and restore it, so the PC speaker (also on channel 2) is unaffected.
    unsafe {
        let mut cmd: Port<u8> = Port::new(PIT_COMMAND);
        let mut ch2: Port<u8> = Port::new(PIT_CHANNEL2_DATA);
        let mut status: Port<u8> = Port::new(0x61);

        let saved = status.read();
        // Enable channel 2 gate, disable speaker output.
        status.write((saved | 0x01) & !0x02);

        // Channel 2, lo/hi, mode 0 (one-shot), binary.
        cmd.write(0xB0);

        let ticks = ((micros as u64) * PIT_INPUT_HZ / 1_000_000).max(1).min(0xFFFF) as u16;
        ch2.write((ticks & 0xFF) as u8);
        ch2.write((ticks >> 8) as u8);

        // Bit 5 of port 0x61 goes high when channel 2's counter reaches zero.
        let mut guard = 0u32;
        while status.read() & (1 << 5) == 0 {
            guard += 1;
            // Bound the wait. A timer that never fires must not hang the
            // kernel inside a delay routine — that turns a diagnosable driver
            // bug into an unresponsive machine.
            if guard > 20_000_000 {
                crate::kwarn!(
                    "pit: spin_delay_us({}) timed out waiting for channel 2; hardware may lack a PIT",
                    micros
                );
                break;
            }
            crate::cpu::pause();
        }
        status.write(saved);
    }
}
