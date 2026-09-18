//! Lock-free raw console output, for panic and fatal-exception paths.
//!
//! ## Why this module exists
//!
//! `console::log` writes through `spin::Mutex`-guarded console objects, which is
//! correct for normal operation: it keeps lines intact and counts records.
//!
//! It is **not** correct inside a panic handler. `spin::Mutex` is not
//! re-entrant, and the most likely reason for a panic to happen mid-log-line is
//! that the code panicked *while holding the console lock*. A panic handler
//! that then calls `lock()` deadlocks, and the system hangs producing no output
//! at all — losing the one diagnostic that mattered. That failure mode is worse
//! than interleaved text.
//!
//! So this path bypasses every lock. It touches only:
//!
//! * the UART data/status ports for serial, and
//! * the VGA text buffer via volatile writes for the screen.
//!
//! Both are safe to write from two contexts at once: the worst outcome is
//! interleaved characters, which is readable, versus a deadlock, which is not.
//!
//! ## What this is not
//!
//! Not a replacement for `console::log`. It has no level filtering, no
//! timestamp, no record counting and no subsystem field beyond what the caller
//! puts in the text. It exists for exactly two callers: `panic.rs` and
//! `idt.rs::fatal_exception`.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicUsize, Ordering};

use x86_64::instructions::port::Port;

use super::serial::{COM1, LSR_THRE};
use super::vga::{HEIGHT, WIDTH};

/// VGA cursor position for the raw path, independent of the `vga::WRITER`
/// mutex-protected cursor. They can diverge — that is acceptable and better
/// than deadlocking. Divergence is bounded because the raw path is only used
/// when the system is already dying.
static RAW_ROW: AtomicUsize = AtomicUsize::new(0);
static RAW_COL: AtomicUsize = AtomicUsize::new(0);

/// Whether the UART passed its loopback self-test. Read, never written, after
/// `serial::init`, so no lock is needed.
static SERIAL_OK: AtomicUsize = AtomicUsize::new(0);

pub fn set_serial_ok(v: bool) {
    SERIAL_OK.store(if v { 1 } else { 0 }, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Serial
// ---------------------------------------------------------------------------

fn serial_byte(b: u8) {
    if SERIAL_OK.load(Ordering::Relaxed) == 0 {
        return;
    }
    // SAFETY: polls the UART line-status register until the transmit holding
    // register is empty, then writes one byte to the data register. No locks,
    // no memory. The spin bound means a wedged UART cannot hang the panic
    // handler — losing the tail of a panic message is better than never
    // finishing it.
    unsafe {
        let mut lsr: Port<u8> = Port::new(COM1 + super::serial::REG_LINE_STATUS);
        let mut data: Port<u8> = Port::new(COM1 + super::serial::REG_DATA);
        let mut spins = 0u32;
        while lsr.read() & LSR_THRE == 0 {
            spins += 1;
            if spins > 2_000_000 {
                return;
            }
            crate::cpu::pause();
        }
        data.write(b);
    }
}

fn serial_str(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            serial_byte(b'\r');
        }
        serial_byte(b);
    }
}

// ---------------------------------------------------------------------------
// VGA
// ---------------------------------------------------------------------------

/// Attribute byte: white on red, for fatal output. Distinct from the normal
/// console's grey-on-black so a panic is unmistakable on screen even if the
/// text scrolls past.
const FATAL_ATTR: u8 = 0x4F;

fn vga_cell(row: usize, col: usize, ascii: u8, attr: u8) {
    if row >= HEIGHT || col >= WIDTH {
        return;
    }
    // The VGA window is mapped as a device region by `vmm::init` at
    // `phys_to_virt(0xB8000)`. Recomputing the address here rather than sharing
    // `vga::WRITER`'s state keeps this path free of any dependency on a lock.
    let base = crate::arch::phys_as_ident(x86_64::PhysAddr::new(0xB8000)).as_u64();
    let off = (row * WIDTH + col) * 2;
    // SAFETY: `base + off` is inside the single mapped VGA page (row < 25,
    // col < 80 keeps off < 4000). Volatile because it is a device region.
    unsafe {
        let p = (base + off as u64) as *mut u8;
        p.write_volatile(ascii);
        p.add(1).write_volatile(attr);
    }
}

fn vga_scroll() {
    let base = crate::arch::phys_as_ident(x86_64::PhysAddr::new(0xB8000)).as_u64();
    // SAFETY: copies within the mapped VGA page. `copy_from` on overlapping
    // ranges is correct here because we move rows upward in ascending order,
    // and each source row is read before its destination row is written.
    unsafe {
        let src = (base + WIDTH as u64 * 2) as *const u8;
        let dst = base as *mut u8;
        let bytes = WIDTH * 2 * (HEIGHT - 1);
        core::ptr::copy(src, dst, bytes);
        for i in 0..(WIDTH * 2) {
            let p = (base + bytes as u64 + i as u64) as *mut u8;
            p.write_volatile(if i % 2 == 0 { b' ' } else { FATAL_ATTR });
        }
    }
}

fn vga_byte(b: u8) {
    let mut row = RAW_ROW.load(Ordering::Relaxed);
    let mut col = RAW_COL.load(Ordering::Relaxed);
    match b {
        b'\n' => {
            col = 0;
            row += 1;
        }
        b'\r' => col = 0,
        0x08 => {
            if col > 0 {
                col -= 1;
                vga_cell(row, col, b' ', FATAL_ATTR);
            }
        }
        c => {
            // The VGA text console is a one-byte-per-cell code page. Non-ASCII
            // becomes '?' rather than being silently dropped — same policy as
            // the normal console, and the framebuffer console in M8 is the
            // Unicode one.
            vga_cell(row, col, if c.is_ascii_graphic() || c == b' ' { c } else { b'?' }, FATAL_ATTR);
            col += 1;
        }
    }
    if col >= WIDTH {
        col = 0;
        row += 1;
    }
    while row >= HEIGHT {
        vga_scroll();
        row = HEIGHT - 1;
    }
    RAW_ROW.store(row, Ordering::Relaxed);
    RAW_COL.store(col, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Write formatted text to both consoles with no locking.
pub fn print(args: fmt::Arguments) {
    // Buffer into a small fixed array first, then emit to both targets.
    // Formatting twice would double the UART cost; formatting once into a
    // stack buffer keeps the two outputs identical, which matters when someone
    // is comparing a screenshot against a serial log.
    let mut buf = [0u8; 512];
    let mut w = SliceWriter { buf: &mut buf, len: 0 };
    let _ = w.write_fmt(args);
    let s = core::str::from_utf8(&w.buf[..w.len]).unwrap_or("<utf8 error>");
    serial_str(s);
    for b in s.bytes() {
        vga_byte(b);
    }
}

/// Write a plain `&str` with no formatting. Cheapest path; used for the panic
/// markers, which must survive even if formatting is what broke.
pub fn print_str(s: &str) {
    serial_str(s);
    for b in s.bytes() {
        vga_byte(b);
    }
}

struct SliceWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Write for SliceWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let n = bytes.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        if n < bytes.len() {
            // Truncated. Append a marker so a reader knows the message was cut
            // rather than believing the kernel stopped mid-sentence.
            let tail = b"...[truncated]";
            let m = tail.len().min(self.buf.len() - self.len);
            self.buf[self.len..self.len + m].copy_from_slice(&tail[..m]);
            self.len += m;
        }
        Ok(())
    }
}

/// Macros for the two fatal paths.
#[macro_export]
macro_rules! raw_print {
    ($($arg:tt)*) => {{
        $crate::console::raw::print(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! raw_println {
    () => { $crate::console::raw::print_str("\n") };
    ($($arg:tt)*) => {{
        $crate::console::raw::print(format_args!($($arg)*));
        $crate::console::raw::print_str("\n");
    }};
}
