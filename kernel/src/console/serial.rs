//! 16550 UART serial console (COM1, `0x3F8`).
//!
//! This is Orin's *primary* kernel log destination, and the reason `make test`
//! can assert on boot behaviour without a human watching a window: QEMU is
//! started with `-serial file:build/serial.log`, so everything the kernel
//! writes here lands in a file the test harness greps.
//!
//! Hand-rolled rather than pulling in the `uart_16550` crate — it is ~90 lines
//! of port I/O against a 40-year-old documented register map, and owning it
//! means we can add the RX path (needed by M9 for a serial debug shell)
//! without waiting on an upstream feature.

use core::fmt;
use spin::Mutex;
use x86_64::instructions::port::Port;

/// COM1 base I/O port. COM2..4 are 0x2F8, 0x3E8, 0x2E8.
pub const COM1: u16 = 0x3F8;

// Public so `console::raw` can drive the same UART without going through the
// mutex-protected `Serial` object. See console/raw.rs for why that matters.
pub const REG_DATA: u16 = 0;
pub const REG_INT_ENABLE: u16 = 1;
pub const REG_FIFO_CTRL: u16 = 2;
pub const REG_LINE_CTRL: u16 = 3;
pub const REG_MODEM_CTRL: u16 = 4;
pub const REG_LINE_STATUS: u16 = 5;

/// Line status bit 5: transmitter holding register is empty.
pub const LSR_THRE: u8 = 1 << 5;
/// Line status bit 0: data ready in the receive buffer.
pub const LSR_DR: u8 = 1 << 0;

/// 8 data bits, no parity, one stop bit.
const LINE_CTRL_8N1: u8 = 0x03;
/// Divisor latch access bit.
const LINE_CTRL_DLAB: u8 = 0x80;

pub struct Serial {
    base: u16,
    initialised: bool,
}

impl Serial {
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            initialised: false,
        }
    }

    /// Program the UART: 8N1, 115200 baud, FIFOs on, loopback self-test.
    ///
    /// The loopback test at the end is not decoration. A serial port that is
    /// wired to nothing (common on real hardware, and on QEMU without
    /// `-serial`) will still accept writes, so without a self-test we would
    /// print logs into a void and believe they were captured. Detecting the
    /// absent port lets the kernel report "serial: NOT PRESENT" instead of
    /// silently losing every diagnostic.
    pub fn init(&mut self) {
        // SAFETY: all accesses are to the documented 16550 register window at
        // `self.base`. Writing these registers configures the UART and has no
        // effect on memory or other devices.
        unsafe {
            let mut int_enable: Port<u8> = Port::new(self.base + REG_INT_ENABLE);
            let mut line_ctrl: Port<u8> = Port::new(self.base + REG_LINE_CTRL);
            let mut fifo_ctrl: Port<u8> = Port::new(self.base + REG_FIFO_CTRL);
            let mut modem_ctrl: Port<u8> = Port::new(self.base + REG_MODEM_CTRL);
            let mut data: Port<u8> = Port::new(self.base + REG_DATA);

            // Disable all interrupts: M1 polls the transmit-ready bit. The
            // RX interrupt path arrives in M9 with the debug shell.
            int_enable.write(0x00);

            // Enable DLAB to set the baud divisor.
            line_ctrl.write(LINE_CTRL_DLAB);

            // 115200 baud: divisor = 115200 / 115200 = 1.
            // (1 for 115200, 2 for 57600, 3 for 38400, 12 for 9600.)
            data.write(0x01); // divisor low byte
            int_enable.write(0x00); // divisor high byte

            // 8N1, DLAB off.
            line_ctrl.write(LINE_CTRL_8N1);

            // Enable FIFOs, clear them, 14-byte trigger threshold.
            fifo_ctrl.write(0xC7);

            // Assert DTR + RTS + OUT2. OUT2 is required on real hardware to
            // unmask the interrupt line; harmless in QEMU.
            modem_ctrl.write(0x0B);

            // Loopback self-test: in loopback mode the transmitter is wired to
            // the receiver, so a byte written must come straight back.
            modem_ctrl.write(0x1E);
            data.write(0xAE);

            let mut ok = false;
            for _ in 0..100_000 {
                let mut lsr: Port<u8> = Port::new(self.base + REG_LINE_STATUS);
                if lsr.read() & LSR_DR != 0 {
                    ok = data.read() == 0xAE;
                    break;
                }
            }

            // Leave loopback, normal operation.
            modem_ctrl.write(0x0F);

            self.initialised = ok;
        }
    }

    /// True if the loopback self-test passed at [`init`](Self::init).
    pub fn present(&self) -> bool {
        self.initialised
    }

    /// Blocking write of one byte.
    pub fn write_byte(&mut self, byte: u8) {
        if !self.initialised {
            return;
        }
        // SAFETY: reads the line-status register and writes the data register
        // of the same UART configured in `init`.
        unsafe {
            let mut lsr: Port<u8> = Port::new(self.base + REG_LINE_STATUS);
            let mut data: Port<u8> = Port::new(self.base + REG_DATA);

            // Wait for the transmit holding register to drain. The bound
            // prevents an infinite hang if the UART stops responding — a
            // kernel that wedges inside its own log path cannot report why.
            let mut spins = 0u32;
            while lsr.read() & LSR_THRE == 0 {
                spins += 1;
                if spins > 10_000_000 {
                    self.initialised = false;
                    return;
                }
                crate::cpu::pause();
            }
            data.write(byte);
        }
    }

    /// Non-blocking read of one byte, if the UART has one.
    ///
    /// Returns `None` when nothing is pending. Used by the M1 keyboard test
    /// path and, in M9, by the serial debug shell.
    pub fn try_read_byte(&mut self) -> Option<u8> {
        if !self.initialised {
            return None;
        }
        // SAFETY: as above; reading the data register consumes one byte from
        // the RX FIFO.
        unsafe {
            let mut lsr: Port<u8> = Port::new(self.base + REG_LINE_STATUS);
            if lsr.read() & LSR_DR == 0 {
                return None;
            }
            let mut data: Port<u8> = Port::new(self.base + REG_DATA);
            Some(data.read())
        }
    }

    pub fn write_str(&mut self, s: &str) {
        for b in s.bytes() {
            if b == b'\n' {
                // Serial terminals expect CRLF for a bare LF on many hosts;
                // QEMU's `file:` backend records bytes verbatim, and the test
                // harness greps line-wise, so emit CRLF for correct display
                // and harmless capture.
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }
}

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Serial::write_str(self, s);
        Ok(())
    }
}

/// COM1, the global serial console.
pub static COM1_PORT: Mutex<Serial> = Mutex::new(Serial::new(COM1));

pub fn print(args: fmt::Arguments) {
    use fmt::Write;
    COM1_PORT.lock().write_fmt(args).ok();
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {{
        $crate::console::serial::print(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($($arg:tt)*) => {{
        $crate::console::serial::print(format_args!($($arg)*));
        $crate::console::serial::print(format_args!("\n"));
    }};
}
