//! VGA text-mode console (80×25, `0xB8000`).
//!
//! This is the *early* console: it works before the heap, before the IDT, and
//! before any driver has been initialised, because the firmware has already
//! put the card in mode 3. It is deliberately tiny and allocation-free.
//!
//! It is **not** the long-term console. M8 replaces it with the framebuffer
//! console, and the graphical compositor supersedes that. It stays in the tree
//! because a kernel that can print before its graphics stack is up is a kernel
//! you can debug when the graphics stack is what's broken.

use core::fmt;
use core::ptr;
use spin::Mutex;

use crate::arch::phys_to_virt;
use x86_64::PhysAddr;

pub const WIDTH: usize = 80;
pub const HEIGHT: usize = 25;

/// Physical address of the VGA text buffer in mode 3.
const VGA_PHYS: u64 = 0xB800_0;

#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ColorCode(pub u8);

impl ColorCode {
    pub const fn new(fg: Color, bg: Color) -> Self {
        Self((bg as u8) << 4 | (fg as u8))
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Cell {
    ascii: u8,
    color: ColorCode,
}

/// Raw access to one cell of the text buffer.
///
/// # Safety
/// `index` must be `< WIDTH * HEIGHT`. The buffer is a memory-mapped device
/// region; writes there have side effects, so every access is `volatile`.
#[inline]
unsafe fn cell_ptr(index: usize) -> *mut Cell {
    // The VGA window is below 1 MiB, i.e. inside the boot identity map, so the
    // higher-half translation is valid for it.
    let base = phys_to_virt(PhysAddr::new(VGA_PHYS)).as_u64() as *mut Cell;
    // SAFETY: the caller guarantees `index < WIDTH * HEIGHT`, so the offset
    // stays inside the single mapped VGA page.
    unsafe { base.add(index) }
}

fn write_cell(index: usize, ascii: u8, color: ColorCode) {
    // SAFETY: caller guarantees index < WIDTH*HEIGHT; the pointer is the
    // firmware-provided VGA window, mapped RW in the boot page tables.
    // `cell_ptr` is itself unsafe (it performs pointer arithmetic on a
    // memory-mapped device region), so it must be called inside the block.
    unsafe {
        let p = cell_ptr(index);
        ptr::write_volatile(p, Cell { ascii, color });
    }
}

fn read_cell(index: usize) -> u8 {
    // SAFETY: as above, read-only.
    unsafe { ptr::read_volatile(cell_ptr(index)).ascii }
}

pub struct VgaWriter {
    column: usize,
    row: usize,
    color: ColorCode,
}

impl VgaWriter {
    pub const fn new() -> Self {
        Self {
            column: 0,
            row: 0,
            color: ColorCode::new(Color::LightGray, Color::Black),
        }
    }

    /// Initialise the console: clear the screen (which also erases whatever
    /// GRUB printed) and reset the cursor.
    pub fn init(&mut self) {
        self.clear_screen();
        self.update_hw_cursor();
    }

    pub fn set_color(&mut self, fg: Color, bg: Color) {
        self.color = ColorCode::new(fg, bg);
    }

    pub fn clear_screen(&mut self) {
        for i in 0..(WIDTH * HEIGHT) {
            write_cell(i, b' ', self.color);
        }
        self.column = 0;
        self.row = 0;
    }

    /// Clear only the current line, from column 0. Used by the interactive
    /// echo line in M1.
    pub fn clear_line(&mut self, row: usize) {
        if row >= HEIGHT {
            return;
        }
        for c in 0..WIDTH {
            write_cell(row * WIDTH + c, b' ', self.color);
        }
    }

    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.new_line(),
            b'\r' => self.column = 0,
            0x08 => self.backspace(),
            0x09 => {
                // Tab: advance to the next 8-column stop.
                let next = (self.column + 8) & !7;
                self.column = next.min(WIDTH - 1);
            }
            // Non-printable control characters are rendered as a visible
            // marker rather than dropped: silently discarding output is how
            // "why is my log missing a line" bugs happen.
            byte if byte < 0x20 || byte == 0x7F => {
                self.put(b'^');
                self.put(byte.wrapping_add(0x40) | 0x80 * 0);
            }
            byte => self.put(byte),
        }
    }

    fn put(&mut self, ascii: u8) {
        if self.column >= WIDTH {
            self.new_line();
        }
        write_cell(self.row * WIDTH + self.column, ascii, self.color);
        self.column += 1;
        self.update_hw_cursor();
    }

    fn backspace(&mut self) {
        if self.column > 0 {
            self.column -= 1;
        } else if self.row > 0 {
            self.row -= 1;
            self.column = WIDTH - 1;
        } else {
            return;
        }
        write_cell(self.row * WIDTH + self.column, b' ', self.color);
        self.update_hw_cursor();
    }

    fn new_line(&mut self) {
        self.column = 0;
        if self.row < HEIGHT - 1 {
            self.row += 1;
        } else {
            self.scroll_up();
        }
        self.update_hw_cursor();
    }

    fn scroll_up(&mut self) {
        for row in 1..HEIGHT {
            for col in 0..WIDTH {
                let ch = read_cell(row * WIDTH + col);
                write_cell((row - 1) * WIDTH + col, ch, self.color);
            }
        }
        self.clear_line(HEIGHT - 1);
    }

    /// Program the CRT controller's hardware cursor so a user watching the
    /// VGA output can see where input goes. Ports 0x3D4 (index) / 0x3D5 (data).
    fn update_hw_cursor(&mut self) {
        let pos = (self.row * WIDTH + self.column) as u16;
        // SAFETY: these are the standard VGA CRTC ports; writing cursor
        // position registers 0x0E/0x0F has no effect beyond moving the cursor.
        unsafe {
            use x86_64::instructions::port::Port;
            let mut idx: Port<u8> = Port::new(0x3D4);
            let mut dat: Port<u8> = Port::new(0x3D5);
            idx.write(0x0F);
            dat.write((pos & 0xFF) as u8);
            idx.write(0x0E);
            dat.write(((pos >> 8) & 0xFF) as u8);
        }
    }

    /// Current cursor position, for tests and for the interactive line.
    pub fn position(&self) -> (usize, usize) {
        (self.row, self.column)
    }

    /// Read back a whole row of text. Used by the boot self-test to verify the
    /// console actually wrote what it claimed to write.
    pub fn read_row(&self, row: usize) -> [u8; WIDTH] {
        let mut out = [b' '; WIDTH];
        if row < HEIGHT {
            for c in 0..WIDTH {
                out[c] = read_cell(row * WIDTH + c);
            }
        }
        out
    }
}

impl fmt::Write for VgaWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            // VGA text mode is a 1-byte-per-cell code-page device. UTF-8
            // multibyte sequences are rendered as their ASCII approximation:
            // non-ASCII bytes become '?'. This is a known limitation of the
            // early console, not of Orin — the framebuffer console in M8 is
            // fully Unicode. Pretending otherwise would violate Rule 1.
            self.write_byte(if byte.is_ascii() { byte } else { b'?' });
        }
        Ok(())
    }
}

/// The global VGA console.
pub static WRITER: Mutex<VgaWriter> = Mutex::new(VgaWriter::new());

/// Print to the VGA console only. Safe to call before `log` is configured.
pub fn print(args: fmt::Arguments) {
    use fmt::Write;
    // Interrupts are off during early init, so `lock()` cannot deadlock here;
    // later, a deadlock would indicate a real bug (printing from an interrupt
    // handler while the console is held) and spinning is the visible symptom.
    WRITER.lock().write_fmt(args).ok();
}

#[macro_export]
macro_rules! vga_print {
    ($($arg:tt)*) => {{
        $crate::console::vga::print(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! vga_println {
    () => { $crate::vga_print!("\n") };
    ($($arg:tt)*) => {{
        $crate::console::vga::print(format_args!($($arg)*));
        $crate::console::vga::print(format_args!("\n"));
    }};
}
