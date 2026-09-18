//! Orin kernel consoles.
//!
//! Two output devices and one structured log layer on top:
//!
//! - [`serial`] — COM1 16550 UART. **Primary.** Captured by QEMU into
//!   `build/serial.log`, which is how `make test` asserts on boot behaviour.
//! - [`vga`] — 80×25 text mode at `0xB8000`. Early/visual console; replaced by
//!   the framebuffer console in M8.
//! - [`log`] — the structured record layer both consoles render.
//!
//! - [`raw`] — lock-free output for panic and fatal-exception paths only. See
//!   its module docs for why a panic handler must not take a console lock.
//!
//! Ordering constraint: `serial::init()` must run before anything else in the
//! kernel, because it is the only output path that works before the VGA window
//! is known-good and before the heap exists. `raw::set_serial_ok` is set from
//! the same place, so the raw path knows whether the UART is real before any
//! panic can occur.

pub mod log;
pub mod raw;
pub mod serial;
pub mod vga;

pub use log::{secret, Level, Secret, Target};
