//! Structured kernel logging.
//!
//! Orin's rule (`docs/ARCHITECTURE.md` §12): **logs are structured records,
//! not strings.** Every kernel message carries a severity, a subsystem, a
//! monotonic timestamp and the source location. The same record renders to
//! serial and to VGA, so a human sees readable text while the test harness and
//! `orin logs` can parse fields.
//!
//! Wire format — stable ABI, parsed by `tools/qemu-run.sh` and `tests/`:
//!
//! ```text
//! ORIN|I|      0.000|console::log    |kernel/src/console/log.rs:88|message text
//!      ^       ^      ^                ^                            ^
//!      level    ms     subsystem        source location               message
//! ```
//!
//! Level letters come from [`crate::log::Level`]: `T D I W E C P`.
//!
//! ## Redaction
//!
//! [`secret`] marks a value that must never reach a log. It renders as
//! `[REDACTED:<len>]` on every console. This is the only sanctioned way to
//! pass a credential-adjacent value through a formatting path; see
//! `docs/SECURITY.md` §9.

use core::fmt;
use spin::Mutex;

use super::{serial, vga};

pub use crate::log::{Level, Target};

/// Runtime log configuration.
pub struct LogConfig {
    pub level: Level,
    pub target: Target,
    /// Include the source-location field. On in debug builds, off in release:
    /// at 115200 baud, location strings are the difference between a usable
    /// trace log and a kernel that spends its life in the UART driver.
    pub show_location: bool,
    /// Records emitted, for `sys.log_stats` over OKI.
    pub emitted: u64,
    /// Records dropped by the level filter.
    pub filtered: u64,
}

pub static CONFIG: Mutex<LogConfig> = Mutex::new(LogConfig {
    level: Level::Info,
    target: Target::Both,
    show_location: cfg!(debug_assertions),
    emitted: 0,
    filtered: 0,
});

/// Apply `orin.log=` / `orin.console=` boot parameters.
pub fn configure(level: Option<Level>, target: Option<Target>) {
    let mut c = CONFIG.lock();
    if let Some(l) = level {
        c.level = l;
    }
    if let Some(t) = target {
        c.target = t;
    }
}

/// Monotonic microseconds since boot.
///
/// Before the PIT is initialised (init steps 1–13) this returns 0, which is the
/// honest answer: no clock exists yet. A real clocksource with TSC calibration
/// lands in M4; until then the PIT tick *is* the clock, and the boot log says so.
///
/// Integer, not `f64`: see the note on `pit::ACTUAL_TICK_HZ_NUM`. An f64 here
/// would pull `__divdf3` into the link and the kernel would not build.
fn now_micros() -> u64 {
    crate::interrupts::pit::micros_since_boot()
}

/// Emit one record.
pub fn log(level: Level, subsys: &str, location: &str, args: fmt::Arguments) {
    let (target, show_loc) = {
        let mut c = CONFIG.lock();
        if level < c.level && level != Level::Panic {
            c.filtered += 1;
            return;
        }
        c.emitted += 1;
        (c.target, c.show_location)
    };

    let ts = now_micros();

    if matches!(target, Target::Serial | Target::Both) {
        write_serial(level, ts, subsys, location, show_loc, args);
    }
    if matches!(target, Target::Vga | Target::Both) {
        write_vga(level, subsys, args);
    }
}

fn write_serial(
    level: Level,
    ts: u64,
    subsys: &str,
    location: &str,
    show_loc: bool,
    args: fmt::Arguments,
) {
    use fmt::Write;
    let mut s = serial::COM1_PORT.lock();
    // The `ORIN|` prefix is what the harness greps for. Field order is stable;
    // do not reorder without bumping the documented log format.
    // Timestamp renders as `<seconds>.<microseconds>`, 11 characters wide, which
    // is the same field width the previous `{:>11.3}` f64 format produced — so
    // the documented log format in docs/ARCHITECTURE.md is unchanged and
    // tests/test_boot.sh's parser does not care that the clock is integer now.
    let _ = write!(
        s,
        "ORIN|{}|{:>6}.{:06}|{:18}",
        level.letter(),
        ts / 1_000_000,
        ts % 1_000_000,
        shorten(subsys)
    );
    if show_loc {
        let _ = write!(s, "|{}", location);
    }
    let _ = write!(s, "|{}\r\n", args);
}

fn write_vga(level: Level, subsys: &str, args: fmt::Arguments) {
    use fmt::Write;
    let mut w = vga::WRITER.lock();
    // Colour by severity so a scrolling boot log is readable at a glance.
    let (fg, bg) = match level {
        Level::Trace | Level::Debug => (vga::Color::DarkGray, vga::Color::Black),
        Level::Info => (vga::Color::LightGray, vga::Color::Black),
        Level::Warn => (vga::Color::Yellow, vga::Color::Black),
        Level::Error | Level::Critical | Level::Panic => (vga::Color::White, vga::Color::Red),
    };
    w.set_color(fg, bg);
    let _ = write!(w, "[{}] ", shorten(subsys));
    let _ = write!(w, "{}", args);
    w.set_color(vga::Color::LightGray, vga::Color::Black);
    let _ = write!(w, "\n");
}

/// `module_path!()` yields `orin_kernel::memory::pmm`; the log field wants
/// `memory::pmm`. Trimming the crate prefix keeps the fixed-width column
/// readable instead of showing the same crate name on every line.
fn shorten(subsys: &str) -> &str {
    match subsys.split_once("::") {
        Some((crate_name, rest)) if crate_name == "orin_kernel" => rest,
        _ => subsys,
    }
}

/// The level currently in effect, for the boot banner.
pub fn effective_level() -> Level {
    CONFIG.lock().level
}

/// `(emitted, filtered)` for the boot banner and `sys.log_stats`.
pub fn stats() -> (u64, u64) {
    let c = CONFIG.lock();
    (c.emitted, c.filtered)
}

/// A value that must never be written to a log.
pub struct Secret<'a>(pub &'a [u8]);

impl fmt::Debug for Secret<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[REDACTED:{}]", self.0.len())
    }
}

impl fmt::Display for Secret<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

pub fn secret(bytes: &[u8]) -> Secret<'_> {
    Secret(bytes)
}

/// The logging macros. Source location is captured at the call site, which is
/// what makes a kernel log actionable without a debugger attached.
#[macro_export]
macro_rules! klog {
    ($level:expr, $subsys:expr, $($arg:tt)*) => {{
        $crate::console::log::log(
            $level,
            $subsys,
            concat!(file!(), ":", line!()),
            format_args!($($arg)*),
        );
    }};
}

#[macro_export]
macro_rules! ktrace {
    ($($arg:tt)*) => { $crate::klog!($crate::log::Level::Trace, module_path!(), $($arg)*) };
}
#[macro_export]
macro_rules! kdebug {
    ($($arg:tt)*) => { $crate::klog!($crate::log::Level::Debug, module_path!(), $($arg)*) };
}
#[macro_export]
macro_rules! kinfo {
    ($($arg:tt)*) => { $crate::klog!($crate::log::Level::Info, module_path!(), $($arg)*) };
}
#[macro_export]
macro_rules! kwarn {
    ($($arg:tt)*) => { $crate::klog!($crate::log::Level::Warn, module_path!(), $($arg)*) };
}
#[macro_export]
macro_rules! kerror {
    ($($arg:tt)*) => { $crate::klog!($crate::log::Level::Error, module_path!(), $($arg)*) };
}
#[macro_export]
macro_rules! kcrit {
    ($($arg:tt)*) => { $crate::klog!($crate::log::Level::Critical, module_path!(), $($arg)*) };
}
