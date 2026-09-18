//! Kernel log levels and console targets.
//!
//! These live outside `console/` on purpose: the boot-parameter parser and the
//! panic handler both need them, and neither should depend on a console module
//! (the panic handler in particular runs when consoles may be broken).

use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Critical = 5,
    /// Panics. Always emitted regardless of the configured filter.
    Panic = 6,
}

impl Level {
    pub const fn letter(self) -> char {
        match self {
            Level::Trace => 'T',
            Level::Debug => 'D',
            Level::Info => 'I',
            Level::Warn => 'W',
            Level::Error => 'E',
            Level::Critical => 'C',
            Level::Panic => 'P',
        }
    }

    pub fn parse(s: &str) -> Option<Level> {
        match s {
            "trace" => Some(Level::Trace),
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" => Some(Level::Warn),
            "error" => Some(Level::Error),
            "critical" | "crit" => Some(Level::Critical),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    Serial,
    Vga,
    Both,
}

impl Target {
    pub fn parse(s: &str) -> Option<Target> {
        match s {
            "serial" => Some(Target::Serial),
            "vga" => Some(Target::Vga),
            "both" => Some(Target::Both),
            _ => None,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // `Formatter::write_char`/`write_str` are not part of the public API;
        // `write!` is the portable way to emit into a formatter.
        write!(f, "{}", self.letter())
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Target::Serial => "serial",
            Target::Vga => "vga",
            Target::Both => "both",
        };
        f.write_str(s)
    }
}
