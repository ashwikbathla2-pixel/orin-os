//! Orin syscall ABI — **DESIGNED, not implemented.**
//!
//! This module exists in M1 for one reason: to make the boundary between
//! "documented" and "working" impossible to confuse. It contains no dispatch
//! table, no argument marshalling and no implementations. What it contains is
//! the reserved ABI, a compile-time-checked numbering scheme, and a handler
//! that returns `ENOSYS` loudly.
//!
//! Rule 1 of this project is "never fake functionality". A syscall stub that
//! returned plausible-looking values would be the worst possible violation of
//! it, because the caller cannot tell. So every entry point here returns
//! [`Errno::Nosys`] and logs *once* per vector, naming the milestone that will
//! implement it.
//!
//! See `docs/SYSCALL.md` for the full ABI specification.

#![allow(dead_code)]

/// Syscall numbers, allocated in blocks by subsystem.
///
/// **Numbers are never reused and never renumbered.** A released Orin binary
/// contains the number it was compiled against; renumbering would silently
/// change what every existing binary does. The block structure exists so a new
/// subsystem can be added without contending for numbers with an existing one.
pub mod nr {
    // 0 is deliberately unused: a syscall table initialised to zeroes should
    // not silently mean "the first real syscall".
    pub const BLOCK_PROCESS: core::ops::Range<u16> = 1..32;
    pub const BLOCK_MEMORY: core::ops::Range<u16> = 32..64;
    pub const BLOCK_IO: core::ops::Range<u16> = 64..128;
    pub const BLOCK_IPC: core::ops::Range<u16> = 128..192;
    pub const BLOCK_CAPABILITY: core::ops::Range<u16> = 192..224;
    pub const BLOCK_TIME: core::ops::Range<u16> = 224..240;
    pub const BLOCK_SYSTEM: core::ops::Range<u16> = 240..256;

    // --- Reserved names, M5+ ------------------------------------------
    /// Terminate the calling thread. M4.
    pub const EXIT: u16 = 1;
    /// Terminate the calling process. M4.
    pub const EXIT_GROUP: u16 = 2;
    /// Wait for a child event. M4.
    pub const WAIT: u16 = 3;
    /// Sleep until a deadline or an event. M4.
    pub const SLEEP: u16 = 4;
    /// Create a process from a signed executable image. M4.
    pub const SPAWN: u16 = 5;
    /// Yield the remaining time slice. M4.
    pub const YIELD: u16 = 6;

    /// Map memory into the caller's address space. M4.
    pub const MMAP: u16 = 32;
    /// Unmap. M4.
    pub const MUNMAP: u16 = 33;
    /// Change permissions on an existing mapping. M4.
    pub const MPROTECT: u16 = 34;

    /// Open a file through the OFS layer. M6.
    pub const OPEN: u16 = 64;
    pub const READ: u16 = 65;
    pub const WRITE: u16 = 66;
    pub const CLOSE: u16 = 67;
    pub const SEEK: u16 = 68;
    pub const STAT: u16 = 69;

    /// Send a message to an IPC endpoint. M9.
    pub const IPC_SEND: u16 = 128;
    /// Receive, blocking or with a deadline. M9.
    pub const IPC_RECEIVE: u16 = 129;
    /// Create an endpoint pair. M9.
    pub const IPC_CONNECT: u16 = 130;

    /// Grant a capability to another process. M9.
    pub const CAP_GRANT: u16 = 192;
    /// Revoke. M9.
    pub const CAP_REVOKE: u16 = 193;
    /// Query the caller's own grant set. M9.
    pub const CAP_QUERY: u16 = 194;
    /// High-level OKI call — the normal path for user-space system access. M9.
    pub const OKI_CALL: u16 = 195;

    /// Monotonic clock. M4.
    pub const CLOCK_GET: u16 = 224;

    /// Reboot / power off, capability-gated. M9.
    pub const SYSTEM_POWER: u16 = 240;
}

/// Orin error codes.
///
/// Named to match POSIX where a POSIX equivalent exists, so `lxabi`
/// (docs/ARCHITECTURE.md §8) can translate without a table, and so a developer
/// recognises them. Orin-specific codes are at the end and marked as such.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Errno {
    Ok = 0,
    /// Operation not permitted: the capability check failed.
    Perm = 1,
    NoEnt = 2,
    IO = 5,
    BadF = 9,
    Again = 11,
    NoMem = 12,
    Access = 13,
    Busy = 16,
    Exist = 17,
    NoDev = 19,
    NotDir = 20,
    IsDir = 21,
    Inval = 22,
    FileTooBig = 27,
    NoSpace = 28,
    Pipe = 32,
    /// Orin-specific: the caller's grant set lacks the required capability.
    /// Distinguished from `Perm` so an app can tell "you may never do this"
    /// from "ask the user for permission" — which is what makes an actionable
    /// permission prompt possible.
    CapMissing = 4000,
    /// Orin-specific: the package signature did not verify.
    SignatureBad = 4001,
    /// Orin-specific: the requested OKI call does not exist in this ABI version.
    CallUnknown = 4002,
    /// Orin-specific: not implemented in this milestone.
    Nosys = 4003,
}

impl Errno {
    /// The kernel returns negated error codes in `rax`, in the range
    /// `-1..=-4095`, matching the convention every Unix-like ABI uses. Orin's
    /// own codes are `>= 4000`, which is why the range must extend past 255.
    pub fn as_negated(self) -> i64 {
        -(self as i32 as i64)
    }

    pub fn name(self) -> &'static str {
        match self {
            Errno::Ok => "OK",
            Errno::Perm => "EPERM",
            Errno::NoEnt => "ENOENT",
            Errno::IO => "EIO",
            Errno::BadF => "EBADF",
            Errno::Again => "EAGAIN",
            Errno::NoMem => "ENOMEM",
            Errno::Access => "EACCES",
            Errno::Busy => "EBUSY",
            Errno::Exist => "EEXIST",
            Errno::NoDev => "ENODEV",
            Errno::NotDir => "ENOTDIR",
            Errno::IsDir => "EISDIR",
            Errno::Inval => "EINVAL",
            Errno::FileTooBig => "EFBIG",
            Errno::NoSpace => "ENOSPC",
            Errno::Pipe => "EPIPE",
            Errno::CapMissing => "ORIN_ECAPMISSING",
            Errno::SignatureBad => "ORIN_ESIGBAD",
            Errno::CallUnknown => "ORIN_ECALLUNKNOWN",
            Errno::Nosys => "ORIN_ENOSYS",
        }
    }
}

/// Register convention for the Orin syscall ABI.
///
/// `syscall`/`sysret` is used rather than `int 0x80`: it is roughly an order of
/// magnitude cheaper, and on x86_64 it is the only sane transport. ARM64 will
/// use `svc` with **the same numbers**, because the numbering is a semantic ABI
/// and the transport is an architecture detail.
///
/// ```text
///   rax  syscall number
///   rdi  arg0        rsi  arg1        rdx  arg2
///   r10  arg3        r8   arg4        r9   arg5
///   ─────────────────────────────────────────────
///   rax  return value, or -(errno) in 1..=4095
///   rcx  clobbered by syscall (holds return RIP)  — NOT an argument register
///   r11  clobbered by syscall (holds RFLAGS)      — NOT an argument register
/// ```
///
/// The argument registers follow SysV order (`rdi rsi rdx rcx r8 r9`) **except**
/// that `r10` replaces `rcx`, because the `syscall` instruction itself overwrites
/// `rcx` with the return address. This is the same substitution Linux makes, and
/// for the same reason: it lets LLVM's standard calling convention be used for
/// everything except the register holding arg3.
pub mod abi {
    /// Register holding the syscall number.
    pub const REG_NR: &str = "rax";
    /// Registers holding arguments, in order.
    pub const REG_ARGS: [&str; 6] = ["rdi", "rsi", "rdx", "r10", "r8", "r9"];
    /// Registers the `syscall` instruction clobbers; user code must not expect
    /// these preserved and the kernel must not read them as arguments.
    pub const REG_CLOBBERED: [&str; 2] = ["rcx", "r11"];
    /// Vector used by the `int` fallback path (see `interrupts::idt`).
    pub const INT_VECTOR: u8 = 0x40;
    /// MSR that holds the `syscall` entry RIP. Programmed in M5.
    pub const MSR_LSTAR: u32 = crate::cpu::msr::addr::LSTAR;
    /// MSR holding segment selectors for `syscall`/`sysret`. Programmed in M5.
    /// Value derived from `interrupts::gdt::{KERNEL_CODE_SEL, USER_DATA_SEL}` —
    /// see the note on descriptor order in `gdt.rs`, which is why that order is
    /// ABI rather than style.
    pub const MSR_STAR: u32 = crate::cpu::msr::addr::STAR;
    /// RFLAGS bits cleared on `syscall`. M5 sets IF (bit 9) at minimum so a
    /// syscall entry cannot be interrupted before the kernel stack is switched.
    pub const MSR_SFMASK: u32 = crate::cpu::msr::addr::SFMASK;
}

/// Compute the `IA32_STAR` value for our GDT layout.
///
/// `sysret` derives its selectors as: `CS = STAR[63:48] + 16`,
/// `SS = STAR[63:48] + 8`. So `STAR[63:48]` must be `user_cs - 16`, and
/// `STAR[47:32]` must be the kernel CS. Getting this wrong produces a
/// `sysret` to an invalid selector, which is a #GP on the way *back to user
/// mode* — one of the more confusing failures in kernel development, hence a
/// function that states the arithmetic explicitly and is unit-tested on the
/// host.
pub const fn star_value(kernel_cs: u16, user_cs_after_sysret: u16) -> u64 {
    let sysret_base = user_cs_after_sysret.wrapping_sub(16) as u64;
    ((sysret_base & 0xFFFF) << 48) | ((kernel_cs as u64 & 0xFFFF) << 32)
}

/// Dispatch a syscall. **Not implemented until M5.**
///
/// Returns `Errno::Nosys` for every number, including numbers that are reserved
/// and documented above. This function is called by both the `int 0x40` handler
/// and (from M5) the `syscall` entry stub, so that there is exactly one place
/// that decides what a syscall does.
pub fn dispatch(nr: u16, _args: [u64; 6]) -> Result<u64, Errno> {
    // Logged once per number by the caller (`idt::on_syscall_vector`) rather
    // than here, because this will be called at very high frequency once real
    // syscalls exist and a log call in the hot path is a performance bug.
    let _ = nr;
    Err(Errno::Nosys)
}

/// Human-readable name for a syscall number, for `orin strace` in M15.
pub fn name_of(nr: u16) -> &'static str {
    match nr {
        nr::EXIT => "exit",
        nr::EXIT_GROUP => "exit_group",
        nr::WAIT => "wait",
        nr::SLEEP => "sleep",
        nr::SPAWN => "spawn",
        nr::YIELD => "yield",
        nr::MMAP => "mmap",
        nr::MUNMAP => "munmap",
        nr::MPROTECT => "mprotect",
        nr::OPEN => "open",
        nr::READ => "read",
        nr::WRITE => "write",
        nr::CLOSE => "close",
        nr::SEEK => "seek",
        nr::STAT => "stat",
        nr::IPC_SEND => "ipc_send",
        nr::IPC_RECEIVE => "ipc_receive",
        nr::IPC_CONNECT => "ipc_connect",
        nr::CAP_GRANT => "cap_grant",
        nr::CAP_REVOKE => "cap_revoke",
        nr::CAP_QUERY => "cap_query",
        nr::OKI_CALL => "oki_call",
        nr::CLOCK_GET => "clock_get",
        nr::SYSTEM_POWER => "system_power",
        _ => "<unknown>",
    }
}
