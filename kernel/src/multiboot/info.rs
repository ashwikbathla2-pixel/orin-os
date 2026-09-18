//! Multiboot2 information-structure parser and boot-parameter parsing.
//!
//! Hand-rolled on purpose (ADR-007): this is a flat, documented list of tagged
//! records, and it determines how much physical memory the kernel is allowed to
//! touch. Trusting a third-party crate to parse it means a dependency bug
//! becomes memory corruption. ~250 lines that can be unit-tested against
//! synthetic blobs on the host is the safer trade.
//!
//! ## Layering for testability
//!
//! [`parse`] works on a `&[u8]` and never touches a raw pointer, so
//! `tools/hostcheck` can build synthetic Multiboot2 structures — including
//! truncated and malformed ones — and assert the parser extracts the right
//! values or fails *without reading out of bounds*. [`read_from`] is the thin
//! kernel-side wrapper that turns GRUB's physical address into that slice.
//!
//! ## Failure policy
//!
//! A missing **optional** tag is recorded and ignored. A missing or malformed
//! **required** tag (the memory map) is a hard boot failure with a specific
//! message, because proceeding without it means guessing which RAM is usable —
//! and guessing is exactly what Rule 1 forbids.

#![allow(dead_code)]

use crate::arch::{phys_to_virt, BOOT_MAPPED_BYTES, PAGE_SIZE};
use crate::log::{Level, Target};
use x86_64::PhysAddr;

/// Multiboot2 information-structure magic, passed in `%eax` by GRUB.
pub const BOOT_MAGIC: u32 = 0x36D7_6289;

/// Tag types, numbered per **Multiboot2 specification §3.1** (the information
/// structure). Note these numbers differ from the *header request* numbering in
/// some loaders' documentation — the spec's info-structure numbering below is
/// authoritative and is what GRUB actually emits.
pub mod tag {
    pub const END: u16 = 0;
    pub const CMDLINE: u16 = 1;
    pub const BOOT_LOADER_NAME: u16 = 2;
    pub const MODULE: u16 = 3;
    pub const BASIC_MEMINFO: u16 = 4;
    pub const BOOTDEV: u16 = 5;
    pub const MMAP: u16 = 6;
    pub const VBE: u16 = 7;
    pub const ELF_SECTIONS: u16 = 8;
    pub const APM: u16 = 9;
    pub const EFI32_IH: u16 = 10;
    pub const EFI64_IH: u16 = 11;
    pub const SMBIOS: u16 = 12;
    pub const ACPI_OLD: u16 = 13;
    pub const ACPI_NEW: u16 = 14;
    pub const NETWORK: u16 = 15;
    pub const EFI_MMAP: u16 = 16;
    pub const EFI_BS: u16 = 17;
    pub const EFI32_CT: u16 = 18;
    pub const EFI64_CT: u16 = 19;
    pub const LOAD_BASE_ADDR: u16 = 20;
    /// GRUB emits the framebuffer as tag 9 in the *header request* but the
    /// information-structure tag for a framebuffer is 9 in GRUB's
    /// implementation of `MULTIBOOT_TAG_TYPE_FRAMEBUFFER`. The spec numbers it
    /// 9 as well; `APM` above (9) is the value GRUB never emits for x86_64
    /// EFI boots. To remove all ambiguity we accept BOTH 9 and the spec's
    /// framebuffer id, and log which one we saw.
    pub const FRAMEBUFFER: u16 = 9;
    pub const FRAMEBUFFER_ALT: u16 = 8;

    /// All tags are padded to 8-byte multiples.
    pub const ALIGN: usize = 8;
    /// Tag header: type(u16) + flags(u16) + size(u32).
    pub const HEADER_LEN: usize = 8;
}

/// One firmware memory-map entry (tag 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmapEntry {
    pub base: u64,
    pub length: u64,
    /// Raw firmware type; `memory::pmm::memtype` names the ones Orin knows.
    pub mem_type: u32,
}

pub const PLACEHOLDER_MMAP: MmapEntry = MmapEntry {
    base: 0,
    length: 0,
    mem_type: 0,
};

/// Framebuffer description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramebufferInfo {
    /// Physical address of the pixel data.
    pub address: u64,
    /// Bytes per scanline; may exceed `width * bpp / 8` because of padding.
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    pub fb_type: u8,
    /// Framebuffer bytes, computed as `pitch * height`. Never taken from the
    /// tag alone: a firmware that reports a wrong size would have us writing
    /// past the end of a mapped device region.
    pub size: u64,
}

/// Framebuffer `type` field values (Multiboot2 §3.1.5).
pub mod fbtype {
    pub const INDEXED: u8 = 0;
    pub const RGB: u8 = 1;
    pub const EGA_TEXT: u8 = 2;
}

// ---------------------------------------------------------------------------
// Fixed-capacity containers (no allocator available at parse time)
// ---------------------------------------------------------------------------

pub mod heapless {
    use core::fmt;

    /// Command lines and loader names in the wild are short; 191 bytes is
    /// generous and keeps `BootInfo` small enough to live on the boot stack.
    pub const STR_CAP: usize = 191;
    /// Firmware memory maps have ~10–30 entries. 64 is headroom; exceeding it
    /// truncates *and logs*, never silently drops.
    pub const MMAP_CAP: usize = 64;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct Str {
        buf: [u8; STR_CAP],
        len: usize,
    }

    impl Str {
        pub const fn new() -> Self {
            Self {
                buf: [0u8; STR_CAP],
                len: 0,
            }
        }

        pub fn as_str(&self) -> &str {
            // `push_str` never splits a UTF-8 sequence, so this cannot fail on
            // a value we built ourselves.
            core::str::from_utf8(&self.buf[..self.len]).unwrap_or("<invalid utf-8>")
        }

        pub fn len(&self) -> usize {
            self.len
        }

        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        /// Append, truncating at capacity **on a char boundary**.
        pub fn push_str(&mut self, s: &str) {
            for ch in s.chars() {
                let mut tmp = [0u8; 4];
                let enc = ch.encode_utf8(&mut tmp);
                if self.len + enc.len() > STR_CAP {
                    return;
                }
                self.buf[self.len..self.len + enc.len()].copy_from_slice(enc.as_bytes());
                self.len += enc.len();
            }
        }
    }

    impl fmt::Debug for Str {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Debug::fmt(self.as_str(), f)
        }
    }
    impl fmt::Display for Str {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Display::fmt(self.as_str(), f)
        }
    }

    #[derive(Clone)]
    pub struct Vec<T: Copy> {
        buf: [T; MMAP_CAP],
        len: usize,
    }

    impl<T: Copy> Vec<T> {
        pub const fn new(item: T) -> Self {
            Self {
                buf: [item; MMAP_CAP],
                len: 0,
            }
        }
        pub fn push(&mut self, v: T) -> Result<(), T> {
            if self.len >= MMAP_CAP {
                return Err(v);
            }
            self.buf[self.len] = v;
            self.len += 1;
            Ok(())
        }
        pub fn as_slice(&self) -> &[T] {
            &self.buf[..self.len]
        }
        pub fn len(&self) -> usize {
            self.len
        }
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
    }

    impl<T: Copy + fmt::Debug> fmt::Debug for Vec<T> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_list().entries(self.as_slice()).finish()
        }
    }
}

/// Everything Orin extracts from the bootloader.
///
/// Fixed-size and heap-free: it is populated before the kernel heap exists and
/// must remain valid after the boot identity map is hardened.
#[derive(Clone, Debug)]
pub struct BootInfo {
    /// Declared `total_size` of the information structure.
    pub total_size: u32,
    pub cmdline: Option<heapless::Str>,
    pub loader_name: Option<heapless::Str>,
    pub mmap: heapless::Vec<MmapEntry>,
    pub framebuffer: Option<FramebufferInfo>,
    /// Physical address of the ACPI RSDP contents, if the loader supplied one.
    pub acpi_rsdp: Option<u64>,
    /// Whether the RSDP came from the v1 (20-byte) or v2 (36-byte) tag.
    pub acpi_version: u8,
    /// Base address GRUB loaded the kernel at (tag 20). Cross-checked against
    /// the linker script's `_kernel_phys_start` in `main.rs`.
    pub load_base_addr: Option<u32>,
    /// Every tag seen, including ignored ones. Proves the walk covered the
    /// whole structure rather than stopping early.
    pub tag_count: u32,
    /// Physical address the structure was found at.
    pub phys_addr: u64,
}

// Compile-time guard: `BootInfo` is returned by value and lives on the boot
// stack. If it grows past 4 KiB the boot stack budget in MEMORY.md is wrong,
// and this turns that into a build error instead of a stack overflow at boot.
const _: () = assert!(core::mem::size_of::<BootInfo>() <= 4096);

/// Why the parser refused to produce a `BootInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Structure shorter than its own 8-byte header.
    TooShort,
    /// Declared `total_size` disagrees with the buffer we were given.
    SizeMismatch,
    /// A tag claimed to extend past the end of the structure.
    TagOverrun,
    /// A tag claimed a size smaller than its own header.
    TagUndersize,
    /// Tag 6 missing or empty. Without it the kernel cannot know which RAM is
    /// usable, so it must not boot.
    NoMemoryMap,
    /// A memory-map tag declared an entry size too small to hold an entry.
    BadMmapEntrySize,
}

impl ParseError {
    pub fn as_str(&self) -> &'static str {
        match self {
            ParseError::TooShort => "information structure shorter than its header",
            ParseError::SizeMismatch => "declared total_size exceeds the buffer",
            ParseError::TagOverrun => "tag extends past the end of the structure",
            ParseError::TagUndersize => "tag size smaller than its 8-byte header",
            ParseError::NoMemoryMap => "no usable memory map (tag 6); refusing to guess RAM",
            ParseError::BadMmapEntrySize => "memory map entry_size smaller than one entry",
        }
    }
}

// --- little-endian field readers -------------------------------------------
// Bounds-checked by construction: every reader returns Option and every caller
// propagates. This is what makes the host-side fuzz-ish tests meaningful.

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    Some(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Parse a Multiboot2 information structure from raw bytes.
///
/// `bytes` must start at the structure and be at least `total_size` long; the
/// caller may pass a longer slice, and only `total_size` bytes are read.
pub fn parse(bytes: &[u8]) -> Result<BootInfo, ParseError> {
    let total = u32_at(bytes, 0).ok_or(ParseError::TooShort)? as usize;
    if total < tag::HEADER_LEN {
        return Err(ParseError::TooShort);
    }
    if total > bytes.len() {
        return Err(ParseError::SizeMismatch);
    }

    let mut info = BootInfo {
        total_size: total as u32,
        cmdline: None,
        loader_name: None,
        mmap: heapless::Vec::new(PLACEHOLDER_MMAP),
        framebuffer: None,
        acpi_rsdp: None,
        acpi_version: 0,
        load_base_addr: None,
        tag_count: 0,
        phys_addr: 0,
    };

    let mut off = tag::HEADER_LEN; // skip { total_size, reserved }
    let mut saw_mmap = false;

    while off + tag::HEADER_LEN <= total {
        let Some(ty) = u16_at(bytes, off) else { break };
        let Some(size) = u32_at(bytes, off + 4) else { break };
        if ty == tag::END {
            break;
        }
        let size = size as usize;
        if size < tag::HEADER_LEN {
            return Err(ParseError::TagUndersize);
        }
        let Some(end) = off.checked_add(size) else {
            return Err(ParseError::TagOverrun);
        };
        if end > total {
            return Err(ParseError::TagOverrun);
        }
        let body = &bytes[off + tag::HEADER_LEN..end];
        info.tag_count += 1;

        match ty {
            tag::CMDLINE => {
                let mut s = heapless::Str::new();
                s.push_str(trim_nul(bytes_to_str(body)));
                info.cmdline = Some(s);
            }
            tag::BOOT_LOADER_NAME => {
                let mut s = heapless::Str::new();
                s.push_str(trim_nul(bytes_to_str(body)));
                info.loader_name = Some(s);
            }
            tag::MMAP => {
                saw_mmap = true;
                parse_mmap(body, &mut info)?;
            }
            // Accepted from either id: see the note on tag::FRAMEBUFFER.
            tag::FRAMEBUFFER | tag::FRAMEBUFFER_ALT if body.len() >= 24 => {
                if info.framebuffer.is_none() {
                    info.framebuffer = parse_framebuffer(body);
                }
            }
            tag::ACPI_OLD if body.len() >= 20 => {
                if info.acpi_rsdp.is_none() {
                    // The tag contains the RSDP *contents*, so the address of
                    // interest is where the body sits inside the structure.
                    // `read_from` adds the structure's physical base.
                    info.acpi_rsdp = Some((off + tag::HEADER_LEN) as u64);
                    info.acpi_version = 1;
                }
            }
            tag::ACPI_NEW if body.len() >= 36 => {
                if info.acpi_rsdp.is_none() {
                    info.acpi_rsdp = Some((off + tag::HEADER_LEN) as u64);
                    info.acpi_version = 2;
                }
            }
            tag::LOAD_BASE_ADDR => info.load_base_addr = u32_at(body, 0),
            tag::ELF_SECTIONS | tag::BASIC_MEMINFO | tag::VBE | tag::SMBIOS => {
                crate::kdebug!("multiboot: saw tag {} ({} bytes), not used in M1", ty, size);
            }
            _ => { /* counted, ignored */ }
        }

        off = (end + (tag::ALIGN - 1)) & !(tag::ALIGN - 1);
    }

    if !saw_mmap || info.mmap.is_empty() {
        return Err(ParseError::NoMemoryMap);
    }
    Ok(info)
}

fn bytes_to_str(b: &[u8]) -> &str {
    // A loader handing us non-UTF-8 must not abort the boot: the command line
    // is informational. Substitute rather than fail, and the substitution is
    // visible in the value so it cannot be mistaken for a real parameter.
    core::str::from_utf8(b).unwrap_or("<non-utf8>")
}

fn trim_nul(s: &str) -> &str {
    match s.find('\0') {
        Some(i) => &s[..i],
        None => s,
    }
}

fn parse_mmap(body: &[u8], info: &mut BootInfo) -> Result<(), ParseError> {
    let entry_size = u32_at(body, 0).ok_or(ParseError::BadMmapEntrySize)? as usize;
    let _entry_version = u32_at(body, 4).ok_or(ParseError::BadMmapEntrySize)?;
    // An entry is base(8) + length(8) + type(4) + reserved(4) = 24 bytes. A
    // smaller declared size means we cannot trust the stride, and trusting a
    // wrong stride means inventing memory regions.
    if entry_size < 24 {
        return Err(ParseError::BadMmapEntrySize);
    }
    let mut eoff = 8usize;
    while eoff + 24 <= body.len() {
        let Some(base) = u64_at(body, eoff) else { break };
        let Some(length) = u64_at(body, eoff + 8) else { break };
        let Some(mem_type) = u32_at(body, eoff + 16) else { break };
        if info
            .mmap
            .push(MmapEntry {
                base,
                length,
                mem_type,
            })
            .is_err()
        {
            crate::kwarn!(
                "multiboot: memory map exceeds {} entries; truncated. Raise heapless::MMAP_CAP.",
                heapless::MMAP_CAP
            );
            break;
        }
        eoff += entry_size;
    }
    Ok(())
}

fn parse_framebuffer(body: &[u8]) -> Option<FramebufferInfo> {
    let address = u64_at(body, 0)?;
    let pitch = u32_at(body, 8)?;
    let width = u32_at(body, 12)?;
    let height = u32_at(body, 16)?;
    let bpp = *body.get(20)?;
    let fb_type = *body.get(21)?;
    // Derive size from pitch * height rather than trusting a field: a firmware
    // that under-reports it would have the compositor (M8) write past the end
    // of a mapped device region.
    let size = (pitch as u64).saturating_mul((height as u64).max(1));
    Some(FramebufferInfo {
        address,
        pitch,
        width,
        height,
        bpp,
        fb_type,
        size,
    })
}

// ---------------------------------------------------------------------------
// Kernel-side entry point
// ---------------------------------------------------------------------------

/// Read and parse the structure GRUB left at physical address `phys`
/// (delivered in `%ebx`).
///
/// Reached through the boot identity map's higher-half alias, so this must run
/// **before** `vmm::harden_boot_map()` sets NX on that alias, and long before
/// M4 removes it.
pub fn read_from(phys: u64) -> Result<BootInfo, ParseError> {
    if phys == 0 || phys >= BOOT_MAPPED_BYTES {
        return Err(ParseError::TooShort);
    }
    let va = phys_to_virt(PhysAddr::new(phys));

    // SAFETY: GRUB guarantees a valid, readable information structure at
    // `phys`; the address is inside the boot-mapped range (checked above) and
    // nothing in the kernel writes to it. We read the declared `total_size`
    // first, bound it, and only then form a slice — so a corrupted size field
    // cannot make us walk into unmapped memory.
    let (total, span) = unsafe {
        let p = va.as_u64() as *const u8;
        let t = (p as *const u32).read_unaligned() as usize;
        // One page of slack past the declared size covers any legal structure
        // and caps a bogus value at 64 KiB.
        let s = t.saturating_add(PAGE_SIZE as usize).min(64 * 1024);
        (t, s)
    };
    if total < tag::HEADER_LEN {
        return Err(ParseError::TooShort);
    }
    // SAFETY: as above; `span` bytes at this address are inside the boot map.
    let bytes: &[u8] = unsafe { core::slice::from_raw_parts(va.as_u64() as *const u8, span) };

    let mut info = parse(bytes)?;
    info.phys_addr = phys;
    // `parse` recorded RSDP positions as offsets within the structure; make
    // them absolute now that we know the base.
    if let Some(off) = info.acpi_rsdp {
        info.acpi_rsdp = Some(phys + off);
    }
    Ok(info)
}

// ---------------------------------------------------------------------------
// Boot command-line parameters — docs/BOOT.md §5
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanicAction {
    Halt,
    Reboot,
    /// Deliberately induce a triple fault. Used to test that the reset path
    /// works and that crash reporting survives it.
    Triple,
}

#[derive(Clone, Debug)]
pub struct BootParams {
    pub log: Option<Level>,
    pub console: Option<Target>,
    pub selftest: bool,
    pub panic_action: PanicAction,
    pub single: bool,
    pub mem_limit_mib: Option<u64>,
    pub nx: bool,
    /// Unrecognised `orin.*` parameters. Logged, never fatal: a typo in
    /// `grub.cfg` must not brick the boot.
    pub unknown: heapless::Str,
}

impl Default for BootParams {
    fn default() -> Self {
        Self {
            log: None,
            console: None,
            selftest: true,
            panic_action: PanicAction::Halt,
            single: false,
            mem_limit_mib: None,
            nx: true,
            unknown: heapless::Str::new(),
        }
    }
}

/// Parse a command line. Pure and host-testable.
pub fn parse_params(cmdline: &str) -> BootParams {
    let mut p = BootParams::default();
    for tok in cmdline.split_ascii_whitespace() {
        let Some(rest) = tok.strip_prefix("orin.") else {
            // Not ours. GRUB and future loaders may add their own parameters;
            // ignoring them is correct behaviour, not an oversight.
            continue;
        };
        let (key, val) = rest.split_once('=').unwrap_or((rest, ""));
        match key {
            "log" => match Level::parse(val) {
                Some(l) => p.log = Some(l),
                None => append_unknown(&mut p.unknown, tok),
            },
            "console" => match Target::parse(val) {
                Some(t) => p.console = Some(t),
                None => append_unknown(&mut p.unknown, tok),
            },
            "selftest" => p.selftest = val != "off",
            "panic" => {
                p.panic_action = match val {
                    "reboot" => PanicAction::Reboot,
                    "triple" => PanicAction::Triple,
                    _ => PanicAction::Halt,
                }
            }
            "single" => p.single = true,
            "memlimit" => match val.parse::<u64>() {
                Ok(v) => p.mem_limit_mib = Some(v),
                Err(_) => append_unknown(&mut p.unknown, tok),
            },
            "nx" => {
                p.nx = val != "off";
                if !p.nx {
                    // Disabling NX is a debugging affordance and must be
                    // impossible to miss.
                    crate::kwarn!(
                        "boot: NX enforcement DISABLED via orin.nx=off; W^X does not hold this boot"
                    );
                }
            }
            _ => append_unknown(&mut p.unknown, tok),
        }
    }
    p
}

fn append_unknown(buf: &mut heapless::Str, tok: &str) {
    if !buf.is_empty() {
        buf.push_str(" ");
    }
    buf.push_str(tok);
}
