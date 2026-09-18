//! PS/2 keyboard driver (scancode set 1, US layout).
//!
//! ## Why a keyboard driver in milestone 1
//!
//! Because it is the smallest thing that proves the entire interrupt path works
//! end to end: a physical device asserts IRQ1 → the PIC forwards it as vector
//! 0x21 → the IDT dispatches to a Rust handler → the handler reads a port and
//! updates state → the main loop observes the state change. Nothing short of a
//! real device interrupt demonstrates that chain, and a kernel whose interrupt
//! path is untested is a kernel that will fail at the worst possible moment.
//!
//! It also makes M1 **interactive** rather than a print-and-hang demo, which is
//! what `make test` asserts on: the harness drives QEMU's QMP `send-key`
//! interface and checks that the typed characters come back out on serial.
//!
//! ## What this is not
//!
//! This is not a complete input subsystem. There is no keymap configuration, no
//! Unicode composition, no key repeat, no accessibility hooks (sticky keys,
//! slow keys — see `docs/APPS.md` §23), and no USB or Bluetooth. Those arrive
//! with `orin-inputd` in M7/M9. The design boundary is already drawn for it:
//! this driver produces `KeyEvent`s and nothing else, and whatever consumes
//! them in M9 will not know or care whether they came from PS/2, USB HID or an
//! on-screen keyboard.

#![allow(dead_code)]

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

/// PS/2 data port: scancodes in, commands to the *device* out.
const PORT_DATA: u16 = 0x60;
/// PS/2 status port (read) / controller command port (write).
const PORT_STATUS: u16 = 0x64;

// Status register bits (port 0x64, read).
const ST_OUT_BUFFER_FULL: u8 = 1 << 0;
const ST_IN_BUFFER_FULL: u8 = 1 << 1;
/// 1 = the byte in the output buffer came from a *device*, 0 = from the
/// controller in response to a command. Misreading this is the classic PS/2
/// bug: you consume a command response as if it were a keystroke.
const ST_FROM_DEVICE: u8 = 1 << 5;
/// Controller timeout: a command did not complete.
const ST_TIMEOUT: u8 = 1 << 6;
/// Parity error on the last byte received.
const ST_PARITY: u8 = 1 << 7;

// Controller commands (port 0x64, write).
const CMD_READ_COMMAND_BYTE: u8 = 0x20;
const CMD_WRITE_COMMAND_BYTE: u8 = 0x60;
const CMD_SELF_TEST: u8 = 0xAA;
const CMD_TEST_PORT_1: u8 = 0xAB;
const CMD_DISABLE_PORT_1: u8 = 0xAD;
const CMD_ENABLE_PORT_1: u8 = 0xAE;

// Device commands (port 0x60, write).
const DEV_SET_SCANCODE_SET: u8 = 0xF0;
const DEV_RESET: u8 = 0xFF;

/// Command byte bits we care about.
const CB_IRQ1_ENABLE: u8 = 1 << 0;
const CB_TRANSLATE: u8 = 1 << 6;

/// Iteration bound for status polling. At ~1 GHz this is well over a
/// millisecond, which is longer than the PS/2 controller's documented command
/// latency. A controller that exceeds it is absent or wedged, and the driver
/// must report that rather than spin forever inside an interrupt handler.
const POLL_LIMIT: u32 = 2_000_000;

// ===========================================================================
//  Scancode ring buffer
// ===========================================================================
//
// Lock-free single-producer/single-consumer: the IRQ1 handler is the only
// producer, the main loop is the only consumer. That pairing is what makes the
// atomics correct without a lock — and it is why this must not be extended to
// multi-producer without replacing it. M4's SMP bring-up is the point where
// this invariant needs revisiting (one input device per core is not a thing).

const RING_CAP: usize = 256;

static RING: [AtomicByte; RING_CAP] = [const { AtomicByte::new(0) }; RING_CAP];
static RING_HEAD: AtomicUsize = AtomicUsize::new(0); // written by ISR
static RING_TAIL: AtomicUsize = AtomicUsize::new(0); // written by consumer

/// A byte cell. `AtomicU8` would do; this exists so the ring can be declared
/// as a `const`-initialised array on stable Rust.
struct AtomicByte(core::sync::atomic::AtomicU8);

impl AtomicByte {
    const fn new(v: u8) -> Self {
        Self(core::sync::atomic::AtomicU8::new(v))
    }
}

/// Count of bytes dropped because the ring was full.
///
/// Exposed rather than hidden: a rising count means the consumer is not keeping
/// up, which is real information about a real bug, and silently discarding
/// keystrokes would make that bug invisible.
static DROPPED: AtomicUsize = AtomicUsize::new(0);

fn ring_push(b: u8) {
    let head = RING_HEAD.load(Ordering::Relaxed);
    let next = (head + 1) % RING_CAP;
    if next == RING_TAIL.load(Ordering::Acquire) {
        // Full. Drop the newest byte rather than the oldest: with a keyboard,
        // losing the key you are pressing now is more noticeable than losing
        // one from a burst that was already too fast to render.
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    RING[head].0.store(b, Ordering::Relaxed);
    // Release: the byte must be visible before the head advances, or the
    // consumer can read a stale cell.
    RING_HEAD.store(next, Ordering::Release);
}

fn ring_pop() -> Option<u8> {
    let tail = RING_TAIL.load(Ordering::Relaxed);
    if tail == RING_HEAD.load(Ordering::Acquire) {
        return None;
    }
    let b = RING[tail].0.load(Ordering::Relaxed);
    RING_TAIL.store((tail + 1) % RING_CAP, Ordering::Release);
    Some(b)
}

/// Bytes pending, for diagnostics.
pub fn pending() -> usize {
    let head = RING_HEAD.load(Ordering::Acquire);
    let tail = RING_TAIL.load(Ordering::Acquire);
    if head >= tail {
        head - tail
    } else {
        RING_CAP - tail + head
    }
}

pub fn dropped_count() -> usize {
    DROPPED.load(Ordering::Relaxed)
}

// ===========================================================================
//  Key model
// ===========================================================================

/// A decoded key event, produced by the translator and consumed by whoever
/// needs input (the M1 echo loop, `orin-inputd` from M9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub code: KeyCode,
    pub pressed: bool,
    /// True while this event's key is a modifier being held.
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    /// Monotonic tick at which the scancode arrived, so consumers can implement
    /// repeat and chord detection without a clock of their own.
    pub tick: u64,
    /// The character this key produces under the current modifier state, if it
    /// produces one. `None` for modifiers, function keys, arrows, etc.
    pub ch: Option<char>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum KeyCode {
    None = 0,
    Escape,
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
    Backquote,
    Num1, Num2, Num3, Num4, Num5, Num6, Num7, Num8, Num9, Num0,
    Minus, Equal, Backspace,
    Tab,
    Q, W, E, R, T, Y, U, I, O, P,
    BracketLeft, BracketRight, Backslash,
    CapsLock,
    A, S, D, F, G, H, J, K, L,
    Z, X, C, V, B, N, M,
    Semicolon, Quote, Enter,
    ShiftLeft, ShiftRight,
    ControlLeft, ControlRight,
    AltLeft, AltRight,
    SuperLeft, SuperRight,
    Space,
    PrintScreen, ScrollLock, Pause,
    Insert, Home, PageUp,
    Delete, End, PageDown,
    ArrowUp, ArrowLeft, ArrowDown, ArrowRight,
    NumLock,
    KeypadSlash, KeypadAsterisk, KeypadMinus, KeypadPlus, KeypadEnter, KeypadDot,
    Keypad0, Keypad1, Keypad2, Keypad3, Keypad4,
    Keypad5, Keypad6, Keypad7, Keypad8, Keypad9,
    Comma_, Period_, Slash_,
    /// A scancode we received but do not know. Kept as a value rather than
    /// dropped, because silently discarding input hides broken keymaps.
    Unknown(u8),
}

/// Scancode set 1 (XT) base table, indexed by the low 7 bits of the make code.
///
/// This is the layout the controller gives us with translation enabled. It is a
/// fixed hardware convention, not a user keymap: user keymaps (M9) map
/// `KeyCode` → characters, so a French or Dvorak user rebinds at that layer and
/// this table never changes.
const SCANCODE_BASE: [KeyCode; 0x60] = [
    KeyCode::None,          KeyCode::Escape,        KeyCode::Num1,          KeyCode::Num2,
    KeyCode::Num3,          KeyCode::Num4,          KeyCode::Num5,          KeyCode::Num6,
    KeyCode::Num7,          KeyCode::Num8,          KeyCode::Num9,          KeyCode::Num0,
    KeyCode::Minus,         KeyCode::Equal,         KeyCode::Backspace,     KeyCode::Tab,
    KeyCode::Q,             KeyCode::W,             KeyCode::E,             KeyCode::R,
    KeyCode::T,             KeyCode::Y,             KeyCode::U,             KeyCode::I,
    KeyCode::O,             KeyCode::P,             KeyCode::BracketLeft,   KeyCode::BracketRight,
    KeyCode::Enter,         KeyCode::ControlLeft,   KeyCode::A,             KeyCode::S,
    KeyCode::D,             KeyCode::F,             KeyCode::G,             KeyCode::H,
    KeyCode::J,             KeyCode::K,             KeyCode::L,             KeyCode::Semicolon,
    KeyCode::Quote,         KeyCode::Backquote,     KeyCode::ShiftLeft,     KeyCode::Backslash,
    KeyCode::Z,             KeyCode::X,             KeyCode::C,             KeyCode::V,
    KeyCode::B,             KeyCode::N,             KeyCode::M,             KeyCode::Comma_,
    KeyCode::Period_,       KeyCode::Slash_,        KeyCode::ShiftRight,    KeyCode::KeypadAsterisk,
    KeyCode::AltLeft,       KeyCode::Space,         KeyCode::CapsLock,      KeyCode::F1,
    KeyCode::F2,            KeyCode::F3,            KeyCode::F4,            KeyCode::F5,
    KeyCode::F6,            KeyCode::F7,            KeyCode::F8,            KeyCode::F9,
    KeyCode::F10,           KeyCode::NumLock,       KeyCode::ScrollLock,    KeyCode::Keypad7,
    KeyCode::Keypad8,       KeyCode::Keypad9,       KeyCode::KeypadMinus,   KeyCode::Keypad4,
    KeyCode::Keypad5,       KeyCode::Keypad6,       KeyCode::KeypadPlus,    KeyCode::Keypad1,
    KeyCode::Keypad2,       KeyCode::Keypad3,       KeyCode::Keypad0,       KeyCode::KeypadDot,
    // 0x54: SysRq on some layouts; 0x55-0x56 unused; 0x57/0x58 are F11/F12 on
    // the 101-key set-1 mapping (0x57 = F11, 0x58 = F12); 0x59-0x5F unused.
    // Every unused slot is explicitly None rather than left to padding, so the
    // array length is checked by the compiler against the index bound in
    // `translate` (which asserts idx < 0x60 before indexing).
    KeyCode::None,          KeyCode::None,          KeyCode::None,          KeyCode::F11,
    KeyCode::F12,           KeyCode::None,          KeyCode::None,          KeyCode::None,
    KeyCode::None,          KeyCode::None,          KeyCode::None,          KeyCode::None,
];
// Compile-time confirmation that the table covers the whole 7-bit scancode
// space `translate` indexes into. Without this, a truncated table would index
// out of bounds on a keypress — at interrupt time, with no useful diagnostic.
const _: () = assert!(SCANCODE_BASE.len() == 0x60);

/// E0-prefixed (extended) scancodes, set 1, as an explicit `(code, key)` map.
///
/// Written as a map rather than a positional 96-entry array on purpose: a
/// positional table for extended codes is nearly impossible to review, and
/// an off-by-one in it silently remaps arrow keys. Every entry here states its
/// scancode in hex next to the key it means, so a reviewer can check it against
/// the PS/2 documentation line by line, and `tools/hostcheck` can assert the
/// whole table round-trips.
///
/// **PrintScreen caveat:** the real sequence is `E0 2A E0 37` on press and
/// `E0 B7 E0 AA` on release. The `2A`/`AA` halves are a *synthetic left-Shift*
/// the keyboard injects for AT compatibility. They are deliberately absent from
/// this table AND explicitly swallowed in [`translate`], so pressing
/// PrintScreen does not also toggle shift state.
const SCANCODE_E0_MAP: &[(u8, KeyCode)] = &[
    (0x1C, KeyCode::KeypadEnter),
    (0x1D, KeyCode::ControlRight),
    (0x35, KeyCode::KeypadSlash),
    (0x37, KeyCode::PrintScreen),
    (0x38, KeyCode::AltRight),
    (0x47, KeyCode::Home),
    (0x48, KeyCode::ArrowUp),
    (0x49, KeyCode::PageUp),
    (0x4B, KeyCode::ArrowLeft),
    (0x4D, KeyCode::ArrowRight),
    (0x4F, KeyCode::End),
    (0x50, KeyCode::ArrowDown),
    (0x51, KeyCode::PageDown),
    (0x52, KeyCode::Insert),
    (0x53, KeyCode::Delete),
    (0x5B, KeyCode::SuperLeft),
    (0x5C, KeyCode::SuperRight),
];

/// Look up an extended scancode by its low 7 bits.
fn lookup_e0(idx: u8) -> KeyCode {
    // Linear scan over 17 entries. This runs on a keypress, not in a hot loop,
    // so clarity beats a lookup table that has to be kept in sync by hand.
    for (code, key) in SCANCODE_E0_MAP {
        if *code == idx {
            return *key;
        }
    }
    KeyCode::None
}

/// US-QWERTY unshifted characters, indexed by `KeyCode` where it produces one.
fn char_for(code: KeyCode, shift: bool) -> Option<char> {
    let (lo, hi): (char, char) = match code {
        KeyCode::Backquote => ('`', '~'),
        KeyCode::Num1 => ('1', '!'),
        KeyCode::Num2 => ('2', '@'),
        KeyCode::Num3 => ('3', '#'),
        KeyCode::Num4 => ('4', '$'),
        KeyCode::Num5 => ('5', '%'),
        KeyCode::Num6 => ('6', '^'),
        KeyCode::Num7 => ('7', '&'),
        KeyCode::Num8 => ('8', '*'),
        KeyCode::Num9 => ('9', '('),
        KeyCode::Num0 => ('0', ')'),
        KeyCode::Minus => ('-', '_'),
        KeyCode::Equal => ('=', '+'),
        KeyCode::Q => ('q', 'Q'),
        KeyCode::W => ('w', 'W'),
        KeyCode::E => ('e', 'E'),
        KeyCode::R => ('r', 'R'),
        KeyCode::T => ('t', 'T'),
        KeyCode::Y => ('y', 'Y'),
        KeyCode::U => ('u', 'U'),
        KeyCode::I => ('i', 'I'),
        KeyCode::O => ('o', 'O'),
        KeyCode::P => ('p', 'P'),
        KeyCode::BracketLeft => ('[', '{'),
        KeyCode::BracketRight => (']', '}'),
        KeyCode::Backslash => ('\\', '|'),
        KeyCode::A => ('a', 'A'),
        KeyCode::S => ('s', 'S'),
        KeyCode::D => ('d', 'D'),
        KeyCode::F => ('f', 'F'),
        KeyCode::G => ('g', 'G'),
        KeyCode::H => ('h', 'H'),
        KeyCode::J => ('j', 'J'),
        KeyCode::K => ('k', 'K'),
        KeyCode::L => ('l', 'L'),
        KeyCode::Semicolon => (';', ':'),
        KeyCode::Quote => ('\'', '"'),
        KeyCode::Z => ('z', 'Z'),
        KeyCode::X => ('x', 'X'),
        KeyCode::C => ('c', 'C'),
        KeyCode::V => ('v', 'V'),
        KeyCode::B => ('b', 'B'),
        KeyCode::N => ('n', 'N'),
        KeyCode::M => ('m', 'M'),
        KeyCode::Comma_ => (',', '<'),
        KeyCode::Period_ => ('.', '>'),
        KeyCode::Slash_ => ('/', '?'),
        KeyCode::Space => (' ', ' '),
        KeyCode::Enter => ('\n', '\n'),
        KeyCode::Tab => ('\t', '\t'),
        KeyCode::Backspace => ('\u{8}', '\u{8}'),
        KeyCode::Escape => ('\u{1b}', '\u{1b}'),
        KeyCode::Keypad0 => ('0', '0'),
        KeyCode::Keypad1 => ('1', '1'),
        KeyCode::Keypad2 => ('2', '2'),
        KeyCode::Keypad3 => ('3', '3'),
        KeyCode::Keypad4 => ('4', '4'),
        KeyCode::Keypad5 => ('5', '5'),
        KeyCode::Keypad6 => ('6', '6'),
        KeyCode::Keypad7 => ('7', '7'),
        KeyCode::Keypad8 => ('8', '8'),
        KeyCode::Keypad9 => ('9', '9'),
        KeyCode::KeypadDot => ('.', '.'),
        KeyCode::KeypadSlash => ('/', '/'),
        KeyCode::KeypadAsterisk => ('*', '*'),
        KeyCode::KeypadMinus => ('-', '-'),
        KeyCode::KeypadPlus => ('+', '+'),
        KeyCode::KeypadEnter => ('\n', '\n'),
        _ => return None,
    };
    Some(if shift { hi } else { lo })
}

// ===========================================================================
//  Driver state
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// Not yet probed.
    Unknown,
    /// Self-test passed; a keyboard may or may not be attached to port 1.
    Controller,
    /// Self-test passed and port 1 test passed.
    Keyboard,
    /// Controller self-test failed. Common on machines with no PS/2 at all
    /// (many UEFI-only boards). The driver disables itself and says so.
    Absent,
}

struct State {
    presence: Presence,
    shift: bool,
    ctrl: bool,
    alt: bool,
    /// True when the last byte was 0xE0, so the next byte is an extended code.
    extended: bool,
    /// True when the last byte was 0xE0 0x2A (Pause's odd 4-byte sequence).
    pause_prefix: bool,
    events: u64,
    unknown_scancodes: u64,
    /// Saved controller command byte, so `shutdown()` can restore it.
    command_byte: u8,
}

static STATE: Mutex<State> = Mutex::new(State {
    presence: Presence::Unknown,
    shift: false,
    ctrl: false,
    alt: false,
    extended: false,
    pause_prefix: false,
    events: 0,
    unknown_scancodes: 0,
    command_byte: 0,
});

pub fn presence() -> Presence {
    STATE.lock().presence
}

pub fn event_count() -> u64 {
    STATE.lock().events
}

/// Reset modifier and escape-prefix state.
///
/// Exists for the self-test, which must decode a known byte sequence from a
/// known state. Deliberately does NOT reset the event counter: the counter is
/// diagnostic and resetting it would hide real activity.
pub fn reset_state_for_test() {
    let mut st = STATE.lock();
    st.shift = false;
    st.ctrl = false;
    st.alt = false;
    st.extended = false;
    st.pause_prefix = false;
}

/// Decode one scancode byte directly, without going through the ring buffer.
///
/// This is the function the self-test and `tools/hostcheck` drive: it isolates
/// the decoder from the interrupt path so a translation bug and a delivery bug
/// cannot be confused with each other.
pub fn translate_raw(byte: u8) -> Option<KeyEvent> {
    translate(byte)
}

/// Decode one raw scancode byte, updating modifier state.
///
/// Pure apart from the modifier state in `STATE`, which is why
/// `tools/hostcheck` can drive it with byte sequences and assert the exact
/// `KeyEvent`s that come out — including the awkward ones (Pause's four-byte
/// sequence, E0-prefixed arrows, release codes).
pub fn translate(byte: u8) -> Option<KeyEvent> {
    let mut st = STATE.lock();
    let tick = crate::interrupts::pit::ticks_since_boot();

    // 0xE0 introduces an extended scancode. 0xE1 introduces Pause's sequence.
    if byte == 0xE0 {
        st.extended = true;
        return None;
    }
    if byte == 0xE1 {
        st.pause_prefix = true;
        return None;
    }
    if st.pause_prefix {
        // Pause/Break sends E1 1D 45 E1 9D C5. There is no release code.
        // Consume the whole sequence and emit one event on the third byte.
        st.pause_prefix = false;
        return Some(KeyEvent {
            code: KeyCode::Pause,
            pressed: true,
            shift: st.shift,
            ctrl: st.ctrl,
            alt: st.alt,
            tick,
            ch: None,
        });
    }

    let released = byte & 0x80 != 0;
    let idx = (byte & 0x7F) as usize;
    if idx >= 0x60 {
        st.unknown_scancodes += 1;
        return None;
    }
    let code = if st.extended {
        st.extended = false;
        // Swallow the synthetic Shift that PrintScreen injects (see the note on
        // SCANCODE_E0_MAP). Delivering it would corrupt shift state.
        if idx == 0x2A || idx == 0xAA {
            return None;
        }
        let c = lookup_e0(idx as u8);
        if c == KeyCode::None {
            st.unknown_scancodes += 1;
            crate::ktrace!("keyboard: unknown extended scancode E0 {:02X}", idx);
            return Some(KeyEvent {
                code: KeyCode::Unknown(idx as u8 | 0x80),
                pressed: !released,
                shift: st.shift,
                ctrl: st.ctrl,
                alt: st.alt,
                tick,
                ch: None,
            });
        }
        c
    } else {
        SCANCODE_BASE[idx]
    };

    // Update modifier state on both press and release, BEFORE computing the
    // character, so that Shift+a yields 'A' and releasing Shift does not
    // retroactively change what was already delivered.
    match code {
        KeyCode::ShiftLeft | KeyCode::ShiftRight => st.shift = !released,
        KeyCode::ControlLeft | KeyCode::ControlRight => st.ctrl = !released,
        KeyCode::AltLeft | KeyCode::AltRight => st.alt = !released,
        _ => {}
    }

    if code == KeyCode::None {
        return None;
    }

    st.events += 1;
    Some(KeyEvent {
        code,
        pressed: !released,
        shift: st.shift,
        ctrl: st.ctrl,
        alt: st.alt,
        tick,
        ch: char_for(code, st.shift),
    })
}

// ===========================================================================
//  Hardware access
// ===========================================================================

/// Wait for the controller's input buffer to drain, so we can write a command.
fn wait_input_empty() -> bool {
    // SAFETY: reading the PS/2 status port has no side effects.
    unsafe {
        let mut status: Port<u8> = Port::new(PORT_STATUS);
        for _ in 0..POLL_LIMIT {
            if status.read() & ST_IN_BUFFER_FULL == 0 {
                return true;
            }
            crate::cpu::pause();
        }
    }
    false
}

/// Wait for the controller to produce a byte.
fn wait_output_full() -> bool {
    // SAFETY: as above.
    unsafe {
        let mut status: Port<u8> = Port::new(PORT_STATUS);
        for _ in 0..POLL_LIMIT {
            if status.read() & ST_OUT_BUFFER_FULL != 0 {
                return true;
            }
            crate::cpu::pause();
        }
    }
    false
}

/// Send a command to the *controller* (port 0x64).
fn controller_cmd(cmd: u8) -> bool {
    // SAFETY: PS/2 controller command port. `wait_input_empty` guards against
    // overwriting a command the controller has not consumed.
    unsafe {
        if !wait_input_empty() {
            return false;
        }
        let mut p: Port<u8> = Port::new(PORT_STATUS);
        p.write(cmd);
    }
    true
}

/// Send a command to the *device* on port 1 (port 0x60).
fn device_cmd(cmd: u8) -> bool {
    // SAFETY: as above, data port.
    unsafe {
        if !wait_input_empty() {
            return false;
        }
        let mut p: Port<u8> = Port::new(PORT_DATA);
        p.write(cmd);
    }
    true
}

/// Read one response byte from the controller or device.
fn read_response() -> Option<u8> {
    // SAFETY: reads the data port after confirming a byte is available.
    unsafe {
        if !wait_output_full() {
            return None;
        }
        let mut p: Port<u8> = Port::new(PORT_DATA);
        Some(p.read())
    }
}

/// Flush any stale bytes sitting in the output buffer.
///
/// Required before probing: on real hardware the BIOS often leaves an ACK or a
/// keystroke buffered, and consuming that as the self-test response produces a
/// wrong verdict. QEMU starts clean, which is exactly why this bug would not
/// show up in the emulator.
fn flush_output() {
    // SAFETY: read-only status/data ports.
    unsafe {
        let mut status: Port<u8> = Port::new(PORT_STATUS);
        let mut data: Port<u8> = Port::new(PORT_DATA);
        let mut guard = 0u32;
        while status.read() & ST_OUT_BUFFER_FULL != 0 {
            let _ = data.read();
            guard += 1;
            if guard > 32 {
                break;
            }
        }
    }
}

/// Probe and initialise the PS/2 controller and keyboard.
///
/// Never panics on absent hardware. A machine with no PS/2 controller is a
/// perfectly normal modern machine; reporting `Presence::Absent` and continuing
/// is correct, whereas panicking would make Orin unbootable on exactly the
/// hardware that most needs to work.
pub fn init() -> Presence {
    flush_output();

    // -- controller self-test (0xAA) -----------------------------------
    if !controller_cmd(CMD_SELF_TEST) {
        crate::kwarn!("keyboard: PS/2 controller did not accept the self-test command; treating as absent");
        STATE.lock().presence = Presence::Absent;
        return Presence::Absent;
    }
    // Small settle delay: the controller self-test resets it, and issuing the
    // next command immediately is the documented way to get a spurious failure.
    crate::interrupts::pit::spin_delay_us(100);
    match read_response() {
        Some(0x55) => {}
        Some(other) => {
            crate::kwarn!(
                "keyboard: PS/2 controller self-test returned {:#04x}, expected 0x55. \
                 No PS/2 controller on this machine (normal for UEFI-only boards); \
                 the M1 interactive echo will be unavailable. USB HID arrives in M7.",
                other
            );
            STATE.lock().presence = Presence::Absent;
            return Presence::Absent;
        }
        None => {
            crate::kwarn!("keyboard: PS/2 controller self-test produced no response; treating as absent");
            STATE.lock().presence = Presence::Absent;
            return Presence::Absent;
        }
    }
    crate::kinfo!("keyboard: PS/2 controller self-test passed (0x55)");

    // -- disable port 1 while configuring ------------------------------
    // Configuring with the port enabled can deliver a partial byte stream that
    // desynchronises the scancode decoder.
    let _ = controller_cmd(CMD_DISABLE_PORT_1);
    flush_output();

    // -- read the command byte -----------------------------------------
    let _ = controller_cmd(CMD_READ_COMMAND_BYTE);
    let cmd_byte = read_response().unwrap_or(0);

    // -- port 1 interface test (0xAB) ----------------------------------
    let _ = controller_cmd(CMD_TEST_PORT_1);
    let port_ok = match read_response() {
        Some(0x00) => true,
        Some(other) => {
            crate::kwarn!(
                "keyboard: PS/2 port 1 interface test returned {:#04x}, expected 0x00. \
                 Controller present but no keyboard on port 1.",
                other
            );
            false
        }
        None => false,
    };

    // -- write back the command byte with IRQ1 enabled -----------------
    // Keep whatever the firmware set for the other bits (translation, port 2),
    // so a controller that also drives a PS/2 mouse keeps working.
    let new_byte = (cmd_byte | CB_IRQ1_ENABLE) & !CB_TRANSLATE;
    // Translation is deliberately OFF: with translation the controller
    // silently converts set-2 scancodes to set-1, and on some controllers the
    // conversion is lossy for extended codes. We ask the device for set 1
    // explicitly below, so no conversion is needed. If the device refuses,
    // `SCANCODE_BASE` would be wrong and the self-test's echo check catches it.
    let _ = controller_cmd(CMD_WRITE_COMMAND_BYTE);
    let _ = device_cmd_write(new_byte);

    // -- ask the device for scancode set 1 ------------------------------
    // Not all keyboards accept this; many hard-wire set 2 and rely on the
    // controller's translation. Send it, read the ACK, and record what we got
    // rather than assuming.
    let _ = device_cmd(DEV_SET_SCANCODE_SET);
    let ack = read_response();
    let _ = device_cmd_write(0x01); // 01 = set 1
    let ack2 = read_response();
    if ack == Some(0xFA) && ack2 == Some(0xFA) {
        crate::kinfo!("keyboard: device accepted scancode set 1");
    } else {
        crate::kwarn!(
            "keyboard: device did not ACK scancode set 1 (got {:?}, {:?}). \
             It is probably hard-wired to set 2 with controller translation; \
             re-enabling translation.",
            ack, ack2
        );
        let _ = controller_cmd(CMD_WRITE_COMMAND_BYTE);
        let _ = device_cmd_write(new_byte | CB_TRANSLATE);
    }

    // -- re-enable port 1 ------------------------------------------------
    let _ = controller_cmd(CMD_ENABLE_PORT_1);
    flush_output();

    let presence = if port_ok { Presence::Keyboard } else { Presence::Controller };
    {
        let mut st = STATE.lock();
        st.presence = presence;
        st.command_byte = cmd_byte;
    }
    crate::kinfo!("keyboard: PS/2 initialised, presence = {:?}", presence);
    presence
}

/// Helper: `device_cmd` but named for the write-command-byte flow, where the
/// payload goes to port 0x60 after a 0x60 command to port 0x64.
fn device_cmd_write(b: u8) -> bool {
    device_cmd(b)
}

/// IRQ1 handler. Called from `interrupts/idt.rs`.
///
/// Does the minimum possible work: read the scancode and push it. Decoding
/// happens in the consumer, because decoding takes a lock and a lock inside an
/// interrupt handler that the lock's holder can be preempted by is a deadlock.
pub fn interrupt_handler() {
    // SAFETY: read status to confirm the byte came from a device, then read the
    // data port exactly once. Reading it twice loses a scancode; not reading it
    // leaves the controller stuck asserting IRQ1 forever.
    unsafe {
        let mut status: Port<u8> = Port::new(PORT_STATUS);
        let s = status.read();

        if s & ST_TIMEOUT != 0 {
            crate::kerror!("keyboard: controller timeout flag set; flushing");
            flush_output();
            return;
        }
        if s & ST_PARITY != 0 {
            // A parity error means the byte is corrupt. Discard it: injecting a
            // corrupt scancode produces a wrong key, which is worse than a
            // dropped one.
            crate::kwarn!("keyboard: parity error on received byte; discarded");
            let mut data: Port<u8> = Port::new(PORT_DATA);
            let _ = data.read();
            return;
        }
        if s & ST_OUT_BUFFER_FULL == 0 {
            // Spurious IRQ1. Nothing to read. Do NOT touch the data port:
            // reading it when the buffer is empty returns garbage on some
            // controllers.
            crate::ktrace!("keyboard: IRQ1 with empty output buffer; spurious");
            return;
        }

        let mut data: Port<u8> = Port::new(PORT_DATA);
        let byte = data.read();

        if s & ST_FROM_DEVICE == 0 {
            // This byte is a controller command response, not a keystroke. It
            // should not arrive asynchronously in M1 (we do all command
            // exchanges with IRQ1 masked during init), so log it.
            crate::kdebug!("keyboard: async controller response {:#04x} discarded", byte);
            return;
        }
        ring_push(byte);
    }
}

/// Decode the next pending key event, if any.
pub fn poll() -> Option<KeyEvent> {
    let byte = ring_pop()?;
    translate(byte)
}

/// Drain and decode every pending scancode into `out`, up to its capacity.
///
/// Returns the number of events written. Used by the M1 echo loop so a burst of
/// keystrokes (which is exactly what QMP `send-key` produces) is handled in one
/// pass instead of one per iteration of the main loop.
pub fn drain(out: &mut [KeyEvent]) -> usize {
    let mut n = 0;
    while n < out.len() {
        match poll() {
            Some(ev) => {
                out[n] = ev;
                n += 1;
            }
            None => break,
        }
    }
    n
}

/// Restore the controller to its pre-init state. Called on a clean shutdown
/// (M9) so kexec into another kernel does not inherit our configuration.
pub fn shutdown() {
    let st = STATE.lock();
    if st.presence == Presence::Absent {
        return;
    }
    let saved = st.command_byte;
    drop(st);
    let _ = controller_cmd(CMD_WRITE_COMMAND_BYTE);
    let _ = device_cmd_write(saved);
    crate::kinfo!("keyboard: controller command byte restored to {:#04x}", saved);
}
