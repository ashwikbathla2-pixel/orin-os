# Orin OS
> **Simple underneath. Powerful on top.**

A modern, secure, Rust-powered operating system built from the ground up.
x86_64 first, ARM64 later.

---

## Repository map

```text
orin/
├── boot/                 Boot protocol payloads: GRUB config, multiboot2 header policy
├── kernel/               orink — the kernel (no_std Rust crate)
├── arch/x86_64/          Arch-specific: boot asm, linker script, entry stubs
│   └── (aarch64/)        reserved
├── drivers/              Out-of-tree driver crates (M7+)
├── memory/               Memory subsystem design + host-testable allocator logic
├── filesystem/           OFS (Orin File System) abstraction layer (M6)
├── process/              Process/thread model, IPC (M4)
├── syscall/              Syscall ABI definition + codegen (M5)
├── networking/           Network stack (M11)
├── userspace/            User-space programs; `incubator/` holds the app-ecosystem prototype
├── services/             orin-init, orin-logind, orin-networkd, orin-audiod, … (M9)
├── desktop/              Orin Desktop environment (M12)
├── graphics/             Compositor + Orin UI Toolkit (M8)
├── shell/                orinsh (M10)
├── sdk/                  Orin SDK: `orin build|run|test|iso|package` (M15)
├── packages/             orinpkg + package manifest format (M13)
├── browser/              Orin Browser (M16)
├── ai/                   Orin AI subsystem (M17)
├── tools/                Build/test harnesses; `hostcheck` = host-side unit tests
├── schemas/              Machine-readable formats: package manifest, OKI protocol, output
├── docs/                 Architecture & subsystem documentation (authoritative)
├── tests/                End-to-end / boot tests (QEMU-driven)
└── build/                Build artefacts (gitignored)
```

## Documentation

Start here, in this order:

| Doc | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | **Read first.** Whole-system architecture, layering, OKI, ABI compatibility strategy |
| [`docs/BOOT.md`](docs/BOOT.md) | Firmware → GRUB → multiboot2 → long mode → kernel handoff |
| [`docs/KERNEL.md`](docs/KERNEL.md) | Kernel module map, init sequence, engineering rules |
| [`docs/MEMORY.md`](docs/MEMORY.md) | Physical frames, virtual map, higher-half, kernel heap |
| [`docs/PROCESS.md`](docs/PROCESS.md) | Process/thread model, IPC, scheduling |
| [`docs/SYSCALL.md`](docs/SYSCALL.md) | Syscall ABI, register convention, versioning |
| [`docs/DRIVERS.md`](docs/DRIVERS.md) | Driver framework and priority order |
| [`docs/FILESYSTEM.md`](docs/FILESYSTEM.md) | VFS/OFS abstraction, on-disk format plan |
| [`docs/GRAPHICS.md`](docs/GRAPHICS.md) | Compositor, surfaces, UI toolkit |
| [`docs/NETWORKING.md`](docs/NETWORKING.md) | Stack layering |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Capabilities, sandboxing, signing, threat model |
| [`docs/DESKTOP.md`](docs/DESKTOP.md) | Orin Desktop identity & components |
| [`docs/APPS.md`](docs/APPS.md) | Application & utility ecosystem (the 27-part app spec) |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Toolchain, build, test, how to contribute |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Milestones M0–M18 with acceptance criteria and status |

## Prerequisites

| Tool | Version verified | Purpose |
|---|---|---|
| `rustup` / `rustc` | 1.100.0-nightly (2026-09-17) | Kernel language |
| `qemu-system-x86_64` | 10.0.13 | Emulator / boot testing |
| `nasm` | 2.16.03 | Boot assembly |
| `grub-mkrescue`, `xorriso` | 2.12 / 1.5.6 | ISO generation |
| GNU `ld`, `objcopy` | 2.24 | ELF inspection (linking uses `rust-lld`) |

`rust-toolchain.toml` pins the toolchain; `make deps` checks everything.

## Quickstart

```bash
cd orin
make deps        # verify toolchain
make kernel      # build the kernel ELF
make test-host   # host-side unit tests (allocator, multiboot2 parser, scancodes)
make run         # build ISO + boot in QEMU with a graphical window
make test        # automated QEMU boot test: asserts on captured serial output
make iso         # produce build/orin.iso only
make clean
```

`make run` boots into **Orin Terminal View**: the kernel brings up serial + VGA
text console, the PS/2 keyboard driver, and echoes your typing on screen.
`make test` proves it did so without a human watching — it drives QEMU's QMP
`send-key` interface, then asserts the echoed characters appear on the serial
console.

### What is real vs. placeholder

Orin does not fake functionality. Every subsystem is tagged in
[`docs/ROADMAP.md`](docs/ROADMAP.md) as one of:

- **IMPLEMENTED** — code exists and is exercised by a test.
- **WIRED-STUB** — the interface exists and is called, but the body is a
  documented placeholder. Stubs print `[stub]` at runtime and fail loudly
  rather than silently pretending.
- **DESIGNED** — specification only, no code.

Nothing in this repository silently pretends to work.
