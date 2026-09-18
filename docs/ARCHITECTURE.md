# Orin OS — Architecture

**Status:** authoritative · **Applies to:** all milestones · **Last reviewed:** M1

---

## 1. Design thesis

Orin is built around one sentence:

> **Simple underneath. Powerful on top.**

Concretely that means:

1. **The kernel is small and boring.** It manages CPU, memory, scheduling, IPC
   and device access. It does *not* know about windows, packages, fonts,
   networks-in-userspace, or AI. Everything else is a user-space service.
2. **All power lives above a narrow, versioned interface.** User-space never
   makes a raw syscall for a system-wide operation. It calls **OKI** (the Orin
   Kernel Interface), which is a small RPC surface served by the kernel and
   privileged services, and which enforces capabilities on every call.
3. **Security assumes compromise.** Any application may be fully controlled by
   an attacker at any moment. The design question is never "how do we stop the
   exploit" but "what can the exploited process actually reach".
4. **Don't reinvent what already works.** Orin writes the kernel, the security
   model, the IPC, the compositor, the shell, the package manager, the desktop
   and the integration layer. It *does not* rewrite LibreOffice, PowerShell,
   GStreamer, Poppler, libarchive, LLVM or a browser engine. Those are consumed
   through an ABI compatibility layer. See §8 and [`APPS.md`](APPS.md).

The result: a system whose privileged core is small enough to audit, sitting
under a user-space rich enough to be a daily driver.

---

## 2. Layering

```text
┌───────────────────────────────────────────────────────────────────────────┐
│  Applications                                                             │
│  Orin Files · Terminal · Settings · Monitor · Store · LibreOffice · pwsh  │
│  Orin Browser · Orin AI · third-party packages                            │
├───────────────────────────────────────────────────────────────────────────┤
│  Orin UI Toolkit  (liborinui)      Orin SDK (liborin)   Orin AI Runtime   │
├───────────────────────────────────────────────────────────────────────────┤
│  User-space services                                                      │
│  orin-init  orin-logind  orin-networkd  orin-audiod  orin-displayd        │
│  orin-updated  orin-packaged  orin-notifyd  orin-securityd  orin-indexd   │
│  orin-aid (opt-in)                                                        │
├───────────────────────────────────────────────────────────────────────────┤
│                     OKI  —  Orin Kernel Interface                         │
│        versioned RPC · capability-checked · audit-logged · structured     │
├───────────────────────────────────────────────────────────────────────────┤
│  orink (kernel)                                                           │
│  scheduler · VM/paging · frame allocator · IPC · signals/events ·         │
│  syscall ABI · driver framework · VFS/OFS · net packet path               │
├───────────────────────────────────────────────────────────────────────────┤
│  arch/x86_64 (later arch/aarch64)                                         │
│  boot · GDT/TSS · IDT · APIC · context switch · MSR/port primitives       │
└───────────────────────────────────────────────────────────────────────────┘
```

**The only two chokepoints** are OKI (user→system) and the syscall ABI
(user→kernel). Everything else is a normal function call inside a layer.

---

## 3. Kernel architecture (`orink`)

### 3.1 Monolithic, modular in construction

Orin's kernel is a **single address space** (monolithic) but built from
**independent, trait-bounded modules** that could later be lifted into
privileged user-space services without changing their internal design.

This is a deliberate rejection of the "microkernel vs monolithic" binary:

| | Orin's choice | Reason |
|---|---|---|
| Address space | One (monolithic) | A microkernel's per-operation IPC cost is unacceptable for a desktop OS in 2026 without a decade of tuning. Orin optimises for shipping. |
| Module coupling | Trait objects + no upward dependencies | Every subsystem is behind a trait (`FrameAllocator`, `Console`, `Bus`, `FileSystem`), so a subsystem can be swapped or moved out later. |
| Drivers | Kernel-mode in M7, with a **hard API boundary** so user-space drivers are possible in M18 | See [`DRIVERS.md`](DRIVERS.md) §2. |
| Policy | **Zero policy in the kernel.** No firewall rules, no permission *decisions*, no update logic | Policy lives in `orin-securityd` / `orin-updated`. The kernel only *enforces* decisions handed to it. |

The migration path matters: because modules communicate through traits and
never reach into each other's internals, the day we decide the audio path
should be a user-space service, we move the crate and give it an OKI endpoint.
Nothing else changes.

### 3.2 Module map (M1 state)

```text
kernel/
├── console/    vga.rs  serial.rs  log.rs      text output + structured kernel log
├── cpu/        cpuid.rs  msr.rs                feature detection, MSR access
├── interrupts/ idt.rs  gdt.rs  pic.rs  pit.rs  exception/IRQ dispatch, timers
├── memory/     pmm.rs  vmm.rs  heap.rs         frames, page tables, kernel heap
├── multiboot/  info.rs                         boot-info parsing (hand-rolled)
├── drivers/    keyboard.rs                     PS/2 scancode → key events
└── panic.rs                                    register/stack dump, no unwind
```

Module rules (enforced in review, see [`KERNEL.md`](KERNEL.md) §6):

- No module may `use` a sibling's internals — only its public trait/API.
- No file over ~400 lines. If it grows, split it.
- `unsafe` requires a `// SAFETY:` comment stating the invariant being upheld.
- No global mutable state except through `spin::Mutex` / `spin::Once`, and
  every such global must be listed in `docs/KERNEL.md` §7.

### 3.3 Kernel responsibilities

| Area | M1 | Later |
|---|---|---|
| CPU | Long mode, GDT/TSS, CPUID, single core | SMP bring-up (M4), per-CPU data, C-states |
| Memory | 4-level paging, higher-half, bitmap PMM, kernel heap | Per-process `Vmm`, demand paging, COW, huge-page policy, KASLR (M4/M14) |
| Processes | — (kernel only) | Process/thread objects, scheduler, signals/events (M4) |
| Interrupts | IDT (256 vectors), 8259 PIC remapped, PIT @ 1 kHz | APIC/IOAPIC, MSI/MSI-X (M4/M7) |
| Syscalls | ABI reserved, vector 64 installed, returns `ENOSYS` | Real ABI in M5 |
| Drivers | PS/2 keyboard, VGA text, 16550 serial | Framebuffer, NVMe, PCI, USB, … (M7+) |

### 3.4 What is explicitly *not* in the kernel

File-format parsing (PDF, images, office). Crypto policy. Package management.
Network protocols above IP. Text rendering. Anything that parses
attacker-controlled input from an untrusted source. These are the historical
source of kernel privilege escalations, and Orin refuses to host them.

---

## 4. OKI — the Orin Kernel Interface

OKI is the contract between user-space and the system. It is **not** the
syscall ABI: the syscall ABI (§6) is a low-level transport; OKI is a
high-level, semantically versioned, capability-checked API.

### 4.1 Shape

```jsonc
// Request
{ "v": 3, "call": "proc.signal", "params": { "pid": 4211, "sig": "term" },
  "cap_hint": "cap:proc.signal" }

// Response — always structured, never a text blob
{ "v": 3, "ok": true, "data": { "delivered": true, "pid": 4211 } }
{ "v": 3, "ok": false, "error": { "code": "EPERM",
    "missing_cap": "cap:proc.signal",
    "hint": "requested by orin.files; grant in Settings ▸ Privacy ▸ Permissions" } }
```

### 4.2 Invariants

1. **Every call names its capability.** The broker checks the *caller's* grant
   set before dispatch. A call that needs no capability declares
   `cap:none` explicitly — there is no "unchecked by default".
2. **Every call is audit-logged** unless tagged `EPHEMERAL` (e.g. reading a
   clock). The audit log is append-only and not writable by user-space.
3. **Results are structured.** `orin`, `pwsh` and the GUI render the same
   data; nobody re-parses human-readable text. This is what makes
   `orin ps --json | orinpkg …` and `Get-OrinProcess` compose.
4. **ABI is append-only.** `oki_abi_version` is bumped on any incompatible
   change. Removing or renaming a field is a kernel release event, not a patch.
5. **Errors are actionable.** Every `EPERM` carries the missing capability and
   a human-readable path to grant it.

### 4.3 Capability set (v1)

Grouped; a package manifest requests whole capabilities, never raw syscalls.

```text
cap:none            cap:proc.read       cap:proc.signal     cap:proc.nice
cap:net.read        cap:net.admin       cap:fs.user         cap:fs.all
cap:dev.block       cap:service.read    cap:service.admin   cap:sys.log
cap:sys.admin       cap:keyring         cap:capture         cap:media
cap:input.inject    cap:clipboard       cap:notify          cap:location
```

Ordinary applications get `cap:fs.user` (their own sandbox subtree),
`cap:proc.read`, `cap:net.read`, `cap:media`, `cap:notify` and nothing else.
That baseline is the default, not an opt-in.

### 4.4 Transport

- **Native:** OKI rides the `ipc_send`/`ipc_receive` syscalls over a
  kernel-mediated endpoint. Zero-copy for large payloads via shared,
  capability-scoped memory regions.
- **Compatibility:** the same JSON shape over a local socket, so tools written
  during bring-up (see §8.2) work unmodified against the real kernel.

The reference implementation of the client side, `orinkern`, is already in
[`userspace/incubator/orinkern`](../userspace/incubator/orinkern) with two
back-ends (`native`, `linuxabi`) selected at runtime — that shim is what lets
the whole user-space ecosystem be developed and tested *before* the kernel can
host it. It is marked **WIRED-STUB** until orink serves OKI in M9.

---

## 5. Security model

Full detail in [`SECURITY.md`](SECURITY.md). The architecture-level summary:

| Boundary | Mechanism |
|---|---|
| user ↔ kernel | Ring 3 / Ring 0, `CR0.WP`, supervisor-only page bits, `SMAP`/`SMEP` where present, no user pointer dereference without `copy_*_user` |
| process ↔ process | Separate `Vmm` (M4), no shared memory except explicitly granted IPC regions |
| app ↔ system | **Capabilities**, granted at install from the signed package manifest, revocable at runtime by the user |
| app ↔ hardware | Only through services. No app talks to a device directly. |
| app ↔ other apps' data | Per-app sandbox subtree under `/home/<user>/Orin/<app-id>/`; `cap:fs.all` is a visible, logged grant |
| code ↔ execution | Packages are signed; the loader refuses unsigned or badly-signed executables in enforcing mode; W^X on all mappings |
| secrets | `orin-securityd` keyring; `cap:keyring`; never written to logs, never in environment variables by default |

**Threat model in one line:** assume every app process is already owned;
make the blast radius a capability set the user explicitly approved.

Two consequences that shape the whole design:

- The kernel contains **no parsers for untrusted formats** (§3.4).
- `orin-securityd` holds policy; the kernel holds enforcement. If securityd is
  compromised it can *grant*, but it cannot *bypass* page tables or
  capability checks — those are in orink.

---

## 6. Syscall strategy

Detailed in [`SYSCALL.md`](SYSCALL.md). Headline decisions:

- **Transport:** `syscall`/`sysret` (MSR `LSTAR`), not `int 0x80`. Faster, and
  it's the only sane choice on x86_64; ARM64 will use `svc` with the same
  numbering.
- **Convention:** number in `rax`; up to 6 args in `rdi rsi rdx r10 r8 r9`
  (matching the SysV register order so C/LLVM codegen is natural, with `r10`
  instead of `rcx` because `syscall` clobbers `rcx`). Return in `rax`;
  `-1..-4095` are negated `errno`-style codes.
- **Numbers are allocated in blocks** by subsystem, never reused, never
  renumbered. Reserved blocks are published in `syscall/abi.toml`.
- **Orin-native, not Linux-cloned.** `open/read/write/close/mmap` exist
  because they are genuinely the right primitives, but Orin adds
  `ipc_send`/`ipc_receive`/`cap_grant`/`oki_call` and does **not** implement
  the Linux-specific long tail (`clone`'s flag soup, `personality`,
  `/proc` semantics). Linux binaries get Linux semantics through §8, not by
  polluting the native ABI.
- **M1 state:** vector 64 is installed and returns `ENOSYS`. The ABI is
  documented and reserved, not implemented. This is a **DESIGNED** item with a
  **WIRED-STUB** handler — the stub logs loudly and never pretends.

---

## 7. Process & thread model (M4)

Summary; detail in [`PROCESS.md`](PROCESS.md).

- **Process** = address space (`Vmm`) + capability set + credential + a set of
  threads + an IPC endpoint table.
- **Thread** = kernel-scheduled unit of execution. Kernel threads are threads
  of the special `kernel` process with `cap:sys.admin`.
- **Scheduler:** CFS-like weighted fair queueing with per-CPU run queues,
  tickless where possible (PIT in M1 → LAPIC timer in M4). Priority changes
  require `cap:proc.nice` and are audited.
- **IPC:** synchronous rendezvous *and* asynchronous datagram, both
  capability-gated, both able to carry transferred file descriptors / memory
  regions. This is the substrate for OKI.
- **Signals/events:** Orin uses a small, explicit **event** model
  (`terminate`, `stop`, `resume`, `child_exit`, `window`, `user(n)`) rather
  than 31 numbered POSIX signals. POSIX signal *semantics* are emulated in the
  compatibility layer (§8) so Linux binaries behave correctly.

---

## 8. ABI compatibility strategy — the key architectural bet

Orin has its own kernel. That would normally mean: no LibreOffice, no
PowerShell, no Firefox, no GStreamer, no compilers-with-C-runtimes. Orin
refuses that outcome, and also refuses to just *become* Linux.

### 8.1 The decision

Orin ships a **Linux ABI compatibility subsystem**, internally `lxabi`, which
lets unmodified Linux x86_64 ELF binaries run on orink.

```text
Orin native app ──► OKI ──► orink                    (capabilities enforced)
Linux ELF       ──► lxabi ──► translation ──► orink  (capabilities ALSO enforced)
```

`lxabi` provides:

| Component | Responsibility |
|---|---|
| **ELF loader extension** | Recognises `PT_INTERP`-less static binaries and dynamic binaries needing `ld-linux-x86-64.so.2`; loads the Orin-provided glibc/musl into the compat sandbox |
| **Syscall translation table** | Linux syscall number → OKI/orink primitive. ~350 calls matter in practice; the table is generated and unit-tested |
| **`/proc`, `/sys`, `/dev` emulation** | A synthetic, *read-mostly* view built from real OKI queries — never a leak of host state the app has no capability for |
| **Namespaces view** | Each compat app sees a filesystem subtree; `cap:fs.all` is still required to escape it |
| **Personality flags** | `uname` reports Orin by default; a compat app that asks gets a Linux-shaped answer *because that's what it asked for* |

**Critically:** a Linux binary running under `lxabi` gets the capabilities of
its Orin package, no more. Running Chrome does not mean "root on the machine".
This is the single most important property of the design and the reason Orin
can be secure *and* useful.

### 8.2 What this unlocks

| Capability | Consumed rather than rewritten |
|---|---|
| Productivity | **LibreOffice** — Writer, Calc, Impress, Draw, Base, Math |
| PowerShell | **Microsoft's open-source PowerShell** (`pwsh`) + an `Orin.System` module that exposes OKI as cmdlets |
| Archive | **libarchive** / `zstd` / `xz` |
| Media | **GStreamer** + **FFmpeg** libs |
| PDF | **Poppler** |
| Browser | an existing engine (Gecko or WebKitGTK/BrowserSDK) behind Orin's own chrome, process model and privacy policy |
| Compilers | **LLVM/clang**, **GCC**, **rustc**, **cargo**, **CPython**, **Node.js** |
| Terminal apps | the entire existing ncurses ecosystem |

### 8.3 Bring-up order (why the incubator exists)

`lxabi` lands late (M18 is optimistic; a first slice lands with M9 user-space).
So the application ecosystem is developed **now** against `orinkern.linuxabi`,
a shim that presents the OKI contract on a Linux host. That shim is in
[`userspace/incubator/`](../userspace/incubator/) and is honest about itself:
it prints which ABI it is running on and every unimplemented OKI call returns
`ENOSYS` with a message naming the milestone that will implement it.

This is not a mock OS. It is the real OKI client, the real `orin` CLI, the real
`orinpkg`, the real `orinsh`, talking to a back-end that will be swapped from
`linuxabi` to `native` when orink grows the server side.

### 8.4 What Orin will *never* do

- Claim a Windows-specific cmdlet works when it does not. `Get-Disk`,
  `Get-NetIPConfiguration` etc. are implemented on Orin data; `Get-WinEvent`,
  `Get-ADUser`, registry cmdlets are **absent**, and `pwsh` says so.
- Present `cmd` compatibility as native Orin. It is a labelled compatibility
  environment (§ [`APPS.md`](APPS.md) part 3).
- Ship a binary blob as "a driver" without saying it is a binary blob.

---

## 9. Graphics architecture

Detail in [`GRAPHICS.md`](GRAPHICS.md).

```text
Applications ──► liborinui (widgets, layout, a11y, theming)
                     │
                     ▼  (surface buffers + event requests, over OKI/IPC)
              orin-displayd  =  compositor + window manager
                     │
                     ▼
              graphics backend:  GPU (Vulkan-style command submission)
                                 │ fallback: software raster → framebuffer
```

- The compositor is a **user-space service**, not a kernel subsystem. It owns
  no policy about which app may draw where — that's the WM, also in
  displayd, also revocable.
- Every window is a buffer the client renders into and *hands over*. Clients
  cannot read other clients' buffers. This is the same rule Wayland got right.
- HiDPI: scaling is a compositor property per output, with fractional scale
  advertised to clients that support it.
- M1 has no graphics. M8 brings up the framebuffer console first (already
  discovered via multiboot2 in M1), then the compositor.

---

## 10. User-space architecture

| Service | Owns | Needs |
|---|---|---|
| `orin-init` | boot sequencing, service supervision, shutdown ordering | `cap:service.admin` |
| `orin-logind` | sessions, seats, user switching, lock policy | `cap:sys.admin` |
| `orin-networkd` | interfaces, DHCP, routes, DNS resolution policy, firewall enforcement point | `cap:net.admin` |
| `orin-audiod` | mixing, per-app volume, device routing, mic permission enforcement | `cap:media` |
| `orin-displayd` | compositor, WM, output config, input routing | `cap:input.inject` |
| `orin-updated` | OS + package update, A/B slot switch, rollback | `cap:sys.admin` |
| `orin-packaged` | package DB, dependency resolution, signature verification | `cap:fs.all` |
| `orin-notifyd` | notification queue, per-app rate limits, persistence | `cap:notify` |
| `orin-securityd` | capability grants, keyring, audit log, sandbox policy | `cap:keyring` |
| `orin-indexd` | search index, privacy-aware (never indexes outside granted paths) | `cap:fs.user` |
| `orin-aid` | **opt-in** assistant; local or cloud models | *whatever the user grants, per action, prompt-visible* |

`orin-aid` is the one service with a hard rule written into the architecture:
**it never holds a standing capability.** Each privileged action it proposes
goes through the same permission prompt a normal app would trigger, and the
prompt names the assistant as the requester. There is no "AI mode".

---

## 11. Configuration system

One store, one schema, one API. Not files scattered across `/etc`.

- Format: TOML on disk (human-diffable), namespaced keys
  (`display.scale`, `privacy.location.enabled`).
- Access: `orin config get|set|watch <key>` on the CLI; a `SettingsClient`
  object in the SDK; D-Bus-free — it rides OKI.
- Per-user overrides layer over system defaults; machine-local layer over both.
- Every key is declared with a type, range, default and *which Settings panel
  renders it*. `orin config schema` dumps the whole thing; the Settings app is
  generated from it, so a new key cannot exist without a UI (or an explicit
  `hidden: true`).

---

## 12. Observability

One coherent model, three surfaces (Task Manager / Event Viewer / Monitor
equivalents are the *same data*):

```text
sources: orink ring log · service logs · app logs · audit log · crash reports
           │
           ▼
      orin-logd  (structured, indexed, retention-policy'd)
           │
   ┌───────┼────────────┬─────────────┐
   ▼       ▼            ▼             ▼
orin logs  Orin Logs   Orin Monitor  orin-aid (diagnostics)
 (CLI)      (GUI)       (live)        (opt-in)
```

Rules: logs are **structured records**, not strings; a record can never
contain a secret (the logger redacts values tagged `secret`); every record
carries `unit`, `pid`, `cap`, `severity`, `monotonic_ts`, `wall_ts`.

---

## 13. Build system

- Cargo workspace at the repo root; `-Zbuild-std=core,alloc,compiler_builtins`
  so the standard library pieces we use are compiled for `x86_64-unknown-none`.
- `rust-lld` links; a single linker script in `arch/x86_64/orin.ld` owns the
  memory map. No `-nostdlib` surprises, no C runtime.
- NASM assembles the boot stub into the kernel ELF as an embedded object.
- `make` orchestrates; `orin` (SDK, M15) will wrap the same steps so the
  commands in the prompt (`orin build|run|test|iso`) are real.
- Reproducibility: pinned toolchain file, committed `Cargo.lock`,
  `--locked` builds, no network at build time after `cargo fetch`.
- Artefacts land in `build/`: `orin_kernel.elf`, `orin.iso`, `serial.log`.

---

## 14. Architectural decision records

Material decisions, so a future reader knows *why*:

| # | Decision | Alternatives rejected | Reason |
|---|---|---|---|
| ADR-001 | Multiboot2 + GRUB for M1 | Limine (simpler, does long mode for us); UEFI-only direct boot | GRUB is installed, produces a hybrid BIOS+UEFI ISO, and forcing us to do the 32→64-bit transition ourselves means we actually understand it. Limine support is a later, additive boot path. |
| ADR-002 | Higher-half kernel from M1 | Identity-mapped kernel | User/kernel separation is a security requirement, not a nice-to-have; retrofitting it is far harder. |
| ADR-003 | Monolithic address space, trait-modular construction | Microkernel; exokernel | Ship a fast desktop OS; keep the option to extract services later. |
| ADR-004 | OKI above the syscall ABI | Expose raw syscalls to apps | One narrow, capability-checked, versioned chokepoint is auditable; 350 raw syscalls are not. |
| ADR-005 | Linux ABI compat subsystem (`lxabi`) | Port everything; or become a Linux distro | Gets LibreOffice/pwsh/LLVM without forking them, and without giving up the security model. |
| ADR-006 | Capability-based app permissions | UID/GID-only; DAC+MAC (SELinux-style) | Users can understand and revoke capabilities. Policy languages they cannot read are policy nobody audits. |
| ADR-007 | 3 external crates in M1 (`x86_64`, `spin`, `linked_list_allocator`) | Zero deps; or `bootloader`/`limine` ecosystems | Hand-rolled paging/IDT would be >1000 lines of unverified `unsafe`, violating Rule 1 in spirit. These three are pure-Rust, no build scripts, widely audited. Everything Orin-specific is hand-rolled. |
| ADR-008 | Events, not POSIX signals, in the native ABI | Clone POSIX signals | 31 overloaded numbers are a 1970s mistake; POSIX semantics are emulated in `lxabi` where they're actually needed. |
| ADR-009 | Compositor in user-space | In-kernel compositor / DRI-style | Kernel should not parse or composite. Compromise of the compositor must not mean kernel compromise. |
| ADR-010 | `orin-aid` holds no standing capability | Give the assistant a privileged daemon | An AI that can act without asking is an unbounded blast radius. Non-negotiable. |

---

## 15. Cross-cutting engineering rules

Restated from the master brief because they bind every module:

1. Never fake functionality. 2. Never hide compilation errors. 3. Never delete
broken code to make a build pass. 4. Explain architectural decisions. 5. Keep
modules small. 6. Prefer readable Rust over clever Rust. 7. Document `unsafe`.
8. Minimise `unsafe`. 9. Test wherever possible. 10. Deterministic builds.
11. Explicit security boundaries. 12. Avoid unnecessary dependencies.
13. Don't blindly copy Linux. 14. Don't reinvent without a technical reason.
15. No massive monolithic files. 16. Clear project structure. 17. Every
milestone produces a testable result.

Rule 17 is enforced mechanically: `make test` must pass for a milestone to be
marked IMPLEMENTED in [`ROADMAP.md`](ROADMAP.md).
