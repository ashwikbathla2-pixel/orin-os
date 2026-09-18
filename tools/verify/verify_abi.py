#!/usr/bin/env python3
"""Verify ABI invariants that the compiler will not enforce for us.

Run by `make verify-abi`.

Two invariants, one of which failed at link time with a message naming neither
the cause nor the cure:

1. The kernel performs no floating-point arithmetic.
   x86_64-unknown-none is built `+soft-float,-sse2`, so an f64 operation becomes
   a call to a compiler_builtins routine such as `__divdf3`. Those routines are
   only emitted when compiler_builtins' float support is enabled, which
   `-Z build-std-features=compiler-builtins-mem` does not do. Introducing one
   `f64` division anywhere in the kernel therefore broke the link with:

       relocation R_X86_64_GOTPCREL out of range: 2148530123 ... references '__divdf3'

   Enabling SSE2 to make the intrinsics unnecessary is not available either:
   `-C target-feature=+sse,+sse2` makes compiler_builtins itself fail to compile
   under -Z build-std. So the invariant is "no FP arithmetic in Orin code", and
   this script is what enforces it. Replacing the f64 clock with exact rational
   integer arithmetic was strictly better anyway — 1000.1525 Hz is not
   representable in binary floating point, so the old code accumulated a
   representation error on top of the divisor truncation it was correcting.

2. Exactly one file exports ABI symbols.
   `#[unsafe(no_mangle)]` removes the crate-hash mangling that keeps Rust symbols
   unique. Two no_mangle functions with the same name in the bin and in its own
   lib collide, and the linker resolves the collision silently. See verify_elf.py
   for the kernel that booted into infinite recursion because of it.
"""

import re
import subprocess
import sys
from pathlib import Path

RESULTS = []

# Soft-float / float-helper C names. compiler_builtins also ships integer helpers
# (__ashrsi3, __udivsi3, …) and a full libm (cbrt, ceil, …); those are not the
# invariant. The invariant is "Orin does not do floating-point arithmetic", which
# is exactly the set of __*df3 / __*sf3 / __float* / __fix* routines that an
# f64 operation would pull in.
SOFT_FLOAT_RE = re.compile(
    r"^__(?:add|sub|mul|div|mod|neg|abs|pow)(?:df|sf|tf|xf|hf)3$"
    r"|^__float(?:si|di|ti|un(?:si|di|ti))(?:df|sf|tf|hf)$"
    r"|^__fix(?:uns)?(?:df|sf|tf|xf|hf)(?:si|di|ti)$"
    r"|^__(?:extend|trunc)(?:df|sf|tf|xf|hf)2$"
    r"|^__unord(?:df|sf|tf|hf)2$"
    r"|^__(?:eq|ne|lt|le|gt|ge)(?:df|sf|tf|hf)2$"
    r"|^__floatundidf$"
)

# The crate-hash fragment rustc puts into every mangled symbol of the Orin
# kernel library. Found by looking at any mangled Orin name in the image; if
# the crate is renamed the hash changes and this check will need updating —
# which is intentional: a silent rename would otherwise make the "is this Orin
# code?" classifier match nothing and report every call as clean.
ORIN_CRATE_HASH_RE = re.compile(r"Cs9RkY8DlIv1E_11orin_kernel|11orin_kernel")

# boot.asm globals: ABI between the stub and Rust, not Rust ABI.
ASM_GLOBALS = {
    "_boot_start", "_kpanic_halt", "_boot_bss_start", "_boot_bss_end",
    "_boot_pml4", "_boot_stack_top", "_kernel_stack_bottom", "_kernel_stack_top",
}


def check(cond, msg, hint=""):
    RESULTS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {msg}")
    if not cond and hint:
        for line in hint.strip().splitlines():
            print(f"          {line}")


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True).stdout


def is_orin_code(name):
    """True if `name` is Orin's own code rather than vendor / toolchain code.

    Orin code is either:
      * a #[no_mangle] symbol we own (main, orin_kernel_main), or
      * a rustc-mangled name whose crate hash is the Orin kernel's.

    Everything else — compiler_builtins (float, int, math/libm), core, alloc,
    the x86_64 crate, spin, linked_list_allocator — is vendor code that may call
    soft-float helpers freely without violating the "Orin does no FP" rule.
    """
    if name in {"main", "orin_kernel_main"}:
        return True
    if name.startswith("_R") or name.startswith("_RI"):
        return bool(ORIN_CRATE_HASH_RE.search(name))
    return False


def is_soft_float_target(name):
    """True if a call target is a soft-float / float-helper routine."""
    bare = name.split("+")[0]
    # Demangled C name (__adddf3) or a mangled name that embeds one.
    if SOFT_FLOAT_RE.search(bare):
        return True
    # Mangling embeds the C name as a trailing component, e.g.
    #   _RNv...compiler_builtins5float3add8___adddf3
    if "compiler_builtins" in bare and "float" in bare:
        return True
    return False


def main(elf, root):
    print("  --- no floating-point arithmetic in Orin code ---")

    # (a) An undefined soft-float routine means Orin called one that
    #     compiler_builtins did not provide. This is the case that broke the
    #     link, and it is checked directly.
    undef = [l.split()[-1] for l in sh("nm", "-u", elf).splitlines() if l.strip()]
    fp_undef = sorted({s for s in undef if SOFT_FLOAT_RE.search(s)})
    check(not fp_undef,
          f"no undefined soft-float routines ({len(undef)} undefined symbols total)",
          "An undefined __*df3 / __*sf3 means Orin code performed FP arithmetic.\n"
          "Find it with: nm -u <elf> | grep -E '__.*[ds]f3', then rewrite the\n"
          "arithmetic in integers. pit.rs documents the exact-rational pattern\n"
          "that replaced the f64 clock.")

    # (b) A call from Orin code into a soft-float routine that WAS provided.
    #     compiler_builtins defines dozens of them and they call each other
    #     freely (tf/xf variants delegate to df; libm calls the soft-float
    #     helpers). The check attributes each call to its enclosing function
    #     and only counts calls made by Orin code.
    label_re = re.compile(r"^([0-9a-f]+) <(.+)>:$")
    call_re = re.compile(
        r"^\s*[0-9a-f]+:\s+(?:call|jmp|tail)\s+\*?\s*"
        r"(?:([0-9a-f]+)\s*)?<([^>]+)>"
    )
    current = None
    violations = []
    orin_funcs = 0
    for line in sh("objdump", "-d", "--no-show-raw-insn", elf).splitlines():
        m = label_re.match(line)
        if m:
            current = m.group(2)
            if is_orin_code(current):
                orin_funcs += 1
            continue
        m = call_re.match(line)
        if not m or current is None:
            continue
        if not is_orin_code(current):
            continue
        target = m.group(2)
        if is_soft_float_target(target):
            violations.append(f"{current} -> {target}")

    check(not violations,
          f"no Orin code calls a soft-float routine "
          f"({orin_funcs} Orin functions scanned)",
          "Call sites found:\n  " + "\n  ".join(violations[:6]) +
          "\nRewrite the arithmetic in integers; pit.rs documents the\n"
          "exact-rational pattern that replaced the f64 clock.")

    print()
    print("  --- exactly one file exports ABI symbols ---")
    src = Path(root) / "kernel" / "src"
    offenders = []
    for f in sorted(src.rglob("*.rs")):
        text = f.read_text()
        # Strip comments first: main.rs and kmain.rs both discuss #[no_mangle]
        # at length, and documentation about the rule is not a use of it.
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        text = re.sub(r"//.*", "", text)
        if "no_mangle" in text:
            offenders.append(str(f.relative_to(Path(root))))
    check(offenders == ["kernel/src/main.rs"],
          f"#[no_mangle] appears in: {', '.join(offenders) or '(nowhere)'}",
          "Only src/main.rs may export ABI symbols. A second no_mangle function\n"
          "with the same name in the library collides with it at link time,\n"
          "silently. See verify_elf.py for the infinite-recursion kernel this\n"
          "produced and the disassembly that revealed it.")

    print()
    print("  --- exported ABI surface is the documented one ---")
    # What can collide with a #[no_mangle] Rust function is a GLOBAL TEXT symbol
    # (nm type 'T') whose name is not mangled. Everything else is noise for this
    # check:
    #   * type 't'  — local text (boot.asm internals, vendor helpers with
    #                 hidden visibility). Cannot collide across crates.
    #   * type 'A'  — absolute linker-script symbols. Addresses, not code.
    #   * type B/D/R/b/d/r — data / bss / rodata, including the many symbols
    #                 orin.ld defines with size omitted. Not callable.
    #   * _R... / _RI... — mangled Rust. Namespaced by crate hash.
    #   * __... — compiler_builtins C helpers (memcpy, __adddf3, …).
    #   * boot.asm's own globals (_boot_start, …) — known, allow-listed.
    #
    # So: collect global text that is none of the above. The set must be exactly
    # {main, orin_kernel_main}. Anything else is a stray #[no_mangle] in the
    # library, which is the collision that produced the self-recursive entry
    # point verify_elf.py checks for.
    expected = {"main", "orin_kernel_main"}
    rust_abi = {}
    for line in sh("nm", "--format=posix", "--defined-only", elf).splitlines():
        f = line.split()
        if len(f) < 3:
            continue
        name, stype = f[0], f[1]
        if stype != "T":
            continue                                   # not global text
        if name.startswith("_R") or name.startswith("_RI") or name.startswith("__rust"):
            continue                                   # mangled Rust
        if name.startswith("__"):
            continue                                   # vendor C helper
        if name in ASM_GLOBALS or name.startswith("gdt64"):
            continue                                   # boot.asm
        # Linker-script address markers placed *inside* a PROGBITS section
        # inherit that section's symbol type. `_kernel_text_start` sits at the
        # first byte of .text so nm reports it as 'T', but it is an address,
        # not a function — calling it would execute whatever happens to be
        # there (currently `main`). The naming convention is the filter:
        # every orin.ld symbol is `_snake_case` of a known shape.
        if re.fullmatch(
            r"_(?:kernel|boot|heap|image|lma|phys)(?:_[a-z0-9]+)+",
            name,
        ):
            continue                                   # orin.ld marker
        rust_abi[name] = rust_abi.get(name, 0) + 1

    dupes = sorted(n for n, c in rust_abi.items() if c > 1)
    check(not dupes,
          f"no duplicated Rust ABI symbols among {sorted(rust_abi) or expected}",
          f"Duplicates: {dupes[:5]}")

    unexpected = sorted(set(rust_abi) - expected)
    missing = sorted(expected - set(rust_abi))
    check(not unexpected and not missing,
          f"Rust ABI surface is exactly {sorted(expected)}"
          + (f" (extra: {unexpected})" if unexpected else "")
          + (f" (missing: {missing})" if missing else ""),
          "Every global unmangled text symbol is a contract with boot.asm or\n"
          "with the bootloader. Only src/main.rs may create one. A second\n"
          "#[no_mangle] in the library collides at link time and the collision\n"
          "resolves silently — see verify_elf.py.")

    for name in sorted(expected):
        check(name in rust_abi, f"{name} is exported as global text")

    print()
    if all(RESULTS):
        print(f"verify-abi: PASS — {len(RESULTS)} checks")
        return 0
    print(f"verify-abi: FAIL — {RESULTS.count(False)} of {len(RESULTS)} checks failed")
    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <kernel.elf> [repo-root]", file=sys.stderr)
        raise SystemExit(2)
    root = (sys.argv[2] if len(sys.argv) > 2
            else str(Path(sys.argv[1]).resolve().parents[3]))
    raise SystemExit(main(sys.argv[1], root))
