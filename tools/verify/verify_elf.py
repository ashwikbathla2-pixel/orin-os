#!/usr/bin/env python3
"""Verify the linked kernel's entry path is real, reachable and non-recursive.

Run by `make verify-elf`.

This script exists because of a bug that passed every other check. Both
src/main.rs (the bin shim) and src/kmain.rs (the library) declared
`#[unsafe(no_mangle)] pub extern "C" fn orin_kernel_main`. They are separate
crates, so Rust saw no conflict; the linker merged them, so the shim's call
resolved to itself:

    ffffffff80000020 <orin_kernel_main>:
        push %rbp ; mov %rsp,%rbp ; sub $0x10,%rsp
        call ffffffff80000020 <orin_kernel_main>      <-- itself

The image linked cleanly, every orin.ld ASSERT passed, .boot_params held the
right values — and the kernel overflowed its stack before executing one
instruction of the init sequence. A duplicate `no_mangle` across a bin and its
own lib is not a Rust error and not a linker error. Only looking at the produced
code reveals it.

So: disassemble the entry path and check what it actually does.
"""

import re
import subprocess
import sys

RESULTS = []


def check(cond, msg, hint=""):
    RESULTS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {msg}")
    if not cond and hint:
        for line in hint.strip().splitlines():
            print(f"          {line}")


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True)


def symbols(elf):
    out = sh("nm", "--format=posix", elf).stdout
    sym = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 3:
            try:
                sym[f[0]] = (int(f[2], 16), int(f[3], 16) if len(f) > 3 else 0)
            except ValueError:
                pass
    return sym


def disasm(elf, start, end):
    out = sh("objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={end:#x}", elf).stdout
    instrs = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+(.*?)\s{2,}(\S.*)$", line)
        if m:
            instrs.append((int(m.group(1), 16), m.group(3).strip(), line.strip()))
        elif re.match(r"\s*[0-9a-f]+:\s+", line) and "\t" in line:
            parts = line.split("\t")
            addr = int(parts[0].strip().rstrip(":"), 16)
            instrs.append((addr, parts[-1].strip(), line.strip()))
    return instrs


def body_of(elf, sym, addr_size, span=64):
    addr, size = addr_size
    return disasm(elf, addr, addr + max(size, 1) + span)


def main(elf):
    sym = symbols(elf)

    print("  --- the kernel is not empty ---")
    text = None
    out = sh("readelf", "-S", "-W", elf).stdout
    m = re.search(r"\]\s+\.text\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", out)
    if m:
        text = int(m.group(3), 16)
    check(text is not None and text > 0x10000,
          f".text is {text:#x} bytes" if text else ".text is missing",
          "A .text of a few dozen bytes means the linker garbage-collected the\n"
          "kernel. rustc passes --gc-sections for this target, and the only thing\n"
          "connecting the ELF entry (_boot_start, in assembly) to the Rust code is\n"
          "a `call orin_kernel_main` that is not a GC root the way ENTRY() is.\n"
          "The fix is -C link-arg=-no-gc-sections plus KEEP() in orin.ld; the\n"
          "symptom is an image that links cleanly and does nothing.")

    print()
    print("  --- entry path ---")
    for name in ("_boot_start", "orin_kernel_main"):
        check(name in sym, f"{name} is defined in the image")

    if "orin_kernel_main" not in sym:
        return finish()

    km_addr, km_size = sym["orin_kernel_main"]
    instrs = body_of(elf, "orin_kernel_main", sym["orin_kernel_main"])
    own = [(a, t, raw) for a, t, raw in instrs if a >= km_addr and a < km_addr + max(km_size, 1) + 8]

    for a, t, raw in own[:8]:
        print(f"          {raw}")

    check(len(own) > 0 and not all("int3" in t for _, t, _ in own),
          "orin_kernel_main contains instructions, not int3 padding",
          "int3 padding is what a garbage-collected or unreferenced function body\n"
          "looks like. See the .text size check above.")

    self_calls = [raw for a, t, raw in own
                  if t.startswith("call") and f"{km_addr:x}" in raw.replace("0x", "")]
    check(not self_calls,
          "orin_kernel_main does not call itself",
          "This is the duplicate-no_mangle bug: src/main.rs exports the ABI\n"
          "symbol and so did src/kmain.rs, so the linker merged them and the\n"
          "shim's call resolved to itself. Infinite recursion, stack overflow,\n"
          "double fault, no output. Only src/main.rs may carry #[no_mangle].\n"
          "Offending instruction(s): " + "; ".join(self_calls[:2]))

    # The shim must reach the library's real init sequence.
    calls_out = [raw for a, t, raw in own if t.startswith(("call", "jmp"))
                 and "int3" not in t]
    targets = []
    for raw in calls_out:
        m = re.search(r"([0-9a-f]{8,})\s*<([^>]+)>", raw)
        if m:
            targets.append((int(m.group(1), 16), m.group(2)))
    reaches_kmain = any("kernel_main" in name and addr != km_addr
                        for addr, name in targets)
    check(reaches_kmain,
          f"orin_kernel_main calls into kmain::kernel_main "
          f"({', '.join(n for _, n in targets[:3]) or 'no call targets found'})",
          "The shim in src/main.rs must forward to the library's init sequence.\n"
          "If it calls nothing, the kernel entry does nothing.")

    print()
    print("  --- boot.asm hands off correctly ---")
    boot_addr, boot_size = sym.get("_boot_start", (0, 0))
    if boot_addr:
        binstrs = disasm(elf, boot_addr, boot_addr + max(boot_size, 1) + 0x400)
        text_all = " ".join(raw for _, _, raw in binstrs)
        # 64-bit handoff: movabs of a high address into rax, then call *rax.
        high = re.findall(r"movabs\s+\$0x(ffffffff[0-9a-f]+)", text_all)
        check(bool(high),
              f"boot stub loads a higher-half address ({high[0] if high else '-'})",
              "After the far jump into long mode the stub must call the Rust entry\n"
              "at its higher-half virtual address, which needs a 64-bit immediate.")
        check(km_addr and any(int(h, 16) == km_addr for h in high),
              f"boot stub calls orin_kernel_main at {km_addr:#x}",
              "If the movabs target is not orin_kernel_main, the stub jumps\n"
              "somewhere else and the init sequence never runs.")
        check("call" in text_all and "%rax" in text_all,
              "boot stub performs an indirect call through a register",
              "A direct `call rel32` cannot span from a low physical address to a\n"
              "higher-half virtual address, so the handoff must be indirect.")

    return finish()


def finish():
    print()
    if all(RESULTS):
        print(f"verify-elf: PASS — {len(RESULTS)} checks")
        return 0
    print(f"verify-elf: FAIL — {RESULTS.count(False)} of {len(RESULTS)} checks failed")
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <kernel.elf>", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
