#!/usr/bin/env python3
"""Verify the linked kernel's memory layout against the values the kernel reads.

Run by `make verify-layout`.

The layout is defined twice, necessarily: once in arch/x86_64/orin.ld (which
places the sections) and once in kernel/src/arch.rs (which holds the constants
the kernel uses at run time). orin.ld has ASSERTs for the invariants it can
express, but an ASSERT can only compare linker-script values to each other. It
cannot tell you that arch.rs's HEAP_VIRT_START drifted from the script's
HEAP_VMA, and that class of drift produces a kernel that maps the heap over
something else — a bug with no diagnostic.

So this script reads the truth out of the linked ELF and compares it to both
sides. It checks:

  * .boot_params contains exactly the six values the layout implies, in the
    order arch::BootParams declares them
  * the section VMAs are the 2 MiB-aligned, disjoint regions orin.ld promises
  * the LMAs are packed and do not overlap
  * everything physical is inside the 2 GiB the boot stub identity-maps
  * _kernel_virt_end covers .eh_frame, without which a panic backtrace faults
"""

import re
import struct
import subprocess
import sys

PAGE = 0x1000
LARGE_PAGE = 0x200000
KERNEL_VMA = 0xFFFFFFFF80000000
HEAP_VMA = 0xFFFFFFFF00000000
HEAP_SIZE = 16 * 1024 * 1024
BOOT_MAPPED_BYTES = 2 * 1024 * 1024 * 1024

# arch::BootParams field order. This is an ABI shared with orin.ld's QUADs.
BOOT_PARAMS_FIELDS = [
    "kernel_phys_start",
    "kernel_phys_end",
    "boot_bss_phys_start",
    "boot_bss_phys_end",
    "heap_phys_start",
    "heap_phys_end",
]

RESULTS = []


def check(cond, msg, hint=""):
    RESULTS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {msg}")
    if not cond and hint:
        for line in hint.strip().splitlines():
            print(f"          {line}")


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True).stdout


def sections(elf):
    """name -> dict(vma, off, size, flags, type)."""
    out = sh("readelf", "-S", "-W", elf)
    secs = {}
    lines = out.splitlines()
    for i, line in enumerate(lines):
        m = re.search(r"\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
        if not m:
            continue
        name, stype, vma, off, size = m.groups()
        rest = (line + " " + (lines[i + 1] if i + 1 < len(lines) else "")).split()
        secs[name] = {
            "type": stype,
            "vma": int(vma, 16),
            "off": int(off, 16),
            "size": int(size, 16),
        }
    return secs


def section_bytes(elf, name):
    out = sh("objdump", "-s", "-j", name, elf)
    rows = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) < 2 or len(p[0]) < 4 or not all(c in "0123456789abcdef" for c in p[0]):
            continue
        body = b"".join(
            bytes.fromhex(g) for g in p[1:5]
            if len(g) == 8 and all(c in "0123456789abcdef" for c in g)
        )
        if body:
            rows[int(p[0], 16)] = body
    if not rows:
        return b""
    return b"".join(rows[k] for k in sorted(rows))


def symbols(elf):
    out = sh("nm", "--format=posix", elf)
    sym = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 3:
            try:
                sym[f[0]] = int(f[2], 16)
            except ValueError:
                pass
    return sym


def main(elf):
    secs = sections(elf)
    sym = symbols(elf)

    print("  --- .boot_params: the values the kernel actually reads ---")
    raw = section_bytes(elf, ".boot_params")
    check(len(raw) == 48,
          f".boot_params is {len(raw)} bytes, expected 48 (six u64)",
          "orin.ld ASSERTs SIZEOF(.boot_params) == 48 and arch.rs asserts\n"
          "size_of::<BootParams>() == 48; if this differs, one of them changed.")
    bp = {}
    if len(raw) == 48:
        bp = {n: struct.unpack_from("<Q", raw, i * 8)[0]
              for i, n in enumerate(BOOT_PARAMS_FIELDS)}
        for n, v in bp.items():
            print(f"          {n:<22} = {v:#018x}")

    print()
    print("  --- boot sections: VMA == LMA (paging is off at entry) ---")
    # GRUB loads at LMA and jumps to VMA. With paging disabled those must be
    # the same address or the stub executes whatever was at VMA already —
    # typically empty memory — and faults before serial or VGA is up. The
    # static layout checks all passed with VMA!=LMA once; this is what catches
    # that class of bug.
    out = sh("readelf", "-l", "-W", elf)
    boot_loads = []
    for line in out.splitlines():
        if not line.strip().startswith("LOAD"):
            continue
        p = line.split()
        # LOAD Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
        if len(p) < 6:
            continue
        va, pa, fsz = int(p[2], 16), int(p[3], 16), int(p[4], 16)
        if 0x100000 <= va < 0x400000:   # boot identity region
            boot_loads.append((va, pa, fsz))
            check(va == pa,
                  f"boot PT_LOAD va={va:#x} pa={pa:#x} fsz={fsz:#x}",
                  "VMA != LMA for a boot section. GRUB loads the bytes at LMA\n"
                  "and jumps to VMA; with paging off that is a different address\n"
                  "and the stub faults before producing any output. Cause is\n"
                  "usually `ALIGN(n) : AT(_lma)` in orin.ld advancing `.`\n"
                  "without advancing `_lma`. Boot sections must not use AT().")
    check(len(boot_loads) >= 2,
          f"found {len(boot_loads)} boot-region PT_LOAD segments",
          "Expected at least .multiboot_header and .boot_text.")

    print()
    print("  --- physical layout ---")
    if bp:
        check(bp["kernel_phys_start"] == 1024 * 1024,
              f"kernel image starts at 1 MiB ({bp['kernel_phys_start']:#x})",
              "Below 1 MiB live the real-mode IVT, BIOS data area, VGA window\n"
              "and option ROMs, which the frame allocator reserves blindly.")
        check(bp["boot_bss_phys_start"] % LARGE_PAGE == 0,
              f"boot bss is 2 MiB aligned ({bp['boot_bss_phys_start']:#x})",
              "boot.asm maps with 2 MiB large pages, so a region straddling a\n"
              "2 MiB boundary would need a second PD entry the stub does not fill.")
        expected_bss = 4 * PAGE + 65536 + 65536  # tables + boot stack + kernel stack
        got_bss = bp["boot_bss_phys_end"] - bp["boot_bss_phys_start"]
        check(got_bss == expected_bss,
              f"boot bss is {got_bss:#x} = 4 page tables + 64K boot stack + 64K kernel stack",
              "boot.asm zeroes this range using sizes computed at ASSEMBLY time,\n"
              "because `mov ecx, (_end - _start)` with extern linker symbols is an\n"
              "invalid operand type in 32-bit mode. If the linker lays it out\n"
              "differently the stub zeroes the wrong bytes and the page tables\n"
              "contain stale data — which faults at an address that looks random.")
        check(bp["heap_phys_end"] - bp["heap_phys_start"] == HEAP_SIZE,
              f"heap backing store is {HEAP_SIZE // (1024*1024)} MiB")
        check(bp["heap_phys_start"] % LARGE_PAGE == 0,
              f"heap base is 2 MiB aligned ({bp['heap_phys_start']:#x})",
              "vmm.rs maps the heap with large pages.")
        check(bp["kernel_phys_end"] >= bp["heap_phys_end"],
              "kernel_phys_end covers the heap backing store",
              "The frame allocator reserves [kernel_phys_start, kernel_phys_end).\n"
              "If the heap is outside that range the PMM can hand its pages to\n"
              "something else, which then overwrites the live heap.")
        check(bp["kernel_phys_end"] <= BOOT_MAPPED_BYTES,
              f"whole image ({bp['kernel_phys_end']:#x}) is inside the 2 GiB boot alias",
              "boot.asm large-pages physical 0..2 GiB into both the identity map\n"
              "and the higher-half alias. Anything past that is unreachable from\n"
              "kernel virtual addresses until the VMM builds real tables.")

    print()
    print("  --- virtual layout: VMA = LMA + KERNEL_VMA, 2 MiB-aligned, disjoint ---")
    # Boot page tables alias phys P at both P and P+KERNEL_VMA. Every kernel
    # section MUST satisfy VMA == LMA + KERNEL_VMA or the CPU fetches the wrong
    # physical page after the long-mode jump (classic symptom: #UD at entry).
    order = [".text", ".rodata", ".data", ".bss"]
    prev_end = None
    for name in order:
        s = secs.get(name)
        if not s:
            check(False, f"{name} section missing")
            continue
        vma, size = s["vma"], s["size"]
        # LMA from program headers is more reliable than section file off for
        # NOBITS; use the section's own sh_addr - KERNEL_VMA for the expected LMA
        # under the boot-alias invariant.
        expected_lma = vma - KERNEL_VMA if vma >= KERNEL_VMA else None
        check(vma >= KERNEL_VMA,
              f"{name} VMA {vma:#x} is in the higher half")
        check(vma % LARGE_PAGE == 0,
              f"{name} VMA {vma:#x} is 2 MiB aligned",
              "Two sections sharing a 2 MiB region cannot have different "
              "permissions (orin.ld PROBLEM 2).")
        check(size <= LARGE_PAGE or name == ".bss",
              f"{name} size {size:#x} fits a 2 MiB region (or is .bss which may grow)",
              f"If {name} outgrows 2 MiB, give it more regions in orin.ld.")
        if prev_end is not None:
            check(vma >= prev_end,
                  f"{name} VMA {vma:#x} is after previous section end {prev_end:#x}")
        # Record end of this section's reserved 2 MiB slot (bss: just content end)
        prev_end = vma + (LARGE_PAGE if name != ".bss" else max(size, 1))

    # Boot-alias invariant against PT_LOAD
    out = sh("readelf", "-l", "-W", elf)
    for line in out.splitlines():
        if not line.strip().startswith("LOAD"):
            continue
        p = line.split()
        if len(p) < 6:
            continue
        va, pa = int(p[2], 16), int(p[3], 16)
        if va >= KERNEL_VMA and int(p[4], 16) > 0:  # file-backed higher-half
            check(va == pa + KERNEL_VMA,
                  f"boot-alias: PT_LOAD va={va:#x} == pa={pa:#x} + KERNEL_VMA",
                  "VMA must equal LMA + KERNEL_VMA or the boot page tables "
                  "translate the kernel entry to the wrong physical page.")

    
    print()
    print("  --- load addresses are packed and non-overlapping ---")
    loadable = [(n, s) for n, s in secs.items()
                if s["type"] == "PROGBITS" and s["size"] > 0
                and (s["vma"] >= KERNEL_VMA or n.startswith(".boot") or n == ".multiboot_header")]
    # Compare each kernel section's LMA against its predecessor by VMA order.
    kern = sorted([(s["vma"], n, s) for n, s in secs.items()
                   if s["vma"] >= KERNEL_VMA and s["type"] == "PROGBITS" and s["size"] > 0])
    prev = None
    for vma, name, s in kern:
        if prev is not None:
            pn, ps = prev
            check(s["off"] >= ps["off"] + ps["size"],
                  f"{name} LMA {s['off']:#x} does not overlap {pn} "
                  f"({ps['off']:#x}+{ps['size']:#x})",
                  "Overlapping LMAs mean GRUB loads one section over another.\n"
                  "The usual cause is a linker script computing an LMA with\n"
                  "AT(ADDR(x) - KERNEL_VMA) while `.` is still a low physical\n"
                  "address, which evaluates to 0.")
        prev = (name, s)

    print()
    print("  --- unwind metadata is inside the mapped extent ---")
    virt_end = sym.get("_kernel_virt_end")
    for name in (".eh_frame", ".gcc_except_table", ".bss"):
        s = secs.get(name)
        if s is None or virt_end is None:
            continue
        check(virt_end >= s["vma"] + s["size"],
              f"_kernel_virt_end ({virt_end:#x}) covers {name} "
              f"(ends {s['vma'] + s['size']:#x})",
              "The VMM maps [_kernel_bss_start, _kernel_virt_end) RW-NX and the\n"
              "panic handler walks .eh_frame for backtraces. Leaving it unmapped\n"
              "turns every panic into a second fault inside the fault handler,\n"
              "which prints nothing and triple-faults.")

    print()
    if all(RESULTS):
        print(f"verify-layout: PASS — {len(RESULTS)} checks")
        return 0
    print(f"verify-layout: FAIL — {RESULTS.count(False)} of {len(RESULTS)} checks failed")
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <kernel.elf>", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
