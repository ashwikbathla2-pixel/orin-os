#!/usr/bin/env python3
"""Verify the Multiboot2 header in a linked Orin kernel ELF.

Run by `make verify-header`. Every check here corresponds to a way the kernel
could fail to boot that produces no diagnostic: GRUB rejects the image, or
accepts it and jumps somewhere that is not the Orin boot stub.

The header is assembled by hand in arch/x86_64/boot/boot.asm, so a typo there is
silent until boot. Checking the bytes rather than the source is what makes it
not silent.
"""

import struct
import subprocess
import sys

MB2_MAGIC = 0xE85250D6
MB2_ARCH_I386 = 0  # 32-bit protected mode, which is what GRUB enters us in

# Multiboot2 *header* tag types (these are what we REQUEST from the loader, and
# are a different numbering from the information-structure tags the loader hands
# back — confusing the two is a classic Multiboot2 bug, see multiboot/info.rs).
HEADER_TAGS = {
    0: "END",
    1: "INFORMATION_REQUEST",
    2: "ADDRESS",
    3: "ENTRY_ADDRESS",
    4: "CONSOLE_FLAGS",
    5: "FRAMEBUFFER",
    6: "MODULE_ALIGN",
    7: "EFI_BS",
}

REQUIRED_TAGS = {3: "ENTRY_ADDRESS", 0: "END"}


def fail(msg):
    print(f"  FAIL  {msg}")
    return False


def ok(msg):
    print(f"  PASS  {msg}")
    return True


def section_bytes(elf, name):
    """Raw bytes of a section, reassembled from objdump's hex dump.

    objdump prints the section's ADDRESS as the row label, not a file offset, so
    rows must be ordered by that address and concatenated — using it as an offset
    silently produces a zero-filled buffer, which reads as "all fields are 0".
    """
    out = subprocess.run(
        ["objdump", "-s", "-j", name, elf], capture_output=True, text=True
    )
    if out.returncode != 0:
        return None
    rows = {}
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or len(parts[0]) < 4:
            continue
        if not all(c in "0123456789abcdef" for c in parts[0]):
            continue
        body = b"".join(
            bytes.fromhex(g)
            for g in parts[1:5]
            if len(g) == 8 and all(c in "0123456789abcdef" for c in g)
        )
        if body:
            rows[int(parts[0], 16)] = body
    if not rows:
        return None
    return b"".join(rows[k] for k in sorted(rows))


def symbol(elf, name):
    """Address of a symbol, or None. `nm --format=posix` is name/type/value/size."""
    out = subprocess.run(["nm", "--format=posix", elf], capture_output=True, text=True)
    for line in out.stdout.splitlines():
        f = line.split()
        if len(f) >= 3 and f[0] == name:
            return int(f[2], 16)
    return None


def elf_entry(elf):
    out = subprocess.run(["readelf", "-h", elf], capture_output=True, text=True)
    return int(out.stdout.split("Entry point address:")[1].split()[0], 16)


def main(elf):
    results = []

    hdr = section_bytes(elf, ".multiboot_header")
    if hdr is None:
        print("  FAIL  no .multiboot_header section in the image")
        print()
        print("        NASM treats `section .foo, align=8` as a section literally")
        print("        NAMED '.foo,' — attributes are space-separated, not")
        print("        comma-separated. If that happens the linker script's")
        print("        *(.multiboot_header) matches nothing, the header is")
        print("        dropped, and GRUB reports 'not a Multiboot2 image'.")
        return 1
    results.append(ok(f".multiboot_header present, {len(hdr)} bytes"))

    if len(hdr) < 16:
        print("  FAIL  header shorter than the 16-byte fixed part")
        return 1

    magic, arch, hlen, cksum = struct.unpack_from("<IIII", hdr, 0)

    results.append(
        ok(f"magic {magic:#010x}") if magic == MB2_MAGIC
        else fail(f"magic {magic:#010x}, expected {MB2_MAGIC:#010x}")
    )
    results.append(
        ok(f"architecture {arch} (i386 / 32-bit protected mode)") if arch == MB2_ARCH_I386
        else fail(f"architecture {arch}, expected {MB2_ARCH_I386}")
    )
    results.append(
        ok(f"header_length {hlen} == {len(hdr)} bytes on disk") if hlen == len(hdr)
        else fail(f"header_length {hlen} != {len(hdr)} bytes on disk")
    )

    # The spec requires magic + arch + header_length + checksum == 0 (mod 2^32).
    total = (magic + arch + hlen + cksum) & 0xFFFFFFFF
    results.append(
        ok(f"checksum {cksum:#010x} (sum mod 2^32 = {total:#x})") if total == 0
        else fail(f"checksum {cksum:#010x}: sum mod 2^32 = {total:#x}, must be 0")
    )

    # GRUB requires the header to start within the first 32 KiB of the file.
    out = subprocess.run(["readelf", "-S", "-W", elf], capture_output=True, text=True)
    for line in out.stdout.splitlines():
        if ".multiboot_header" in line:
            fields = line.split()
            # readelf -S wraps name/type onto the next line; find the offset.
            try:
                idx = fields.index(".multiboot_header")
                off = int(fields[idx + 3], 16)
            except (ValueError, IndexError):
                off = None
            if off is not None:
                results.append(
                    ok(f"header file offset {off:#x} (< 32 KiB)") if off < 0x8000
                    else fail(f"header file offset {off:#x} is past the 32 KiB limit")
                )
            break

    # Walk the tags.
    entry = None
    tags = []
    off = 16
    while off + 8 <= len(hdr):
        ttype, tflags, tsize = struct.unpack_from("<HHI", hdr, off)
        tags.append(ttype)
        if tsize < 8 or off + tsize > len(hdr):
            results.append(fail(f"tag type {ttype} has invalid size {tsize}"))
            break
        if ttype == 3 and tsize >= 12:
            entry = struct.unpack_from("<I", hdr, off + 8)[0]
        if ttype == 0:
            break
        off += (tsize + 7) & ~7  # tags are 8-byte aligned
    else:
        results.append(fail("tag list did not terminate with an END tag"))

    names = [f"{t}({HEADER_TAGS.get(t, '?')})" for t in tags]
    results.append(ok(f"tags: {', '.join(names)}"))
    for t, label in REQUIRED_TAGS.items():
        results.append(
            ok(f"{label} tag present") if t in tags
            else fail(f"{label} tag missing")
        )

    # The entry_address tag is a 32-bit PHYSICAL address, and must be the boot
    # stub — not the Rust entry point, which lives at a higher-half virtual
    # address GRUB cannot jump to with paging disabled.
    boot_start = symbol(elf, "_boot_start")
    e_entry = elf_entry(elf)
    kmain = symbol(elf, "orin_kernel_main")

    if entry is None:
        results.append(fail("ENTRY_ADDRESS tag did not contain an address"))
    else:
        results.append(
            ok(f"entry_address {entry:#x} == _boot_start {boot_start:#x}")
            if entry == boot_start
            else fail(f"entry_address {entry:#x} != _boot_start {boot_start:#x}")
        )
        if kmain is not None:
            results.append(
                ok(f"entry is the 32-bit stub, not orin_kernel_main ({kmain:#x})")
                if entry != kmain
                else fail("entry_address points at the Rust entry point; GRUB "
                          "enters with paging disabled and would fault")
            )
    results.append(
        ok(f"ELF e_entry {e_entry:#x} == entry_address") if e_entry == entry
        else fail(f"ELF e_entry {e_entry:#x} != entry_address {entry:#x}")
    )

    print()
    if all(results):
        print("verify-header: PASS — GRUB will accept this image and jump to the Orin boot stub")
        return 0
    print(f"verify-header: FAIL — {results.count(False)} of {len(results)} checks failed")
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <kernel.elf>", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
