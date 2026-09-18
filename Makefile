# =============================================================================
#  Orin OS — build system
#  Makefile
#
#  Every target here produces something checkable. `make test` is the contract:
#  it builds the kernel, statically verifies the ELF, boots it in QEMU, and
#  fails if the kernel did not do what it claimed to do. There is no target that
#  reports success without having observed the result.
#
#  Deterministic builds: build.rs stamps version, git rev, rustc version and
#  profile into the image. It does NOT stamp a wall-clock timestamp unless
#  ORIN_BUILD_TIMESTAMP=1, so two builds of the same tree produce the same
#  bytes. That is what makes `make verify-*` meaningful across machines.
# =============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

# --- Toolchain ---------------------------------------------------------------
CARGO      ?= cargo
NASM       ?= nasm
QEMU       ?= qemu-system-x86_64
GRUB_MKRESCUE ?= grub-mkrescue
OBJDUMP    ?= objdump
NM         ?= nm
READELF    ?= readelf
PYTHON     ?= python3

TARGET     := x86_64-unknown-none
PROFILE    ?= debug
# -Z build-std is what makes `core`, `alloc` and `compiler_builtins` available
# for a target that ships no precompiled std. `compiler-builtins-mem` supplies
# memcpy/memset, which the kernel needs and the target does not provide.
BUILD_STD  := -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem

# --- Paths -------------------------------------------------------------------
ROOT       := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
OUT        := $(ROOT)/target/$(TARGET)/$(PROFILE)
KERNEL_ELF := $(OUT)/orin_kernel
KERNEL_STRIPPED := $(OUT)/orin_kernel.stripped
ISO_ROOT   := $(OUT)/iso
ISO        := $(OUT)/orin.iso
BOOT_ASM   := $(ROOT)/arch/x86_64/boot/boot.asm
LINKER_LD  := $(ROOT)/arch/x86_64/orin.ld
TOOLS      := $(ROOT)/tools

# QEMU run parameters. `-no-reboot` turns a triple fault into an exit rather
# than an infinite reboot loop, so a crash terminates the test instead of
# hanging it. `-no-shutdown` is deliberately absent for the same reason.
QEMU_MEM   ?= 512M
QEMU_MACHINE ?= q35
QEMU_TIMEOUT ?= 25

# =============================================================================
#  Top-level targets
# =============================================================================

.PHONY: all
all: iso

.PHONY: help
help:
	@echo "Orin OS — build targets"
	@echo
	@echo "  make kernel      build the kernel ELF (debug)"
	@echo "  make release     build the kernel ELF (release, LTO)"
	@echo "  make iso         build a bootable GRUB2 hybrid ISO"
	@echo "  make run         boot the ISO in QEMU, serial to the terminal"
	@echo "  make test        the M1 acceptance gate: verify + boot + assert"
	@echo
	@echo "  make verify-header   Multiboot2 header is valid and names _boot_start"
	@echo "  make verify-layout   ELF layout matches arch::BootParams and orin.ld"
	@echo "  make verify-elf      entry point is real code and does not recurse"
	@echo "  make verify-abi      no soft-float calls; no duplicate no_mangle symbols"
	@echo "  make verify          all of the above"
	@echo
	@echo "  make test-host   host-side unit tests (tools/hostcheck)"
	@echo "  make fmt         rustfmt"
	@echo "  make clippy      lint"
	@echo "  make clean       remove build output"
	@echo
	@echo "  PROFILE=release make iso     build a release ISO"

# =============================================================================
#  Build
# =============================================================================

.PHONY: kernel
kernel:
	@echo "==> building kernel ($(PROFILE))"
	@cd $(ROOT) && $(CARGO) build --quiet --target $(TARGET) $(BUILD_STD) \
	    $(if $(filter release,$(PROFILE)),--release,) >/dev/null
	@test -f $(KERNEL_ELF) || { echo "build produced no ELF"; exit 1; }
	@echo "    $(KERNEL_ELF) ($$(stat -c%s $(KERNEL_ELF)) bytes)"

.PHONY: release
release:
	@$(MAKE) --no-print-directory PROFILE=release kernel

# A stripped copy is what goes on the ISO: the debug build is ~8 MB of DWARF
# around ~200 KB of kernel, and none of it is needed to boot. The unstripped ELF
# is kept for addr2line on a panic RIP.
# The debug build is ~8 MB of DWARF around ~200 KB of kernel. The ISO gets a
# stripped copy; the unstripped ELF is kept so `addr2line -e target/.../orin_kernel
# <panic rip>` resolves a backtrace to source lines.
OBJCOPY ?= objcopy
$(KERNEL_STRIPPED): kernel
	@echo "==> stripping debug info for the ISO"
	@cp $(KERNEL_ELF) $@
	@$(OBJCOPY) --strip-debug $@ 2>/dev/null || \
	    echo "    (objcopy unavailable; shipping the unstripped ELF)"
	@echo "    $@ ($$(stat -c%s $@) bytes)"

.PHONY: iso
iso: $(KERNEL_STRIPPED)
	@echo "==> building bootable ISO"
	@rm -rf $(ISO_ROOT)
	@mkdir -p $(ISO_ROOT)/boot/grub
	@cp $(KERNEL_STRIPPED) $(ISO_ROOT)/boot/orin_kernel.elf
	@cp $(ROOT)/boot/grub/grub.cfg $(ISO_ROOT)/boot/grub/grub.cfg
	@$(GRUB_MKRESCUE) -o $(ISO) $(ISO_ROOT) 2>/dev/null
	@test -f $(ISO) || { echo "grub-mkrescue did not produce an ISO"; exit 1; }
	@echo "    $(ISO) ($$(stat -c%s $(ISO)) bytes)"

# =============================================================================
#  Run
# =============================================================================

.PHONY: run
run: iso
	@echo "==> booting in QEMU (serial to this terminal, Ctrl-A X to quit)"
	$(QEMU) -machine $(QEMU_MACHINE) -m $(QEMU_MEM) -cdrom $(ISO) \
	    -serial mon:stdio -display none -no-reboot

# =============================================================================
#  Verification — static checks on the linked ELF
# =============================================================================

VERIFY_DIR := $(ROOT)/tools/verify

.PHONY: verify-header
verify-header: kernel
	@echo "==> verify-header: Multiboot2 header"
	@$(PYTHON) $(VERIFY_DIR)/verify_header.py $(KERNEL_ELF)

.PHONY: verify-layout
verify-layout: kernel
	@echo "==> verify-layout: ELF layout vs arch::BootParams"
	@$(PYTHON) $(VERIFY_DIR)/verify_layout.py $(KERNEL_ELF)

.PHONY: verify-elf
verify-elf: kernel
	@echo "==> verify-elf: entry point is real, non-recursive code"
	@$(PYTHON) $(VERIFY_DIR)/verify_elf.py $(KERNEL_ELF)

.PHONY: verify-abi
verify-abi: kernel
	@echo "==> verify-abi: no soft-float calls, no duplicate ABI symbols"
	@$(PYTHON) $(VERIFY_DIR)/verify_abi.py $(KERNEL_ELF) $(ROOT)

.PHONY: verify
verify: verify-header verify-layout verify-elf verify-abi
	@echo "==> all static checks passed"

# =============================================================================
#  Test
# =============================================================================

# The M1 acceptance gate. Boots the kernel in QEMU with serial captured to a
# file, then asserts on what the kernel actually printed:
#   * it reached the self-test suite and reported a SUMMARY line
#   * no self-test FAILED
#   * the boot banner appeared (so init completed, not just started)
#   * a keystroke injected over QMP was decoded and echoed
# A missing SUMMARY is a failure, not a pass: a kernel that hangs early produces
# no SUMMARY, and "no FAIL lines" would otherwise read as success.
.PHONY: test
test: iso verify
	@echo "==> boot test"
	@$(ROOT)/tests/test_boot.sh $(ISO) $(QEMU) $(QEMU_TIMEOUT)

.PHONY: test-host
test-host:
	@echo "==> host unit tests"
	cd $(ROOT) && $(CARGO) test -p orin-hostcheck --target x86_64-unknown-linux-gnu -- --nocapture

# =============================================================================
#  Hygiene
# =============================================================================

.PHONY: fmt
fmt:
	cd $(ROOT) && $(CARGO) fmt --all

.PHONY: clippy
clippy:
	cd $(ROOT) && $(CARGO) clippy --target $(TARGET) $(BUILD_STD) -- -D warnings

.PHONY: clean
clean:
	cd $(ROOT) && $(CARGO) clean
	@rm -f $(ISO) $(KERNEL_STRIPPED)
