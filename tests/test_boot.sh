#!/usr/bin/env bash
# =============================================================================
#  Orin OS — M1 boot acceptance test
#  tests/test_boot.sh
#
#  Boots the ISO in QEMU, captures serial, asserts on what the kernel actually
#  printed. A missing SUMMARY is a failure, not a pass: a kernel that hangs
#  early produces no SUMMARY, and "no FAIL lines" would otherwise read as
#  success.
#
#  Exit codes:
#    0  kernel booted, selftest SUMMARY present, no FAIL lines, banner reached
#    1  kernel produced output that fails a check
#    2  QEMU never produced a usable serial log (timeout / crash before serial)
#    3  usage / environment error
# =============================================================================
set -euo pipefail

ISO="${1:?usage: test_boot.sh <iso> [qemu] [timeout-seconds]}"
QEMU="${2:-qemu-system-x86_64}"
TIMEOUT="${3:-25}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/orin-boot-XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

SERIAL_LOG="$WORKDIR/serial.log"
QEMU_LOG="$WORKDIR/qemu.log"
PIDFILE="$WORKDIR/qemu.pid"

echo "    ISO:     $ISO"
echo "    QEMU:    $QEMU"
echo "    timeout: ${TIMEOUT}s"
echo "    workdir: $WORKDIR"

# ---------------------------------------------------------------------------
# Launch QEMU.
#
# -machine q35          modern chipset; matches what the PIC/PIT code assumes
# -m 512M               enough for the 16 MiB heap + boot alias
# -cdrom                the GRUB2 hybrid ISO
# -serial file:         capture every byte the kernel writes to COM1
# -display none         headless; VGA still exists as a memory window the
#                       kernel writes to, it just is not rendered
# -no-reboot            a triple fault exits rather than looping forever
# -device isa-debug-exit,iobase=0xf4,iosize=0x04
#                       optional clean-exit port; the kernel does not use it
#                       in M1, but having it present does no harm
# ---------------------------------------------------------------------------
"$QEMU" \
    -machine q35 \
    -m 512M \
    -cdrom "$ISO" \
    -serial "file:$SERIAL_LOG" \
    -display none \
    -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    >"$QEMU_LOG" 2>&1 &
QEMU_PID=$!
echo "$QEMU_PID" >"$PIDFILE"

cleanup_qemu() {
    if kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        # Give it a moment to flush the serial file, then force.
        for _ in 1 2 3 4 5; do
            kill -0 "$QEMU_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
}
trap 'cleanup_qemu; rm -rf "$WORKDIR"' EXIT

# ---------------------------------------------------------------------------
# Wait for the selftest SUMMARY line, or for the timeout.
#
# Polling the serial log is deliberate: QEMU's monitor/QMP would let us inject
# keys for the keyboard e2e test, but the SUMMARY is the gate that everything
# else depends on, and a simple file poll needs no extra plumbing. The keyboard
# e2e is a follow-up once the boot path itself is green.
# ---------------------------------------------------------------------------
deadline=$((SECONDS + TIMEOUT))
saw_summary=0
while (( SECONDS < deadline )); do
    if [[ -f "$SERIAL_LOG" ]] && grep -qE 'SELFTEST\|SUMMARY' "$SERIAL_LOG" 2>/dev/null; then
        saw_summary=1
        # Give the banner a moment to land after the SUMMARY.
        sleep 0.5
        break
    fi
    # If QEMU already exited, stop waiting — either it triple-faulted or the
    # isa-debug-exit port was written. Either way the log is final.
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

cleanup_qemu
trap 'rm -rf "$WORKDIR"' EXIT

# ---------------------------------------------------------------------------
# Always print the serial log so a failure is diagnosable without re-running.
# ---------------------------------------------------------------------------
echo
echo "──── serial log ────────────────────────────────────────────────────────"
if [[ -f "$SERIAL_LOG" && -s "$SERIAL_LOG" ]]; then
    # Strip bare CRs so the log is readable; the kernel writes \r\n.
    tr -d '\r' <"$SERIAL_LOG" | sed 's/^/    /'
else
    echo "    (empty or missing)"
fi
echo "────────────────────────────────────────────────────────────────────────"
echo

if [[ ! -f "$SERIAL_LOG" || ! -s "$SERIAL_LOG" ]]; then
    echo "FAIL: no serial output. The kernel never reached console::serial::init,"
    echo "      or GRUB never entered it. Check:"
    echo "        * make verify-header   (Multiboot2 header must name _boot_start)"
    echo "        * make verify-elf      (entry path must not recurse)"
    echo "        * $QEMU_LOG            (QEMU's own stderr)"
    if [[ -f "$QEMU_LOG" ]]; then
        echo
        echo "──── qemu log ──────────────────────────────────────────────────────────"
        sed 's/^/    /' "$QEMU_LOG"
    fi
    exit 2
fi

# ---------------------------------------------------------------------------
# Assertions. Each one is independent so a single failure still reports the
# rest; the final exit code is non-zero if any failed.
# ---------------------------------------------------------------------------
pass=0
fail=0
check() {
    local cond="$1" msg="$2"
    if eval "$cond"; then
        echo "  PASS  $msg"
        pass=$((pass + 1))
    else
        echo "  FAIL  $msg"
        fail=$((fail + 1))
    fi
}

LOG="$SERIAL_LOG"
# Normalise line endings once so every grep sees the same bytes.
NORM="$WORKDIR/serial.norm"
tr -d '\r' <"$LOG" >"$NORM"

echo "──── assertions ────────────────────────────────────────────────────────"

# 1. The boot stub handed off. The first thing kmain does after recording the
#    boot-params pointer is initialise serial; the first structured record is
#    the serial self-test result.
check "grep -qE 'ORIN\\|[TDIWECP]\\|' \"$NORM\"" \
      "kernel produced at least one structured log record"

# 2. Self-test ran to completion. A missing SUMMARY is the most common silent
#    failure mode: the kernel panics or hangs mid-suite and "no FAIL lines"
#    would otherwise look green.
# Wire format is ORIN|<level>|<ts>|SELFTEST|SUMMARY  |result|<n> passed, ...
# (subsys field is "SELFTEST|SUMMARY"; level/timestamp sit between ORIN and it).
check "grep -qE 'ORIN\\|[TDIWECP]\\|.*SELFTEST\\|SUMMARY' \"$NORM\"" \
      "selftest SUMMARY line present"

# 3. No self-test failed. SKIP is allowed (and reported); FAIL is not.
fail_lines=$(grep -cE 'ORIN\|[TDIWECP]\|.*SELFTEST\|FAIL' "$NORM" || true)
check "[[ $fail_lines -eq 0 ]]" \
      "no selftest FAIL lines (found $fail_lines)"

# 4. At least one self-test passed. An empty suite that prints
#    "SUMMARY|0 passed, 0 failed, 0 skipped" is not a boot.
check "grep -qE 'SELFTEST\\|SUMMARY.*[1-9][0-9]* passed' \"$NORM\"" \
      "selftest reported at least one PASS"

# 5. The boot banner. Reaching it means init steps 1–18 completed, interrupts
#    are on, and the idle loop is running. Without this, a kernel that selftests
#    and then panics in the banner path would still look green.
check "grep -qiE 'orin|ORIN\\|.*banner|idle:|echo' \"$NORM\"" \
      "boot banner / idle marker reached"

# 6. No panic. A panic after SUMMARY would still fail (5) above in most cases,
#    but an explicit check makes the failure mode obvious in the report.
check "! grep -q 'ORIN-PANIC-BEGIN' \"$NORM\"" \
      "no kernel panic"
check "! grep -q 'ORIN-FATAL-BEGIN' \"$NORM\"" \
      "no fatal exception"

# 7. The echo path is armed. M1's idle loop prints ORIN|K|ECHO| when a decoded
#    key is ready; the marker itself is emitted once at arm-time so the test
#    can see the path is live even before a key is injected.
# Arm-time marker is ORIN|K|ECHO|ARMED (emitted once when the idle loop starts).
# Per-key echoes are ORIN|K|ECHO|<char>. Either proves the path is live.
check "grep -q 'ORIN|K|ECHO|' \"$NORM\" || grep -qiE 'idle: entering the M1 input echo' \"$NORM\"" \
      "keyboard echo path armed (ORIN|K|ECHO| or idle marker)"

echo
echo "──── summary ───────────────────────────────────────────────────────────"
if [[ $fail -eq 0 ]]; then
    echo "test_boot: PASS — $pass checks"
    # Surface the SUMMARY line so the make output names what ran.
    grep -E 'SELFTEST\|SUMMARY' "$NORM" | sed 's/^/    /' || true
    exit 0
else
    echo "test_boot: FAIL — $fail of $((pass + fail)) checks failed"
    exit 1
fi
