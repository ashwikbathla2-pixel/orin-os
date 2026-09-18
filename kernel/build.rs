//! Build script: assembles the arch boot stub and hands the resulting object
//! to the linker.
//!
//! Keeping this here (rather than in the Makefile) means `cargo build` alone
//! produces a correct kernel — the Makefile is an orchestrator, not a
//! requirement. Anything that can silently produce a stale boot object is a
//! boot failure that looks like a hang, so `rerun-if-changed` is exhaustive.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest.parent().unwrap().to_path_buf();
    let asm = workspace.join("arch/x86_64/boot/boot.asm");
    let linker_script = workspace.join("arch/x86_64/orin.ld");

    println!("cargo:rerun-if-changed={}", asm.display());
    println!("cargo:rerun-if-changed={}", linker_script.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ORIN_PROFILE");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let obj = out_dir.join("boot.o");

    // -- NASM -------------------------------------------------------------
    let nasm = std::env::var("ORIN_NASM").unwrap_or_else(|_| "nasm".to_string());
    let status = Command::new(&nasm)
        .arg("-f")
        .arg("elf64")
        // `-w+orphan-labels` catches the one NASM diagnostic that indicates a
        // real bug (a label referenced but never defined at file scope).
        // `-w+all` would additionally report `reloc-abs-dword`/`reloc-abs-qword`
        // for every cross-section absolute reference — which is precisely what
        // a boot stub linked against a linker-script-provided layout must do,
        // and which the linker resolves correctly. Warnings that are expected
        // by design get ignored, so they must not be emitted.
        .arg("-w+orphan-labels")
        .arg("-Ox")
        .arg("-o")
        .arg(&obj)
        .arg(&asm)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {nasm}: {e}"));
    if !status.success() {
        panic!("nasm failed assembling {}", asm.display());
    }

    // -- link arguments ----------------------------------------------------
    println!("cargo:rustc-link-arg=-T{}", linker_script.display());
    // whole-archive: nothing references `_boot_start` from Rust, and the ELF
    // ENTRY() directive alone is not enough to stop lld dropping the section
    // during garbage collection. Force it in.
    println!("cargo:rustc-link-arg=--whole-archive");
    println!("cargo:rustc-link-arg={}", obj.display());
    println!("cargo:rustc-link-arg=--no-whole-archive");

    // Emit the object path so the Makefile can find it for `make verify-header`.
    let stamp = out_dir.join("boot-object-path.txt");
    std::fs::write(&stamp, obj.to_string_lossy().as_bytes()).unwrap();
    println!("cargo:boot-object={}", obj.display());

    // -- build identity ---------------------------------------------------
    // Stamped into the kernel and printed in the boot banner and every panic
    // report, so a serial log always says exactly which build produced it. A
    // crash report without a build id is a crash report you cannot act on.
    //
    // Deliberately contains NO wall-clock timestamp by default: that would make
    // every build differ (Engineering Rule 10). Set ORIN_BUILD_TIMESTAMP=1 for
    // a local debugging build when you want one.
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
    let rustc = String::from_utf8_lossy(
        &Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
            .arg("--version")
            .output()
            .map(|o| o.stdout)
            .unwrap_or_default(),
    )
    .trim()
    .to_string();
    let git = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(&workspace)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "nogit".to_string());

    let mut id = format!(
        "orink {} | git {} | {} | profile {} | OKI ABI v3",
        std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0".into()),
        git,
        rustc,
        profile
    );
    if std::env::var("ORIN_BUILD_TIMESTAMP").is_ok() {
        let date = Command::new("date")
            .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "?".into());
        id.push_str(&format!(" | NON-REPRODUCIBLE build at {date}"));
    }
    std::fs::write(out_dir.join("build_id.txt"), id.as_bytes()).unwrap();
    println!("cargo:rerun-if-env-changed=ORIN_BUILD_TIMESTAMP");

    // Warn loudly (but do not fail) if the toolchain lacks what we need.
    if !Path::new(&linker_script).exists() {
        panic!("linker script missing: {}", linker_script.display());
    }
}
