//! In-kernel device drivers.
//!
//! M1 contains exactly one driver, [`keyboard`], and that is deliberate: it is
//! the minimum needed to prove the interrupt path works end to end with a real
//! device rather than a synthetic one.
//!
//! The driver framework (device model, probing, binding, hotplug) is specified
//! in `docs/DRIVERS.md` and lands in M7. Every driver in this directory must
//! produce *events* and never policy — the keyboard driver emits `KeyEvent`s and
//! knows nothing about keymaps, repeat rates or accessibility, which belong to
//! `orin-inputd` in user space. That boundary is what lets a driver be moved
//! out of the kernel later without rewriting its consumers.

pub mod keyboard;
