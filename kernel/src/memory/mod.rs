//! Memory subsystem.
//!
//! Three allocators, one per concern — see `docs/MEMORY.md` §1:
//!
//! * [`pmm`] — physical frames. Owns every 4 KiB page of machine RAM.
//! * [`vmm`] — kernel virtual address space and the permission policy (W^X).
//! * [`heap`] — the `#[global_allocator]` backing `Box`/`Vec`/`String`.
//!
//! Init order is fixed and load-bearing: `pmm` → `vmm` → `heap`. The VMM needs
//! frames for page tables; the heap needs the VMM to have mapped its backing
//! store.

pub mod heap;
pub mod pmm;
pub mod vmm;
