"""
orinkern — Orin Kernel Interface (OKI) client library
======================================================

Orin OS has its own kernel (``orink``). User-space never touches POSIX or
Linux syscalls directly: every privileged or system-wide operation goes
through OKI, a small, versioned, capability-checked RPC surface.

Two implementations of OKI exist:

  * ``orinkern.native``  — talks to the real orink kernel over /dev/oki
                           (ioctl + shared-memory rings). Ships on Orin
                           hardware/VM images.
  * ``orinkern.linuxabi``— the Linux ABI compatibility shim. Translates OKI
                           calls into POSIX/Linux syscalls. This is what runs
                           during porting, in CI, and when a Linux binary
                           (LibreOffice, pwsh, GStreamer) is executed inside
                           Orin's lxrun compatibility environment.

Selection is automatic: native if ``/dev/oki`` exists, else linuxabi.
Force with ``ORIN_ABI=native|linuxabi``.

Design rules (see docs/01-architecture.md §4):
  * No OKI call may succeed without a capability grant to the caller.
  * Every OKI call is audit-logged (``oki.audit``) unless flagged EPHEMERAL.
  * OKI returns *structured* results (dicts); text rendering is the CLI's job.
  * OKI is stable ABI. Adding fields is allowed; removing/renaming is not.
"""

from __future__ import annotations

import os

__version__ = "1.0.0"
OKI_ABI_VERSION = 3

# ---------------------------------------------------------------------------
# Capability constants — granted by orink at exec() time from the package
# manifest's `permissions` block, and shown to the user at install time.
# ---------------------------------------------------------------------------

CAP_NONE = "cap:none"
CAP_PROC_READ = "cap:proc.read"           # enumerate/inspect processes
CAP_PROC_SIGNAL = "cap:proc.signal"        # signal processes
CAP_PROC_NICE = "cap:proc.nice"            # change scheduling priority
CAP_NET_READ = "cap:net.read"              # read interface/socket state
CAP_NET_ADMIN = "cap:net.admin"            # change interface/route/firewall
CAP_FS_USER = "cap:fs.user"                # read/write caller's own files
CAP_FS_ALL = "cap:fs.all"                  # read/write outside caller's home
CAP_DEV_BLOCK = "cap:dev.block"            # raw block device access
CAP_SERVICE_READ = "cap:service.read"
CAP_SERVICE_ADMIN = "cap:service.admin"
CAP_SYS_LOG = "cap:sys.log"
CAP_SYS_ADMIN = "cap:sys.admin"
CAP_KEYRING = "cap:keyring"
CAP_CAPTURE = "cap:capture"                # screenshot / screen recording
CAP_MEDIA = "cap:media"

ALL_CAPS = sorted(
    v for k, v in list(globals().items()) if k.startswith("CAP_") and isinstance(v, str)
)


class OKIPermissionError(PermissionError):
    """Raised when a call is denied by the capability broker."""

    def __init__(self, cap: str, call: str, hint: str = ""):
        self.cap = cap
        self.call = call
        self.hint = hint
        msg = f"OKI: call '{call}' requires {cap} which is not granted to this process"
        if hint:
            msg += f"\n     hint: {hint}"
        super().__init__(msg)


class OKIError(RuntimeError):
    """Generic OKI failure (kernel-side)."""


def get_abi():
    """Return the active OKI implementation (module-like object)."""
    forced = os.environ.get("ORIN_ABI", "").strip().lower()
    if forced == "native":
        from . import native as impl
        return impl
    if forced == "linuxabi":
        from . import linuxabi as impl
        return impl
    if os.path.exists("/dev/oki"):
        from . import native as impl
        return impl
    from . import linuxabi as impl
    return impl


def abi_name() -> str:
    return get_abi().ABI_NAME
