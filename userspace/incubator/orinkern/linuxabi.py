"""
orinkern.linuxabi — Linux ABI compatibility shim for OKI
========================================================

Implements the Orin Kernel Interface on top of a Linux host. Used for:
  * porting / bring-up before orink is available
  * CI and the reference test-suite
  * running Orin user-space inside a plain Linux container

Every function mirrors the native OKI signature 1:1, so switching
``ORIN_ABI=native`` requires no user-space changes.

Capability enforcement is real even in shim mode: the shim reads the grant
set from ``ORIN_CAPS`` (colon-separated) or from the process credential
record created by ``orink`` at exec time. Ungranted calls raise
OKIPermissionError exactly as the kernel would.
"""

from __future__ import annotations

import os
import time

from . import (
    ALL_CAPS,
    OKI_ABI_VERSION,
    OKIPermissionError,
    get_abi,
)
from . import info, proc, net, storage, log, audit

ABI_NAME = "linuxabi"

# ---------------------------------------------------------------------------
# Capability broker (shim implementation)
# ---------------------------------------------------------------------------

_ROOT_ENV = "ORIN_RUN_AS_ROOT"


def caps() -> set[str]:
    """Return the capability set granted to *this* process by orink.

    Native: read from the process credential blob (oki_getcaps).
    Shim:   ORIN_CAPS env, default = all caps for uid 0, fs.user + proc.read
            + net.read for everybody else (the "ordinary app" baseline).
    """
    raw = os.environ.get("ORIN_CAPS")
    if raw is not None:
        if raw.strip() in ("", "*"):
            return set() if raw.strip() == "" else set(ALL_CAPS)
        return {c.strip() for c in raw.split(":") if c.strip()}
    if os.geteuid() == 0 or os.environ.get(_ROOT_ENV) == "1":
        return set(ALL_CAPS)
    return {"cap:fs.user", "cap:proc.read", "cap:net.read", "cap:service.read",
            "cap:sys.log", "cap:media"}


def have(cap: str) -> bool:
    return cap in caps()


def require(cap: str, call: str, hint: str = "") -> None:
    if not have(cap):
        raise OKIPermissionError(cap, call, hint)


def abi_info() -> dict:
    return {
        "oki_abi_version": OKI_ABI_VERSION,
        "abi": ABI_NAME,
        "kernel": info.kernel_version(),
        "native": False,
        "caps_granted": sorted(caps()),
    }


# ---------------------------------------------------------------------------
# Re-exports: this module *is* the OKI surface for user-space.
# ---------------------------------------------------------------------------

host_info = info.host_info
kernel_version = info.kernel_version
cpu_info = info.cpu_info
mem_info = info.mem_info
battery_info = info.battery_info
temp_info = info.temp_info
gpu_info = info.gpu_info
uptime = info.uptime

proc_list = proc.proc_list
proc_get = proc.proc_get
proc_signal = proc.proc_signal
proc_nice = proc.proc_nice
proc_tree = proc.proc_tree

svc_list = proc.svc_list
svc_state = proc.svc_state
svc_action = proc.svc_action

net_ifaces = net.net_ifaces
net_routes = net.net_routes
net_sockets = net.net_sockets
net_wifi = net.net_wifi
net_dns = net.net_dns

blk_list = storage.blk_list
blk_smart = storage.blk_smart
mnt_list = storage.mnt_list
fs_usage = storage.fs_usage

log_query = log.log_query
log_units = log.log_units

audit_write = audit.audit_write
audit_query = audit.audit_query

__all__ = [
    "ABI_NAME", "caps", "have", "require", "abi_info",
    "host_info", "kernel_version", "cpu_info", "mem_info", "battery_info",
    "temp_info", "gpu_info", "uptime",
    "proc_list", "proc_get", "proc_signal", "proc_nice", "proc_tree",
    "svc_list", "svc_state", "svc_action",
    "net_ifaces", "net_routes", "net_sockets", "net_wifi", "net_dns",
    "blk_list", "blk_smart", "mnt_list", "fs_usage",
    "log_query", "log_units", "audit_write", "audit_query",
    "OKIPermissionError", "ALL_CAPS", "get_abi", "time",
]
