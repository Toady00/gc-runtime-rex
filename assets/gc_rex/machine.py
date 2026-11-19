"""Stable local machine identity, shared by the controller and launcher."""

import ctypes
import os
from pathlib import Path
import sys
import uuid


def machine_id():
    if sys.platform == "darwin":
        try:
            # gethostuuid(3) takes a 16-byte output and a struct timespec.
            result = (ctypes.c_ubyte * 16)()
            timeout = (ctypes.c_long * 2)(0, 250_000_000)
            lib = ctypes.CDLL(None)
            if lib.gethostuuid(result, timeout) == 0 and any(result):
                return uuid.UUID(bytes=bytes(result)).hex
        except (AttributeError, OSError):
            pass
    else:
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                return uuid.UUID(Path(path).read_text(encoding="ascii").strip()).hex
            except (FileNotFoundError, ValueError):
                continue
    # An operator-assigned ID must be stable and distinct for each host.
    override = os.environ.get("GC_REX_MACHINE_ID")
    if override:
        return uuid.UUID(override).hex
    raise ValueError("stable machine ID unavailable; set GC_REX_MACHINE_ID")
