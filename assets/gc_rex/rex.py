"""Rex revision 18 CLI transport. Addresses are always full server-issued IDs."""

import json
import os
from pathlib import Path
import re
import stat
import sys

from .support import Absent, Failure


def object_id(value, kind):
    if not isinstance(value, str) or not re.fullmatch(
        kind + r":[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value,
    ):
        raise Failure("invalid Rex object ID")
    return value


class Rex:
    def __init__(self, home, budget):
        self.budget = budget
        support = home / "Library/Application Support"
        install = support / ("com.superlogical.rex/RexServer/Versions/Current/"
                             "Rex Server.app/Contents/MacOS/rex")
        default_socket = (support / "rex/server.sock" if sys.platform == "darwin"
                          else home / ".local/state/rex/server.sock")
        self.binary = Path(os.environ.get("GC_REX_BIN") or install)
        sock = Path(os.environ.get("GC_REX_SOCKET") or default_socket)
        if not sock.is_absolute() or not self.binary.is_absolute():
            raise Failure("GC_REX_BIN and GC_REX_SOCKET must be absolute local paths")
        self.socket = sock.resolve()
        # Deliberately ignore discovery, client, remote host, and session variables.
        self.env = {
            "HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "REX_AUTOSTART": "0", "REX_SERVER": self.socket.as_uri().replace("file:", "unix:", 1),
        }

    def cli(self, *args, data=None, creating=False):
        if not self.binary.is_file() or not os.access(self.binary, os.X_OK):
            raise Failure("Rex executable missing or not executable; set GC_REX_BIN")
        try:
            st = self.socket.stat()
        except FileNotFoundError:
            raise Failure("local Rex server socket is unavailable") from None
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.geteuid():
            raise Failure("Rex socket must be a Unix socket owned by the runtime user")
        code, output = self.budget.run(
            [str(self.binary), "--autostart=false", *args], data=data,
            creating=creating, env=self.env,
        )
        if code == 3:
            raise Absent()
        if code == 4:
            raise Failure("local Rex server is unavailable (CLI exit 4)")
        if code != 0:
            # Rex errors can echo request text. Do not copy them into gc logs.
            raise Failure(f"Rex {args[0]} failed (CLI exit {code})")
        return output

    def api(self, rpc, *, creating=False, **params):
        out = self.cli("api", "call", rpc, "-", data=encode(params), creating=creating)
        return json.loads(out)

    def process(self, target):
        return self.method(target, "process")

    def method(self, target, method, **args):
        return self.api("block.method", **target, method=method, args=args)

    def capture(self, target):
        return self.cli("capture", "-s", target["session_id"], "-b", target["block_id"])

    def keys(self, target, keys):
        self.cli("send-key", "-s", target["session_id"], "-b", target["block_id"], "--", *keys)

    def paste(self, target, text):
        self.api("block.event", **target, event={"type": "paste", "payload": {"text": text}})

    def snapshot(self, target, *methods):
        # rex do converts JSON nulls to missing Lua fields. Keep the direct
        # reply so a missing last_exit is distinguishable from a live process.
        return {method: self.method(target, method) for method in methods}


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
