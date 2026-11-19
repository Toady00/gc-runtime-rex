"""Rex revision 18 CLI transport. Addresses are always full server-issued IDs."""

import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

from .support import Absent, Failure, Unconfirmed


# Batched reads use one attached connection. Never cache the server instance
# across calls. Rex's Lua bridge drops null fields and sends empty arrays
# back as objects, so give the process's explicit null a wire sentinel.
INSPECT = """
local a = rex.args
local s = rex.call("server.status", {})
if not s or not s.instance_id then return {error="server.status"} end
if s.instance_id ~= a.instance then return {gone=true} end
local function read(method)
    return rex.call("block.method", {session_id=a.session_id, block_id=a.block_id, method=method})
end
local function failed(method, err)
    -- Rex reports missing blocks/sessions as typed errors in this string.
    if err and (err:match(" code=not_found%)$") or err:match(" code=session_not_found%)$")) then
        return {gone=true}
    end
    return {error=method}
end
local function process()
    local p, err = read("process")
    if not p then return nil, failed("process", err) end
    if not p.last_exit then
        if not p.child or not p.child.pid or p.child.pid <= 0 then return nil, {error="child PID"} end
        if p.child.pid ~= a.pid then return nil, {gone=true} end
        p.last_exit = false
    end
    return p
end
local p, err = process()
if not p then return err end
local result = {instance_id=s.instance_id, process=p}
for _, method in ipairs(a.methods) do
    local value, err = read(method)
    if not value then return failed(method, err) end
    result[method] = value
end
if result.program_status then
    -- A dying program can leave its final OSC root on screen. Sample exit
    -- after the root too, without reading that root on an unverified block.
    p, err = process()
    if not p then return err end
    result.process = p
end
return result
"""


class Rejected(Failure):
    """Rex rejected the operation before applying it."""


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
            raise Rejected("Rex executable missing or not executable; set GC_REX_BIN")
        try:
            st = self.socket.stat()
        except FileNotFoundError:
            raise Rejected("local Rex server socket is unavailable") from None
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.geteuid():
            raise Rejected("Rex socket must be a Unix socket owned by the runtime user")
        code, output, error = self.budget.run(
            [str(self.binary), "--autostart=false", "--timeout=2s", *args], data=data,
            creating=creating, env=self.env, limit=3, capture_error=True,
        )
        if code == 3:
            raise Absent()
        if code == 4:
            raise Rejected("local Rex server is unavailable (CLI exit 4)")
        if code != 0:
            # Rex errors can echo request text. Do not copy them into gc logs.
            # Only explicit server rejection (or CLI usage failure) proves
            # that the request did not run. EOF and lost responses do not.
            rejected = code == 2 or re.search(rb"status=4\d\d code=[a-z_]+", error or b"")
            failure = Rejected if rejected else Unconfirmed
            raise failure(f"Rex {args[2] if args[:2] == ('api', 'call') else args[0]} failed (CLI exit {code})")
        return output

    def api(self, rpc, *, creating=False, **params):
        out = self.cli("api", "call", rpc, "-", data=encode(params), creating=creating)
        return json.loads(out)

    def process(self, target):
        return self.method(target, "process")

    def inspect(self, target, instance, pid, *methods):
        args = dict(target, instance=instance, pid=pid, methods=methods)
        reply = json.loads(self.cli("do", "-s", target["session_id"], "--json", "-e", INSPECT,
                                    "--args", "-", data=encode(args)))
        if reply.get("gone") is True:
            raise Absent()
        if "error" in reply:
            detail = reply["error"]
            if detail not in {"server.status", "process", "child PID", *methods}:
                detail = "unknown read"
            raise Failure(f"Rex observation failed: {detail}")
        if reply["instance_id"] != instance:
            raise Absent()
        process = reply["process"]
        if process["last_exit"] is False:
            if process["child"]["pid"] != pid:
                raise Absent()
            process["last_exit"] = None
        elif not isinstance(process["last_exit"], dict):
            raise Failure("Rex observation omitted the process liveness discriminator")
        if "size" in reply:
            reply["size"].setdefault("owner", None)
            if reply["size"].get("desired") == {}:
                reply["size"]["desired"] = []
        if "program_status" in reply and reply["program_status"].get("records") == {}:
            reply["program_status"]["records"] = []
        return reply

    def instance(self):
        return str(uuid.UUID(self.api("server.status")["instance_id"]))

    def method(self, target, method, **args):
        return self.api("block.method", **target, method=method, args=args)

    def capture(self, target):
        return self.cli("capture", "-s", target["session_id"], "-b", target["block_id"])

    def keys(self, target, keys):
        from .terminal import key_payload

        for key in keys:
            self.api("block.event", **target, event={"type": "key", "payload": key_payload(key)})

    def paste(self, target, text):
        self.api("block.event", **target, event={"type": "paste", "payload": {"text": text}})

    def snapshot(self, target, *methods):
        return {method: self.method(target, method) for method in methods}


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
