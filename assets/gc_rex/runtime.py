"""Gas City RPP dispatch and lifecycle for the Rex carrier."""

import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import sys
import time
import uuid

from . import staging, terminal
from .rex import Rex, object_id
from .support import Absent, Budget, Cancelled, Failure, Store, atomic_json, digest, read_json


IDENTITY = ("GC_SESSION_ID", "GC_RUNTIME_EPOCH", "GC_INSTANCE_TOKEN", "GT_PROCESS_NAMES")
DRIVING = {"nudge", "send-keys", "interrupt", "clear-scrollback"}
ARITY = {
    **dict.fromkeys(("start", "stop", "is-running", "nudge", "interrupt", "clear-scrollback",
                     "get-last-activity", "is-attached", "program-status", "process-alive", "list-running"), 1),
    **dict.fromkeys(("peek", "set-meta", "get-meta", "remove-meta"), 2),
    "copy-to": 3,
}


def config(data):
    cfg = json.loads(data or b"{}")
    if not isinstance(cfg, dict):
        raise Failure("start config must be a JSON object")
    for key in ("command", "work_dir", "nudge", "ready_prompt_prefix", "overlay_dir", "session_setup_script"):
        if not isinstance(cfg.get(key, ""), str):
            raise Failure(f"start config {key} must be a string")
    for key in ("process_names", "pre_start", "session_setup", "pack_overlay_dirs"):
        items = cfg.get(key, [])
        if not isinstance(items, list) or any(not isinstance(it, str) for it in items):
            raise Failure(f"start config {key} must be a list of strings")
    files = cfg.get("copy_files", [])
    if not isinstance(files, list) or any(not isinstance(it, dict) or not isinstance(it.get("src"), str)
                                          or not isinstance(it.get("rel_dst", ""), str) for it in files):
        raise Failure("invalid start config copy_files")
    env = cfg.setdefault("env", {})
    if not isinstance(env, dict) or any(not k or "=" in k or "\0" in k or not isinstance(v, str)
                                        or "\0" in v for k, v in env.items()):
        raise Failure("invalid start config env")
    delay = cfg.get("ready_delay_ms", 0)
    if type(delay) is not int or delay < 0 or type(cfg.get("fresh_only", False)) is not bool:
        raise Failure("invalid start readiness or freshness option")
    return cfg


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def rfc3339(value):
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)", value)
    if not match:
        raise Failure("Rex supplied an invalid status timestamp")
    date, fraction, zone = match.groups()
    # Python 3.9 accepts three or six fractional digits; Rex emits variable precision.
    return datetime.datetime.fromisoformat(date + "." + (fraction or "").ljust(6, "0")[:6] +
                                           ("+00:00" if zone == "Z" else zone))


def target(row):
    return {kind + "_id": object_id(row[kind + "_id"], kind) for kind in ("session", "block")}


class Runtime:
    def __init__(self, budget):
        self.budget = budget
        self.store = Store(budget)
        self.rex = Rex(self.store.home, budget)

    def read_row(self, path):
        row = read_json(path)
        if row and row["socket"] != str(self.rex.socket):
            raise Failure("state belongs to a different Rex socket; restore its configuration")
        return row

    def city_id(self):
        path = self.store.root / "city.json"
        with self.store.lock("city"):
            row = self.read_row(path)
            if row:
                if not row.get("session_id"):
                    raise Failure("earlier Rex city create has no confirmed ID; inspect before clearing city.json")
                sid = object_id(row["session_id"], "session")
                try:
                    self.rex.api("session.list_blocks", session_id=sid)
                    return sid
                except Absent:
                    path.unlink()
            # Journal the attempt before creating anything. Rex does not accept
            # a caller-supplied ID or an idempotency key for this RPC.
            # Preflight first so a missing binary/server does not journal a create.
            self.rex.api("session.list")
            row = {"socket": str(self.rex.socket)}
            atomic_json(path, row)
            result = self.rex.api("session.create", creating=True, label=("GC " + self.store.label)[:128])
            row["session_id"] = object_id(result["session_id"], "session")
            atomic_json(path, row)
            return row["session_id"]

    def handoff(self, row):
        return self.store.root / (uuid.UUID(row["launch"]).hex + ".handoff")

    def receipt(self, row):
        info = read_json(self.handoff(row).with_suffix(".receipt"))
        if info:
            target(info)
            if info["session_id"] != row["session_id"] or (
                    row.get("block_id") and info["block_id"] != row["block_id"]):
                raise Failure("Rex launcher receipt does not match creation reply")
            if type(info["pid"]) is not int or info["pid"] <= 0:
                raise Failure("invalid Rex launcher PID")
        return info

    def delete_row(self, path, row):
        for suffix in (".handoff", ".receipt", ".receipt.tmp"):
            self.handoff(row).with_suffix(suffix).unlink(missing_ok=True)
        path.unlink(missing_ok=True)

    def stop(self, path, row):
        if not row:
            return
        if not row.get("block_id"):
            # Leave a record if a reply was lost and no launcher identified
            # the block. Never guess which object to close in a shared server.
            self.handoff(row).unlink(missing_ok=True)
            info = self.receipt(row)
            if not info:
                raise Failure("Rex window creation not confirmed; ownership ID missing from reply and receipt")
            row.update(info)
            atomic_json(path, row)
        try:
            self.rex.api("block.close", **target(row))
        except Absent:
            pass
        self.delete_row(path, row)

    def process(self, row):
        if not row:
            return None
        if not row.get("block_id") or not row.get("pid"):
            raise Failure("Rex launch is incomplete; stop the recorded attempt first")
        try:
            return self.rex.process(target(row))
        except Absent:
            return None

    def launch(self, path, row, cfg, work):
        handoff = self.handoff(row)
        atomic_json(handoff, {"uid": os.geteuid(), "host": socket.gethostname(),
                              "work_dir": str(work), "command": cfg.get("command", ""),
                              "env": cfg["env"]})
        atomic_json(path, row)
        result = self.rex.api(
            "session.new_window", creating=True, session_id=row["session_id"], focus=False,
            window_label=row["name"][:128], layout={"block": {
                "flavor": "com.superlogical.terminal.shell", "label": row["name"][:128],
                "options": {"shell": "none", "login": False, "cwd": str(work),
                            "command": [sys.executable, "-I", "-S", "-B",
                                        str(Path(__file__).with_name("launch.py")), str(handoff), row["session_id"]],
                            "size": {"columns": 132, "rows": 50}, "exit": {"on_completion": False}},
            }},
        )
        row["block_id"] = object_id(result["block_ids"][0], "block")
        atomic_json(path, row)
        while True:
            left = self.budget.remaining(0.3)
            info = self.receipt(row)
            if info:
                if info.get("ready") is not True:
                    raise Failure("Rex launcher could not apply the local hand-off")
                row["pid"] = info["pid"]
                atomic_json(path, row)
                handoff.with_suffix(".receipt").unlink()
                return
            if not terminal.alive(self.rex.process(target(row))):
                raise Failure("Rex terminal exited before consuming the launch hand-off")
            time.sleep(min(left, 0.05))

    def status(self, row, path):
        if "pid" not in row:
            raise Failure("Rex launch is incomplete")
        previous = copy.deepcopy(row.get("reporter"))
        answer = terminal.status_answer(row, self.rex.snapshot(target(row), "program_status", "process"))
        if previous != row.get("reporter"):
            atomic_json(path, row)
        return answer

    def first_turn(self, row, path, cfg):
        text = terminal.input_text(cfg.get("nudge", ""))
        if not text:
            return
        prefix = cfg.get("ready_prompt_prefix", "").encode("utf-8")
        delay_ms = cfg.get("ready_delay_ms", 0)
        ready_at = time.monotonic() + (delay_ms / 1000 if delay_ms else 0.25)
        while True:
            self.budget.remaining(0.3)
            status = self.status(row, path)
            if status["exited"]:
                raise Failure("program exited before the first turn")
            if not delay_ms and status["state"] == "idle":
                break
            if prefix:
                screen = terminal.tail(self.rex.capture(target(row)), 12)
                lines = screen.split(b"\n")
                last = next((line.lstrip() for line in reversed(lines) if line.strip()), b"")
                if not status["state"] in ("working", "blocked") and (
                        last.startswith(prefix) or last == prefix.rstrip(b" ")):
                    if not delay_ms or time.monotonic() >= ready_at:
                        break
            elif time.monotonic() >= ready_at and status["state"] in ("", "idle"):
                break
            time.sleep(min(0.1, self.budget.remaining(0.3)))
        self.deliver(path, row, text)

    def start(self, name, path, old, cfg):
        if old:
            process = self.process(old)
            if process is not None and (cfg.get("fresh_only") or terminal.alive(process)):
                raise Failure("session already exists", 73)
            self.stop(path, old)
        work = Path(cfg.get("work_dir") or self.store.city)
        if not work.is_absolute():
            raise Failure("work_dir must be absolute")
        staging.prepare(cfg, work, self.store.city, self.budget)
        row = {"name": name, "session_id": self.city_id(), "work_dir": str(work),
               "socket": str(self.rex.socket), "launch": uuid.uuid4().hex,
               "process_names": cfg.get("process_names", []), "activity": timestamp(),
               "meta": {key: cfg["env"][key] for key in IDENTITY if key in cfg["env"]}}
        try:
            self.budget.remaining(0.3)
            self.launch(path, row, cfg, work)
            self.first_turn(row, path, cfg)
            staging.setup(cfg, work, name, self.budget)
            self.budget.remaining()
        except BaseException:
            with self.budget.rollback():
                try:
                    if path.exists() or row.get("block_id"):
                        self.stop(path, row)
                except (Failure, OSError, ValueError, KeyError):
                    print("Rex runtime: rollback incomplete; see the recorded launch state", file=sys.stderr)
                finally:
                    self.handoff(row).unlink(missing_ok=True)
            raise

    def deliver(self, path, row, text):
        if row.get("input_pending"):
            raise Failure("earlier nudge may have been partially delivered; inspect terminal and restart before retrying")
        block = target(row)
        terminal.check_paste(self.rex, block, text)
        if not terminal.alive(self.rex.process(block)):
            raise Absent()
        row["input_pending"] = True
        atomic_json(path, row)
        try:
            for chunk in terminal.chunks(text):
                self.rex.paste(block, chunk)
            self.rex.keys(block, ["enter"])
        except Absent:
            raise Failure("Rex block disappeared during nudge; delivery is unconfirmed") from None
        del row["input_pending"]
        atomic_json(path, row)

    def attachment(self, row):
        size = self.rex.method(target(row), "size")
        # The app subscribes to all sessions. Block ownership and per-block
        # size requests indicate interaction rather than a global subscription.
        if "owner" not in size or not isinstance(size.get("desired"), list):
            raise Failure("Rex did not report block attachment information")
        if size["owner"] is not None:
            return True
        if not size["desired"]:
            return False
        clients = self.rex.api("session.list_clients", session_id=row["session_id"])["clients"] or []
        active = {client["client_id"] for client in clients if client.get("connection_state") != "lost"}
        if any(request["client_id"] in active for request in size["desired"]):
            return True
        raise Failure("Rex reported a size requester but no matching active client")

    def activity(self, path, row):
        block = target(row)
        screen = hashlib.sha256(self.rex.capture(block)).hexdigest()
        changed = row.get("screen") != screen
        # OSC reports are output too, even if they change no visible cells.
        # Rex stamps them when received. Use the later of that time and the
        # last screen change we sampled.
        status = self.rex.method(block, "program_status")
        candidates = [row["activity"], *(r["updated_at"] for r in status["records"])]
        if changed:
            candidates.append(timestamp())
        latest = max(candidates, key=rfc3339)
        if changed or latest != row["activity"]:
            row["activity"], row["screen"] = latest, screen
            atomic_json(path, row)
        return latest

    def list_running(self, prefix):
        names = []
        for path in self.store.root.glob("*.json"):
            if path.name == "city.json":
                continue
            with self.store.lock(path.stem):
                row = self.read_row(path)
                if row and row["name"].startswith(prefix):
                    process = self.process(row)
                    if process is not None and terminal.alive(process):
                        names.append(row["name"])
        for name in sorted(names):
            print(name)

    def dispatch(self, op, name, args):
        if op == "list-running":
            self.list_running(name)
            return
        path = self.store.slot(name)
        with self.store.lock(path.stem):
            row = self.read_row(path)
            try:
                self.session_op(op, name, args, path, row)
            except Absent:
                if op in ("is-attached", "is-running", "process-alive"):
                    print("false")
                elif op == "program-status":
                    raise
                elif op in ("start", "peek", "set-meta"):
                    raise Failure("Rex terminal is gone") from None
                # Legacy driving/metadata ops are best effort on a missing name.

    def session_op(self, op, name, args, path, row):
        if op == "start":
            self.start(name, path, row, config(sys.stdin.buffer.read()))
            return
        if op == "stop":
            self.stop(path, row)
            return
        if op in ("is-running", "process-alive", "set-meta", "get-meta", "remove-meta"):
            process = self.process(row)
            if process is None:
                raise Absent()
            if op == "is-running":
                print(str(terminal.alive(process)).lower())
            elif op == "process-alive":
                names = sys.stdin.read().splitlines()
                candidates = [process.get("child"), process.get("foreground"), *(process.get("ancestors") or [])]
                live = terminal.alive(process) and (not names or any(
                    terminal.process_name(p, names) for p in candidates if p))
                print(str(live).lower())
            else:
                meta, key = row["meta"], args[0]
                if op == "get-meta":
                    sys.stdout.buffer.write(meta.get(key, "").encode("utf-8", "surrogateescape"))
                else:
                    if op == "set-meta":
                        meta[key] = sys.stdin.buffer.read().decode("utf-8", "surrogateescape")
                    else:
                        meta.pop(key, None)
                    atomic_json(path, row)
            return
        if op == "copy-to" and not os.path.lexists(args[0]):
            return
        if not row:
            raise Absent()
        if not row.get("block_id"):
            raise Failure("Rex window creation is incomplete")
        block = target(row)
        if op == "program-status":
            print(json.dumps(self.status(row, path), separators=(",", ":")))
        elif op == "is-attached":
            print(str(self.attachment(row)).lower())
        elif op == "peek":
            sys.stdout.buffer.write(terminal.tail(self.rex.capture(block), int(args[0])))
        elif op == "get-last-activity":
            print(self.activity(path, row))
        elif op == "copy-to":
            if self.process(row) is not None:
                staging.copy_entry(Path(row["work_dir"]), *args)
        elif op == "nudge":
            self.deliver(path, row, terminal.input_text(sys.stdin.buffer.read().decode("utf-8")))
        elif op in DRIVING:
            process = self.process(row)
            if not process or not terminal.alive(process):
                raise Absent()
            if op == "send-keys":
                self.rex.keys(block, [terminal.translate(key) for key in args])
            elif op == "interrupt":
                self.rex.keys(block, ["ctrl+c"])
            elif op == "clear-scrollback":
                self.rex.method(block, "clear")


def main():
    op, *args = sys.argv[1:]
    if (op != "send-keys" and len(args) != ARITY[op]) or (op == "send-keys" and len(args) < 2):
        print("Rex runtime: wrong number of operation arguments", file=sys.stderr)
        return 1
    name, *rest = args
    if (op != "list-running" and not name) or any(c in name for c in "\n\r\0"):
        print("Rex runtime: invalid session name", file=sys.stderr)
        return 1
    try:
        if op == "peek":
            int(rest[0])
        if op == "send-keys":
            for key in rest:
                terminal.translate(key)
        budget = Budget({"start": 120, "program-status": 2, "is-attached": 4}.get(op, 30))
        signal.signal(signal.SIGTERM, budget.cancel)
        Runtime(budget).dispatch(op, name, rest)
        budget.remaining()
    except Failure as exc:
        if exc.code != 66:
            print(f"Rex runtime: {exc}", file=sys.stderr)
        return exc.code
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError):
        print(f"Rex runtime: invalid {op} request or unreadable local/Rex state", file=sys.stderr)
        return 1
    return 0
