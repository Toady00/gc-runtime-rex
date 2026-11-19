"""Gas City RPP dispatch and lifecycle for the Rex carrier."""

import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import uuid

from . import staging, terminal
from .launch import PIPE_WAIT
from .rex import Rejected, Rex, encode, object_id
from .support import Absent, Budget, Cancelled, Deadline, Failure, Store, Unconfirmed, atomic_json, read_json


IDENTITY = ("GC_SESSION_ID", "GC_RUNTIME_EPOCH", "GC_INSTANCE_TOKEN", "GT_PROCESS_NAMES")
DRIVING = {"nudge", "send-keys", "interrupt", "clear-scrollback"}
OBSERVERS = {"get-meta", "is-running", "process-alive", "peek", "get-last-activity", "is-attached", "program-status"}
STARTUP_NOTE = "GC_STARTUP_DELIVERY_UNCONFIRMED"
PASTE_SETTLE = 0.5
READY_SETTLE = 0.4
# A late launch can spend a CLI timeout in flight, then wait for the pipe.
ORPHAN_GRACE = PIPE_WAIT + 3
ACTIVITY_SAMPLE = 2.0
ARITY = {
    **dict.fromkeys(("start", "stop", "is-running", "nudge", "interrupt", "clear-scrollback",
                     "get-last-activity", "is-attached", "program-status", "process-alive", "list-running"), 1),
    **dict.fromkeys(("peek", "set-meta", "get-meta", "remove-meta"), 2),
    "copy-to": 3,
}


class PendingChoice(Failure):
    """A dialog vetoed input before submission was attempted."""


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


def check_launch_pipe(fd):
    st = os.fstat(fd)
    if not stat.S_ISFIFO(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise Failure("Rex launcher did not provide a private launch pipe")


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

    def city_id(self, instance):
        path = self.store.root / "city.json"
        with self.store.lock("city"):
            row = self.read_row(path)
            if row and row.get("instance") == instance:
                sid = object_id(row["session_id"], "session")
                try:
                    self.rex.api("session.list_blocks", session_id=sid)
                    return sid
                except Absent:
                    path.unlink()
            try:
                result = self.rex.api("session.create", creating=True, label=("GC " + self.store.label)[:128])
            except Unconfirmed:
                raise Failure("Rex city create unconfirmed; an empty test/city session may remain") from None
            row = {"socket": str(self.rex.socket), "instance": instance,
                   "session_id": object_id(result["session_id"], "session")}
            atomic_json(path, row)
            self.budget.remaining()
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
        for suffix in (".handoff", ".receipt", ".receipt.tmp", ".status", ".activity"):
            self.handoff(row).with_suffix(suffix).unlink(missing_ok=True)
        path.unlink(missing_ok=True)

    def stop(self, path, row):
        if not row:
            return
        self.handoff(row).unlink(missing_ok=True)
        if not row.get("block_id"):
            info = self.receipt(row)
            if not info:
                # Keep a secret-free recovery note for a receipt that arrives
                # after stop. The name itself is free and no program can start.
                atomic_json(self.handoff(row).with_suffix(".orphan"), {
                    key: row[key] for key in ("launch", "socket", "session_id", "instance")})
                path.unlink(missing_ok=True)
                return
            row = dict(row, **info)
        self.close_block(row)
        self.delete_row(path, row)

    def close_block(self, row):
        if self.rex.instance() != row["instance"]:
            return  # A restored block is not our process, even if the ID survived.
        try:
            if row.get("pid") and self.direct_process(row) is None:
                return
            self.rex.api("block.close", **target(row))
        except Absent:
            pass

    def reap_receipts(self):
        if not any(self.store.root.glob("*.orphan")):
            return
        with self.store.lock("city"):
            for path in self.store.root.glob("*.orphan"):
                try:
                    row = self.read_row(path)
                    info = self.receipt(row) if row else None
                    if info:
                        self.close_block(dict(row, **info))
                        self.delete_row(path, row)
                    elif row and time.time() - path.stat().st_mtime >= ORPHAN_GRACE:
                        # With no receipt there is no authorized ID to close.
                        self.delete_row(path, row)
                except Cancelled:
                    raise
                except (Failure, OSError, ValueError, KeyError):
                    print("Rex runtime: late window cleanup not confirmed", file=sys.stderr)

    def process(self, row):
        reading = self.observation(row)
        return reading["process"] if reading is not None else None

    def observation(self, row, *methods):
        if not row or not row.get("pid"):
            return None
        try:
            return self.rex.inspect(target(row), row["instance"], row["pid"], *methods)
        except Absent:
            return None

    def direct_process(self, row):
        try:
            process = self.rex.process(target(row))
        except Absent:
            return None
        if terminal.alive(process):
            pid = (process.get("child") or {}).get("pid")
            if type(pid) is not int or pid <= 0:
                raise Failure("Rex did not identify the block's live child process")
            if pid != row["pid"]:
                return None
        return process

    def launch(self, path, row, cfg, work):
        handoff = self.handoff(row)
        atomic_json(path, row)
        fd = None
        try:
            result = self.rex.api(
                "session.new_window", creating=True, session_id=row["session_id"], focus=False,
                window_label=row["name"][:128], layout={"block": {
                    "flavor": "com.superlogical.terminal.shell", "label": row["name"][:128],
                    "options": {"shell": "none", "login": False, "cwd": str(work),
                                "command": [sys.executable, "-I", "-S", "-B", str(Path(__file__).with_name("launch.py")),
                                            str(handoff), row["session_id"], self.store.machine],
                                "size": {"columns": 132, "rows": 50}, "exit": {"on_completion": False}},
                }},
            )
            row["block_id"] = object_id(result["block_ids"][0], "block")
            atomic_json(path, row)
            info = self.wait_receipt(row)
            if self.rex.instance() != row["instance"]:
                raise Failure("Rex restarted before launch configuration was sent")
            fd = os.open(handoff, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            check_launch_pipe(fd)
            data = memoryview(encode({"uid": os.geteuid(), "machine_override": os.environ.get("GC_REX_MACHINE_ID"),
                                      "work_dir": str(work), "command": cfg.get("command", ""), "env": cfg["env"],
                                      "strip_rex_env": os.environ.get("GC_REX_STRIP_ENV") == "1"}) + b"\n")
            while data:
                self.budget.remaining(0.75)
                try:
                    data = data[os.write(fd, data):]
                except BlockingIOError:
                    time.sleep(0.01)
            ready = self.wait_receipt(row, ready=True)
            if ready["pid"] != info["pid"]:
                raise Failure("Rex launcher PID changed during hand-off")
            row["pid"] = info["pid"]
            row["meta"] = {key: cfg["env"][key] for key in IDENTITY if key in cfg["env"]}
            if cfg.get("ready_prompt_prefix"):
                row["meta"]["GC_READY_PROMPT_PREFIX"] = cfg["ready_prompt_prefix"]
            atomic_json(path, row)
            handoff.with_suffix(".receipt").unlink(missing_ok=True)
        finally:
            if fd is not None:
                os.close(fd)
            handoff.unlink(missing_ok=True)

    def wait_receipt(self, row, *, ready=False):
        deadline = time.monotonic() + 4
        while True:
            left = self.budget.remaining(0.75)
            info = self.receipt(row)
            if info and (not ready or info.get("ready") is True):
                return info
            if time.monotonic() >= deadline:
                raise Failure("Rex launcher did not acknowledge the hand-off")
            if not terminal.alive(self.rex.process(target(row))):
                raise Failure("Rex terminal exited before consuming the launch hand-off")
            time.sleep(min(left, 0.05))

    def status(self, row, path):
        cache = self.handoff(row).with_suffix(".status")
        with self.store.lock(path.stem, family="status"):
            reading = self.observation(row, "program_status")
            if reading is None:
                raise Absent()
            current = dict(row)
            previous = read_json(cache)
            if previous:
                current["reporter"] = copy.deepcopy(previous)
            answer = terminal.status_answer(current, reading)
            if previous != current.get("reporter"):
                self.write_observation(path, row, cache, current["reporter"])
            return answer

    def write_observation(self, path, row, cache, value):
        def same_launch():
            current = read_json(path)
            return current and current.get("launch") == row["launch"]

        if same_launch():
            atomic_json(cache, value)
            if not same_launch():
                cache.unlink(missing_ok=True)

    def input_look(self, row):
        process = self.process(row)
        if process is None:
            raise Absent()
        if not terminal.alive(process):
            raise Failure("Rex program exited; input was not sent")
        block = target(row)
        screen = self.rex.capture(block)
        reports = self.rex.method(block, "program_status")
        observation = terminal.status_answer(dict(row), {"program_status": reports, "process": process})
        view = terminal.composer(screen, row["meta"].get("GC_READY_PROMPT_PREFIX", ""))
        # Only trusted reports can make startup ready; any reported root
        # that says blocked can veto input, even when attribution is unclear.
        blocked = any(not report.get("id") and report.get("state") == "blocked"
                      for report in reports["records"])
        return "blocked" if blocked else observation["state"], view

    def first_turn(self, row, path, cfg):
        text = cfg.get("nudge", "")
        if not text:
            return
        prefix = cfg.get("ready_prompt_prefix", "")
        delay = 0 if prefix else cfg.get("ready_delay_ms", 0) / 1000
        started = time.monotonic()
        deadline = min(self.budget.end - 1.2, started + (min(delay + 5, 60) if delay else 15))
        ready_since = None
        while True:
            # A readiness timeout is not a failed launch. Do not type into an
            # unproven composer just because the start budget is expiring.
            if time.monotonic() >= deadline:
                process = self.process(row)
                if not process or not terminal.alive(process):
                    raise Failure("Rex program exited before the first turn")
                return self.withhold(path, row, "readiness not confirmed before timeout")
            try:
                with self.budget.until(deadline):
                    state, view = self.input_look(row)
                    modes = (self.rex.snapshot(target(row), "modes", "input_mode")
                             if not prefix and not delay and state not in ("idle", "blocked") and
                             view.kind == "plain" else None)
            except (Deadline, Unconfirmed):
                process = self.process(row)
                if not process or not terminal.alive(process):
                    raise
                return self.withhold(path, row, "readiness timeout while observing the terminal")
            if view.kind in ("dialog", "menu") or state == "blocked":
                return self.withhold(path, row, "terminal is waiting for a dialog or menu choice")
            now = time.monotonic()
            if delay:
                ready = now >= started + delay
            elif not prefix and state == "idle":
                ready = True
            else:
                observed = view.kind == "prompt" if prefix else (
                    modes is not None and terminal.bracketed_paste(modes["modes"]) and not modes["input_mode"]["canonical"])
                ready_since = (ready_since if ready_since is not None else now) if observed else None
                ready = ready_since is not None and now - ready_since >= READY_SETTLE
            if ready and time.monotonic() < deadline:
                try:
                    self.deliver(path, row, terminal.input_text(text))
                except (Cancelled, Absent):
                    raise
                except Failure as exc:
                    # A program that exited is different from a dialog that
                    # arrived during delivery. Only the former fails start.
                    process = self.process(row)
                    if not process or not terminal.alive(process):
                        raise
                    self.withhold(path, row, str(exc))
                return
            time.sleep(max(0, min(0.2, deadline - time.monotonic())))

    def withhold(self, path, row, reason):
        row["meta"][STARTUP_NOTE] = reason
        atomic_json(path, row)
        print(f"Rex runtime: first turn not confirmed: {reason}", file=sys.stderr)

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
        self.reap_receipts()
        instance = self.rex.instance()
        row = {"name": name, "session_id": self.city_id(instance), "work_dir": str(work),
               "socket": str(self.rex.socket), "launch": uuid.uuid4().hex, "instance": instance,
               "process_names": cfg.get("process_names", []), "activity": timestamp()}
        try:
            self.budget.remaining(0.75)
            try:
                self.launch(path, row, cfg, work)
            except Absent:
                if row.get("block_id") or self.rex.instance() != instance:
                    raise
                self.delete_row(path, row)
                # The city can disappear after city_id's probe. Retry only
                # a definite not-found create and only against the same server.
                row.update(session_id=self.city_id(instance), launch=uuid.uuid4().hex)
                self.launch(path, row, cfg, work)
            self.first_turn(row, path, cfg)
            staging.setup(cfg, work, name, self.budget)
            self.budget.remaining()
        except (Rejected, Absent):
            if not row.get("block_id"):
                self.delete_row(path, row)
                raise
            self.rollback_start(path, row)
            raise
        except BaseException:
            self.rollback_start(path, row)
            raise

    def rollback_start(self, path, row):
        with self.budget.rollback():
            try:
                if path.exists() or row.get("block_id"):
                    self.stop(path, row)
            except (Failure, OSError, ValueError, KeyError):
                print("Rex runtime: rollback incomplete; see the recorded launch state", file=sys.stderr)
            finally:
                self.handoff(row).unlink(missing_ok=True)

    def deliver(self, path, row, text):
        block = target(row)
        if not text:
            return
        view = self.guard_input(row)
        pending = row.get("input_pending")
        if pending and not (pending == "unsubmitted" and view.empty):
            raise Failure("earlier nudge may have been partially delivered; inspect terminal and interrupt before retrying")
        terminal.check_paste(self.rex, block, text)
        self.budget.remaining(0.6)
        row["input_pending"] = True
        atomic_json(path, row)
        accepted = False
        try:
            for chunk in terminal.chunks(text):
                if accepted:
                    self.guard_input(row)
                self.rex.paste(block, chunk)
                accepted = True
            if self.budget.remaining() <= PASTE_SETTLE:
                raise Failure("nudge deadline prevented submit after paste")
            time.sleep(PASTE_SETTLE)
            self.guard_input(row)
            self.rex.keys(block, ["enter"])
        except PendingChoice:
            # The guard ran before Enter (or before a later paste chunk).
            # A future empty composer proves this abandoned draft is gone.
            row["input_pending"] = "unsubmitted"
            atomic_json(path, row)
            raise
        except (Rejected, Deadline):
            if not accepted:
                self.clear_pending(path, row)
            raise
        except Absent:
            if not accepted:
                self.clear_pending(path, row)
            raise Failure("Rex block disappeared during nudge; delivery is unconfirmed") from None
        self.clear_pending(path, row)
        if row["meta"].pop(STARTUP_NOTE, None) is not None:
            atomic_json(path, row)

    def guard_input(self, row):
        state, view = self.input_look(row)
        if state == "blocked" or view.kind in ("dialog", "menu"):
            raise PendingChoice("nudge withheld: terminal is waiting for a dialog or menu choice")
        return view

    def clear_pending(self, path, row):
        if row.pop("input_pending", None):
            atomic_json(path, row)

    def attachment(self, row):
        reading = self.observation(row, "size")
        if reading is None:
            raise Absent()
        size = reading["size"]
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
        cache = self.handoff(row).with_suffix(".activity")
        with self.store.lock(path.stem, family="activity"):
            observation = self.observation(row, "program_status")
            if observation is None:
                raise Absent()
            previous = read_json(cache) or {"activity": row["activity"], "sample": -ACTIVITY_SAMPLE}
            reading = dict(previous)
            # On macOS Python 3.9 monotonic origins differ across processes.
            now = time.time()
            candidates = [previous["activity"]]
            if not 0 <= now - previous["sample"] < ACTIVITY_SAMPLE:
                screen = hashlib.sha256(self.rex.capture(block)).hexdigest()
                if previous.get("screen") != screen:
                    candidates.append(timestamp())
                reading.update(screen=screen, sample=now)
            status = observation["program_status"]
            candidates.extend(r["updated_at"] for r in status["records"])
            reading["activity"] = max(candidates, key=rfc3339)
            if reading != previous:
                self.write_observation(path, row, cache, reading)
            return reading["activity"]

    def list_running(self, prefix):
        names = []
        for path in self.store.root.glob("*.json"):
            if path.name == "city.json":
                continue
            row = self.read_row(path)
            if row and row["name"].startswith(prefix):
                process = self.process(row)
                if process is not None and terminal.alive(process):
                    names.append(row["name"])
        for name in sorted(names):
            print(name)

    def dispatch(self, op, name, args):
        if op == "list-running":
            if self.store.state_exists():
                self.list_running(name)
            return
        path = self.store.slot(name)
        try:
            if op in OBSERVERS:
                row = self.read_row(path) if self.store.state_exists() else None
                self.session_op(op, name, args, path, row)
            else:
                with self.store.lock(path.stem, collision=op == "start"):
                    row = self.read_row(path)
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
            self.reap_receipts()
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
        if not row or not row.get("pid"):
            raise Absent()
        block = target(row)
        if op == "program-status":
            print(json.dumps(self.status(row, path), separators=(",", ":")))
        elif op == "is-attached":
            print(str(self.attachment(row)).lower())
        elif op == "peek":
            if self.process(row) is None:
                raise Absent()
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
                self.clear_pending(path, row)
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
    except OSError as exc:
        reason = os.strerror(exc.errno) if exc.errno is not None else type(exc).__name__
        print(f"Rex runtime: {op} failed: {reason}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Rex runtime: {op} could not parse JSON at line {exc.lineno} column {exc.colno}", file=sys.stderr)
        return 1
    except (ValueError, TypeError, KeyError, AttributeError, IndexError) as exc:
        print(f"Rex runtime: {op} has invalid arguments or malformed state ({type(exc).__name__})", file=sys.stderr)
        return 1
    return 0
