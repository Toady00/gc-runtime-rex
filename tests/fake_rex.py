#!/usr/bin/env python3
"""Small Rex CLI double. The socket pathname locates its fixture directory."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.parse import unquote, urlparse
import uuid


def save(path, data):
    tmp = path.with_name(path.name + "." + str(os.getpid()))
    tmp.write_text(json.dumps(data))
    tmp.replace(path)


def launcher(path, session, block, delay, pipe_kind):
    receipt = {"session_id": session, "block_id": block, "pid": 101, "ready": False}
    time.sleep(float(delay))
    if pipe_kind == "regular":
        path.touch(mode=0o600)
    else:
        os.mkfifo(path, 0o600)
        if pipe_kind == "shared":
            path.chmod(0o666)
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        save(path.with_suffix(".receipt"), receipt)
        raw = bytearray()
        for _ in range(300):
            try:
                data = os.read(fd, 65536)
                if not data:
                    if raw or not path.exists():
                        return 0
                    time.sleep(0.01)
                    continue
                raw.extend(data)
            except BlockingIOError:
                time.sleep(0.01)
            if raw.endswith(b"\n"):
                assert isinstance(json.loads(raw)["env"], dict)
                save(path.with_suffix(".receipt"), dict(receipt, ready=True))
                return 0
    finally:
        os.close(fd)
        path.unlink(missing_ok=True)
    return 1


def block_read(live, method):
    if method == "process":
        result = {"last_exit": live.get("exit"), "child": {"pid": live.get("pid", 101), "name": live.get("image", "test-agent")}}
        if "path" in live:
            result["child"]["path"] = live["path"]
        if "foreground" in live:
            result["foreground"] = live["foreground"]
        return result
    if method == "program_status":
        return {"records": live.get("program_status", [])}
    if method == "size":
        return live.get("size", {"owner": None, "desired": []})
    raise AssertionError(method)


def main():
    argv = sys.argv[1:]
    if argv[0] == "launch":
        return launcher(Path(argv[1]), *argv[2:])
    assert argv.pop(0) == "--autostart=false"
    assert argv.pop(0) == "--timeout=2s"
    assert os.environ["REX_AUTOSTART"] == "0"
    assert "REX_BLOCK" not in os.environ and "GC_INSTANCE_TOKEN" not in os.environ
    endpoint = urlparse(os.environ["REX_SERVER"])
    assert endpoint.scheme == "unix" and not endpoint.netloc
    root = Path(unquote(endpoint.path)).parent
    args = json.load(sys.stdin) if argv[-1] == "-" else {}
    with (root / "calls").open("a") as handle:
        handle.write(json.dumps([argv, args]) + "\n")
    fixture = root / "backend.json"
    state = json.loads(fixture.read_text()) if fixture.exists() else {"blocks": {}}
    if state.get("error"):
        return state["error"]
    if state.get("hang"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        (root / "pid").write_text(str(os.getpid()))
        time.sleep(20)
    method = argv[2] if argv[:2] == ["api", "call"] else argv[0]
    block = args.get("block_id")
    if method in ("capture", "send-key"):
        block = argv[argv.index("-b") + 1]
    if method == "block.close" and state.get("close_delay"):
        time.sleep(state["close_delay"])
    if (state.get("method_error") or {}).get(method):
        return state["method_error"][method]
    if method == "do" and state.get("do_gate"):
        # Hold the caller's first read until the test has changed its state.
        (root / "do_entered").touch()
        until = time.monotonic() + 20
        while not (root / "do_release").exists():
            if time.monotonic() > until:
                return 1  # Never answer from the state read before the gate.
            time.sleep(0.01)
    # A script attached to a live session reads a typed error for a block
    # that is gone. Everything else, including a missing session, exits 3.
    if method == "do" and args["session_id"] != state.get("session_id"):
        return 3
    if block and block not in state["blocks"] and method != "do":
        return 3
    live = state["blocks"].get(block)
    result = {}
    dirty = False
    instance = state.get("instance_id", "00000000-0000-0000-0000-000000000001")
    if method == "do":
        assert argv[1:4] == ["-s", args["session_id"], "--json"]
        if args["instance"] != instance:
            result = {"gone": True}
        elif live is None:
            result = {"gone": True, "missing": True}
        else:
            process = block_read(live, "process")
            if process["last_exit"] is None:
                process["last_exit"] = False
                if process["child"]["pid"] != args["pid"]:
                    print('{"gone":true}')
                    return 0
            result = {"instance_id": instance, "process": process}
            for field in args["methods"]:
                result[field] = {k: ({} if v == [] else v) for k, v in block_read(live, field).items() if v is not None}
        if state.get("restart_after_do"):
            # The server restarts after this read and restores the layout.
            state["restart_after_do"] -= 1
            if not state["restart_after_do"]:
                state["instance_id"] = "00000000-0000-0000-0000-000000000009"
            dirty = True
    elif method == "server.status":
        result = {"instance_id": instance}
    elif method == "session.list":
        result = {"sessions": []}
    elif method == "session.create":
        state["session_id"] = result["session_id"] = f"session:{uuid.uuid4()}"
        dirty = True
    elif method == "session.list_blocks":
        if state.get("session_id") != args["session_id"]:
            return 3
        result = {"blocks": list(state["blocks"])}
    elif method == "session.new_window":
        assert args["session_id"] == state["session_id"] and args["focus"] is False
        if state.get("lose_city"):
            state.pop("lose_city")
            state.pop("session_id")
            save(fixture, state)
            return 3
        if state.get("create_error"):
            print("test request rejected (status=400 code=bad_request)", file=sys.stderr)
            return state["create_error"]
        if state.get("lost_create_without_launcher"):
            print("unexpected EOF", file=sys.stderr)
            return 1
        options = args["layout"]["block"]["options"]
        assert options["shell"] == "none" and options["login"] is False
        assert options["exit"] == {"on_completion": False}
        handoff = Path(options["command"][-3])
        assert not handoff.exists()
        block = f"block:{uuid.uuid4()}"
        reported = f"block:{uuid.uuid4()}" if state.get("receipt_mismatch") else block
        subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()), "launch", str(handoff),
                           state["session_id"], reported, str(state.get("receipt_delay", 0)),
                           state.get("pipe_kind", "private")],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        state["blocks"][block] = dict(state.get("new_block", {}))
        if "boot_seconds" in state["blocks"][block]:
            state["blocks"][block]["ready_at"] = time.time() + state["blocks"][block]["boot_seconds"]
        if state.get("lose_reply"):
            save(fixture, state)
            print("unexpected EOF", file=sys.stderr)
            return 1
        dirty = True
        result = {"block_ids": [block], "window_id": f"window:{uuid.uuid4()}"}
    elif method == "block.close":
        if state.get("lose_close_reply"):
            print("unexpected EOF", file=sys.stderr)
            return 1
        del state["blocks"][block]
        if state.get("auto_empty") and not state["blocks"]:
            state.pop("session_id", None)
        dirty = True
    elif method == "block.method":
        fn = args["method"]
        if fn in ("process", "program_status", "size"):
            result = block_read(live, fn)
        elif fn == "modes":
            result = {"modes": [{"number": 2004, "set": live.get("bracketed", True) and
                                 time.time() >= live.get("ready_at", 0)}]}
        elif fn == "input_mode":
            result = {"canonical": live.get("canonical", False) or time.time() < live.get("ready_at", 0)}
        elif fn == "clear":
            live["screen"] = "\n"
            dirty = True
        else:
            raise AssertionError(fn)
    elif method == "session.list_clients":
        result = {"clients": state.get("clients", [])}
    elif method == "capture":
        time.sleep(live.get("capture_delay", 0))
        if live.get("track_first_capture") and "first_capture" not in live:
            live["first_capture"] = time.time()
            save(fixture, state)
        sys.stdout.write(live.get("screen", "one\ntwo\nprompt> \n"))
        return 0
    elif method == "block.event":
        payload = args["event"]["payload"]
        if args["event"]["type"] == "paste":
            if live.get("reject"):
                print("test request rejected (status=400 code=bad_request)", file=sys.stderr)
                return 1
            if live.get("lose_paste_reply"):
                print("unexpected EOF", file=sys.stderr)
                return 1
            live.setdefault("paste", []).append(payload["text"])
            live["pasted_at"] = time.time()
            if "post_paste_screen" in live:
                live["screen"] = live["post_paste_screen"]
        else:
            live.setdefault("keys", []).append(payload)
            live["key_at"] = time.time()
            if payload["key"] == "enter" and live.get("lose_submit_reply"):
                save(fixture, state)
                print("unexpected EOF", file=sys.stderr)
                return 1
            if payload["key"] == "enter" and "screen_after_explicit_enter" in live:
                live["screen"] = live.pop("screen_after_explicit_enter")
                live.pop("post_paste_screen", None)
        dirty = True
    else:
        raise AssertionError(method)
    if dirty:
        save(fixture, state)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
