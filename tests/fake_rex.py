#!/usr/bin/env python3
"""Small Rex CLI double. The socket pathname locates its fixture directory."""

import json
import os
from pathlib import Path
import signal
import sys
import time
from urllib.parse import unquote, urlparse
import uuid


def save(path, data):
    path.write_text(json.dumps(data))


def main():
    argv = sys.argv[1:]
    assert argv.pop(0) == "--autostart=false"
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
    if block and block not in state["blocks"]:
        return 3
    live = state["blocks"].get(block)
    result = {}
    if method == "session.list":
        result = {"sessions": []}
    elif method == "session.create":
        state["session_id"] = result["session_id"] = f"session:{uuid.uuid4()}"
    elif method == "session.list_blocks":
        if state.get("session_id") != args["session_id"]:
            return 3
        result = {"blocks": list(state["blocks"])}
    elif method == "session.new_window":
        assert args["session_id"] == state["session_id"] and args["focus"] is False
        options = args["layout"]["block"]["options"]
        assert options["shell"] == "none" and options["login"] is False
        assert options["exit"] == {"on_completion": False}
        handoff = Path(options["command"][-2])
        assert handoff.stat().st_mode & 0o777 == 0o600
        cfg = json.loads(handoff.read_text())
        assert not any(value and value in json.dumps(args) for key, value in cfg["env"].items()
                       if key.startswith("SECRET"))
        handoff.unlink()
        block = f"block:{uuid.uuid4()}"
        save(handoff.with_suffix(".receipt"), {"session_id": state["session_id"], "block_id": block,
                                               "pid": 101, "ready": True})
        state["blocks"][block] = {}
        result = {"block_ids": [block], "window_id": f"window:{uuid.uuid4()}"}
    elif method == "block.close":
        del state["blocks"][block]
    elif method == "block.method":
        fn = args["method"]
        if fn == "process":
            result = {"last_exit": live.get("exit"), "child": {"pid": 101, "name": live.get("image", "test-agent")}}
        elif fn == "program_status":
            result = {"records": live.get("program_status", [])}
        elif fn == "modes":
            result = {"modes": [{"number": 2004, "set": live.get("bracketed", True)}]}
        elif fn == "input_mode":
            result = {"canonical": live.get("canonical", False)}
        elif fn == "size":
            result = live.get("size", {"owner": None, "desired": []})
        elif fn == "clear":
            live["screen"] = "\n"
        else:
            raise AssertionError(fn)
    elif method == "session.list_clients":
        result = {"clients": state.get("clients", [])}
    elif method == "capture":
        sys.stdout.write(live.get("screen", "one\ntwo\nprompt> \n"))
        return 0
    elif method == "block.event":
        if live.get("reject"):
            return 1
        live.setdefault("paste", []).append(args["event"]["payload"]["text"])
    elif method == "send-key":
        live.setdefault("keys", []).extend(argv[argv.index("--") + 1:])
    else:
        raise AssertionError(method)
    save(fixture, state)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
