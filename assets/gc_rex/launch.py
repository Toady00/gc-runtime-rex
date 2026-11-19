"""Run inside a Rex terminal, consume a private hand-off, then replace ourselves."""

import json
import os
from pathlib import Path
import socket
import sys


def overlay(base, updates):
    env = dict(base)
    for key, value in updates.items():
        if value:
            env[key] = value
        else:
            env.pop(key, None)
    return env


def publish_receipt(path, receipt):
    tmp = path.with_suffix(".receipt.tmp")
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as handle:
        json.dump(receipt, handle)
    tmp.replace(path.with_suffix(".receipt"))


def launch(path, expected_session):
    path = Path(path)
    # Rex sets these values itself. The receipt must not depend on session env.
    receipt = {"session_id": os.environ["REX_SESSION"], "block_id": os.environ["REX_BLOCK"],
               "pid": os.getpid(), "ready": False}
    if receipt["session_id"] != expected_session:
        raise ValueError("launcher identity mismatch")
    try:
        with path.open("rb") as handle:
            cfg = json.load(handle)
            path.unlink()
        if os.geteuid() != cfg["uid"] or socket.gethostname() != cfg["host"]:
            raise ValueError("launcher must run on the caller's host and as its user")
        os.chdir(cfg["work_dir"])
        env = overlay(os.environ, cfg["env"])
    except (OSError, ValueError, KeyError):
        # A late launch after cancellation still identifies its block to stop.
        publish_receipt(path, receipt)
        raise
    publish_receipt(path, dict(receipt, ready=True))
    argv = ["/bin/sh", "-c", cfg["command"]] if cfg["command"] else ["/bin/sh", "-i"]
    os.execve(argv[0], argv, env)


if __name__ == "__main__":
    try:
        launch(sys.argv[1], sys.argv[2])
    except (OSError, ValueError, KeyError):
        sys.exit("Rex launch hand-off failed")
