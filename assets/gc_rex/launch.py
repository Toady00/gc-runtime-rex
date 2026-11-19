"""Consume a one-use launch pipe inside Rex, then replace the launcher."""

import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

if __package__:
    from .machine import machine_id
else:
    # The absolute launcher is executed with Python's isolated mode.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from machine import machine_id


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


def receive(path, receipt):
    # The terminal creates and expires the pipe. A controller killed before
    # its create RPC leaves no pipe, and one killed after create leaves no
    # writer. Neither case puts the configuration on the filesystem.
    os.mkfifo(path, 0o600)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISFIFO(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise ValueError("invalid launch pipe")
        publish_receipt(path, receipt)
        deadline = time.monotonic() + 5
        data = bytearray()
        while time.monotonic() < deadline:
            try:
                part = os.read(fd, 65536)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            if not part:
                if data or not path.exists():
                    break  # A partial writer left, or stop removed the pipe.
                time.sleep(0.01)  # The controller has not opened the writer yet.
                continue
            data.extend(part)
            if data.endswith(b"\n"):
                return json.loads(data)
        raise ValueError("launch pipe closed before configuration arrived")
    finally:
        os.close(fd)
        path.unlink(missing_ok=True)


def launch(path, expected_session, expected_host):
    path = Path(path)
    receipt = {"session_id": os.environ["REX_SESSION"], "block_id": os.environ["REX_BLOCK"],
               "pid": os.getpid(), "ready": False}
    if receipt["session_id"] != expected_session:
        raise ValueError("launcher session mismatch")
    cfg = receive(path, receipt)
    # The override is only a fallback for hosts that have no machine UUID.
    if cfg.get("machine_override"):
        os.environ["GC_REX_MACHINE_ID"] = cfg["machine_override"]
    if os.geteuid() != cfg["uid"] or machine_id() != expected_host:
        raise ValueError("launcher must run on the caller's host and as its user")
    os.chdir(cfg["work_dir"])
    env = overlay(os.environ, cfg["env"])
    if cfg.get("strip_rex_env"):
        env = {key: value for key, value in env.items() if not key.startswith("REX_")}
    publish_receipt(path, dict(receipt, ready=True))
    argv = ["/bin/sh", "-c", cfg["command"]] if cfg["command"] else ["/bin/sh", "-i"]
    # Match subprocess's restore_signals: exec preserves ignored signals.
    for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), signal.SIG_DFL)
    os.execve(argv[0], argv, env)


if __name__ == "__main__":
    try:
        launch(*sys.argv[1:])
    except (OSError, ValueError, KeyError):
        sys.exit("Rex launch hand-off failed")
