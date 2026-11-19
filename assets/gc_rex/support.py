"""Operation deadlines, child lifetime, and per-city sidecar state."""

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import tempfile
import time

from .machine import machine_id


class Failure(Exception):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


class Absent(Failure):
    def __init__(self):
        super().__init__("Rex object is gone", 66)


class Cancelled(Failure):
    def __init__(self):
        super().__init__("operation cancelled", 143)


class Unconfirmed(Failure):
    """The request may have reached the backend before the reply was lost."""


class Deadline(Failure):
    """The local budget expired before dispatch."""


class Budget:
    def __init__(self, seconds):
        ms = os.environ.get("GC_EXEC_DEADLINE_MS")
        self.end = time.monotonic() + min(seconds, max(0, int(ms)) / 1000 if ms else seconds)
        self.signal_at = None
        self.defer = False

    def cancel(self, *_):
        if self.signal_at is None:
            self.signal_at = time.monotonic()
        if not self.defer:
            raise Cancelled()

    def remaining(self, reserve=0):
        if self.signal_at is not None and not self.defer:
            raise Cancelled()
        left = self.end - time.monotonic() - reserve
        if left <= 0:
            raise Deadline("operation deadline reached")
        return left

    def run(self, argv, *, data=None, limit=5, creating=False, capture_error=False, **kwargs):
        end = time.monotonic() + min(limit, self.remaining())
        child = None
        previous = self.defer
        self.defer = True  # Do not interrupt Popen before we own the child PID.
        try:
            child = subprocess.Popen(
                argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE if capture_error else subprocess.DEVNULL,
                start_new_session=True, **kwargs,
            )
            while True:
                deadline = end
                if self.signal_at is not None and not previous:
                    if not creating:
                        raise Cancelled()
                    # Acknowledge a create already on the wire so rollback has an ID.
                    deadline = min(deadline, self.signal_at + 0.65)
                left = deadline - time.monotonic()
                if left <= 0:
                    raise Unconfirmed("child command timed out; request not confirmed")
                try:
                    output, error = child.communicate(input=data, timeout=min(0.1, left))
                    return (child.returncode, output, error) if capture_error else (child.returncode, output)
                except subprocess.TimeoutExpired:
                    data = None
        finally:
            if child is not None and child.returncode is None:
                # Kill the group even if its leader exited while a child held the pipe.
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            self.defer = previous

    @contextlib.contextmanager
    def rollback(self):
        previous = self.end, self.defer
        self.end = time.monotonic() + 0.95
        self.defer = True
        try:
            yield
        finally:
            self.end, self.defer = previous

    @contextlib.contextmanager
    def until(self, end):
        previous = self.end
        self.end = min(self.end, end)
        try:
            yield
        finally:
            self.end = previous


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def atomic_json(path, value):
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".write-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def read_json(path):
    try:
        return json.loads(path.read_bytes())
    except FileNotFoundError:
        return None


def private_dir(path, *, create=True):
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        st = path.lstat()
    except FileNotFoundError:
        if create:
            raise
        return False
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise Failure("runtime state directory must be private and owned by this user")
    return True


class Store:
    def __init__(self, budget):
        self.budget = budget
        self.home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        city = os.environ.get("GC_EXEC_CITY_PATH", "")
        if not os.path.isabs(city):
            raise Failure("GC_EXEC_CITY_PATH must be an absolute city path")
        self.city = Path(os.path.realpath(city))
        self.label = os.environ.get("GC_EXEC_CITY_NAME") or self.city.name
        root = Path(os.environ.get("GC_EXEC_STATE_DIR") or self.home / ".local/share/gc-runtime-rex")
        if not root.is_absolute():
            raise Failure("GC_EXEC_STATE_DIR must be absolute")
        try:
            self.machine = machine_id()
        except (OSError, ValueError):
            raise Failure("stable machine ID unavailable; set GC_REX_MACHINE_ID to a host UUID") from None
        self.root = root / digest(self.machine + "\0" + str(self.city))

    def slot(self, name):
        return self.root / (digest(name) + ".json")

    def state_exists(self):
        return private_dir(self.root.parent, create=False) and private_dir(self.root, create=False)

    @contextlib.contextmanager
    def lock(self, stem, *, family="name", collision=False):
        private_dir(self.root.parent)
        private_dir(self.root)
        # Only the exact name can report a lifecycle collision. Observation
        # locks can share buckets because they wait rather than report 73.
        # Never unlink a lock file while a waiter may still hold its inode.
        leaf = stem if stem == "city" else family + "-" + (stem if family == "name" else stem[:2])
        fd = os.open(self.root / (leaf + ".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if collision:
                        raise Failure("session already exists (operation in progress)", 73) from None
                    time.sleep(min(0.02, self.budget.remaining()))
            yield
        finally:
            os.close(fd)
