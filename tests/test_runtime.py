import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
ASSETS = REPO / "assets"
OP = ASSETS / "gc-runtime-rex"
sys.path.insert(0, str(ASSETS))
from gc_rex import terminal
from gc_rex.machine import machine_id
from gc_rex.runtime import ARITY, STARTUP_NOTE
from gc_rex.support import Budget, Store


class RuntimeTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="t")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        sock = self.root / "s"
        listener.bind(str(sock))  # Filesystem fixture only; the CLI double never connects.
        # Use the same interpreter as unittest, independent of the invoking shell.
        fake = self.root / "fake rex"
        fake.write_text(f"#!{sys.executable} -B\n" + (REPO / "tests/fake_rex.py").read_text().split("\n", 1)[1])
        fake.chmod(0o700)
        self.env = {"PATH": str(Path(sys.executable).parent) + ":/usr/bin:/bin",
                    "HOME": "/nonexistent", "GC_EXEC_CITY_PATH": str(self.root),
                    "GC_EXEC_STATE_DIR": str(self.root / "state"), "GC_REX_BIN": str(fake),
                    "GC_REX_SOCKET": str(sock), "REX_BLOCK": "do-not-target",
                    "GC_INSTANCE_TOKEN": "do-not-forward"}

    def op(self, *args, data=b"", code=0):
        result = subprocess.run([str(OP), *args], input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=self.env, timeout=10)
        self.assertEqual(result.returncode, code, result.stderr.decode())
        return result.stdout

    def start(self, name="box", code=0, **cfg):
        return self.op("start", name, data=json.dumps(cfg).encode(), code=code)

    def backend(self):
        return json.loads((self.root / "backend.json").read_text())

    def patch_backend(self, **changes):
        data = self.backend() if (self.root / "backend.json").exists() else {"blocks": {}}
        data.update(changes)
        (self.root / "backend.json").write_text(json.dumps(data))

    def block(self):
        return next(iter(self.backend()["blocks"].values()))

    def patch_block(self, **changes):
        data = self.backend()["blocks"]
        next(iter(data.values())).update(changes)
        self.patch_backend(blocks=data)

    def state_dir(self):
        return next(p for p in (self.root / "state").iterdir() if p.is_dir())

    def state_row(self):
        return next(p for p in self.state_dir().glob("*.json") if p.name != "city.json")

    def starting(self, cfg, budget="4300"):
        p = subprocess.Popen([str(OP), "start", "box"], env=dict(self.env, GC_EXEC_DEADLINE_MS=budget),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.stdin.write(json.dumps(cfg).encode())
        p.stdin.close()
        p.stdin = None
        self.addCleanup(self.reap, p)
        return p

    @staticmethod
    def reap(p):
        if p.poll() is None:
            p.kill()
        p.communicate(timeout=2)

    def test_handshake_needs_no_home_city_or_python(self):
        p = subprocess.run([str(OP), "protocol"], env={"PATH": "/nonexistent"}, capture_output=True, check=True)
        self.assertEqual(json.loads(p.stdout), {"version": 0, "locality": "local", "capabilities": [
            "carrier.ops", "idle-boundary", "report-activity", "report-attachment", "program-status", "fs.host"]})

    def test_unsupported_never_reads_stdin(self):
        for op in ("exec", "provision", "server-stop", "watch-startup", "attach", "unknown"):
            with self.subTest(op=op):
                with subprocess.Popen([str(OP), op, "box"], stdin=subprocess.PIPE, env=self.env) as p:
                    self.assertEqual(p.wait(timeout=2), 2)

    def test_arity_and_malformed_arguments(self):
        for op in (*ARITY, "send-keys", "protocol"):
            with self.subTest(op=op):
                self.op(op, "a", "b", "c", "d", code=1) if op != "send-keys" else self.op(op, "a", code=1)
        self.op("peek", "box", "x", code=1)
        self.op("send-keys", "box", "Enter", "unrecognised", code=1)
        self.op("start", "box", data=b'{"env":{"KEY":1}}', code=1)

    def test_absent_ops(self):
        for op in ("is-running", "is-attached", "process-alive"):
            self.assertEqual(self.op(op, "box"), b"false\n")
        for op in ("nudge", "stop", "clear-scrollback", "interrupt", "get-last-activity"):
            self.assertEqual(self.op(op, "box"), b"")
        for op in ("get-meta", "remove-meta"):
            self.assertEqual(self.op(op, "box", "key"), b"")
        self.op("send-keys", "box", "C-c")
        self.op("copy-to", "box", "/does-not-exist", "")
        self.op("set-meta", "box", "key", code=1)
        self.op("program-status", "box", code=66)
        self.op("peek", "box", "1", code=1)

    def test_lifecycle_metadata_and_listing(self):
        self.start(env={"GC_SESSION_ID": "test-id", "GC_INSTANCE_TOKEN": "token", "SECRET_MARKER": "hidden-value"})
        self.assertEqual(self.op("is-running", "box"), b"true\n")
        self.assertEqual(self.op("get-meta", "box", "GC_SESSION_ID"), b"test-id")
        value = "❯  ".encode() + b"\xff\r\n"
        self.op("set-meta", "box", "GC_READY_PROMPT_PREFIX", data=value)
        self.assertEqual(self.op("get-meta", "box", "GC_READY_PROMPT_PREFIX"), value)
        self.op("remove-meta", "box", "GC_READY_PROMPT_PREFIX")
        self.assertEqual(self.op("get-meta", "box", "GC_READY_PROMPT_PREFIX"), b"")
        self.op("set-meta", "box", "GC_READY_PROMPT_PREFIX", data=value)
        self.assertEqual(self.op("process-alive", "box", data=b"test-agent\n"), b"true\n")
        self.assertEqual(self.op("process-alive", "box", data=b"other\n"), b"false\n")
        self.assertEqual(self.op("list-running", "b"), b"box\n")
        self.assertEqual(self.op("list-running", "a"), b"")
        self.start(code=73)
        self.op("stop", "box")
        self.op("stop", "box")
        self.assertEqual([p.name for p in self.state_dir().glob("*.json")], ["city.json"])
        self.assertEqual(self.op("list-running", ""), b"")
        self.assertEqual(self.op("get-meta", "box", "GC_READY_PROMPT_PREFIX"), b"")
        self.assertNotIn("hidden-value", (self.root / "calls").read_text())

    def test_kept_dead_block_is_recycled_except_fresh_only(self):
        self.start()
        original = next(iter(self.backend()["blocks"]))
        self.patch_block(exit={"exit_code": 0})
        self.assertEqual(self.op("is-running", "box"), b"false\n")
        self.assertEqual(self.op("peek", "box", "1"), b"prompt> \n")
        self.start(code=73, fresh_only=True)
        self.assertIn(original, self.backend()["blocks"])
        self.assertEqual(self.op("list-running", ""), b"")
        self.op("nudge", "box", data=b"must not type", code=1)
        self.assertNotIn("paste", self.block())
        self.start()
        self.assertNotIn(original, self.backend()["blocks"])

    def test_process_status_roots_and_incarnations(self):
        def read():
            return json.loads(self.op("program-status", "box"))
        self.start()
        first = read()
        owner = {"pid": 101, "name": "test-agent"}
        nested = {"id": "child", "state": "working", "owner": owner}
        self.patch_block(program_status=[nested, {"state": "new-word", "owner": owner, "msg": "ignore"}])
        self.assertEqual(read(), dict(first, state="new-word"))
        self.patch_block(program_status=[nested, {"state": "idle", "owner": {"pid": 404, "name": "test-agent"}}])
        self.assertEqual(read(), first)
        self.patch_block(exit={"exit_code": 0}, program_status=[{"state": "idle", "owner": owner}])
        self.assertEqual(read(), dict(first, exited=True))
        self.start()
        self.assertNotEqual(read()["incarnation"], first["incarnation"])

    def test_program_status_retires_old_root_after_observed_exec(self):
        self.start()
        def read():
            return json.loads(self.op("program-status", "box"))
        root = {"state": "idle", "owner": {"pid": 101, "name": "test-agent"}, "updated_at": "first"}
        self.patch_block(program_status=[root])
        first = read()
        self.assertEqual(first["state"], "idle")
        # A different image can still have the same name. PID and name alone
        # match the retained report, so the retired-report check must veto it.
        self.patch_block(path="/new/image/test-agent")
        silent = read()
        self.assertEqual(silent["state"], "")
        self.assertNotEqual(silent["incarnation"], first["incarnation"])
        self.patch_block(program_status=[dict(root, updated_at="second")])
        self.assertEqual(read(), dict(silent, state="idle"))

    def test_program_status_foreground_exit_fallback(self):
        self.start(process_names=["test-agent"])
        # A child with this PID is absent, but the terminal wrapper stays up.
        pid = 2147483000
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        fg = {"pid": pid, "name": "test-agent"}
        self.patch_block(foreground=fg, program_status=[{"state": "idle", "owner": fg}])
        first = json.loads(self.op("program-status", "box"))
        self.assertEqual(first["state"], "idle")
        self.patch_block(foreground={"pid": 101, "name": "wrapper"})
        self.assertEqual(json.loads(self.op("program-status", "box")), dict(first, state="", exited=True))

    def test_attachment_owner_and_uncertainty(self):
        self.start()
        self.assertEqual(self.op("is-attached", "box"), b"false\n")
        self.patch_block(size={"owner": "client:own", "desired": []})
        self.assertEqual(self.op("is-attached", "box"), b"true\n")
        self.patch_block(size={"owner": None, "desired": [{"client_id": "client:uncertain"}]})
        self.op("is-attached", "box", code=1)
        self.patch_backend(clients=[{"client_id": "client:uncertain", "connection_state": "connected"}])
        self.assertEqual(self.op("is-attached", "box"), b"true\n")

    def test_peek_activity_clear_and_keys(self):
        self.start()
        self.assertEqual(self.op("peek", "box", "2"), b"two\nprompt> \n")
        self.assertEqual(self.op("peek", "box", "0"), b"one\ntwo\nprompt> \n")
        when = self.op("get-last-activity", "box")
        calls = (self.root / "calls").read_text().count('"capture"')
        self.assertEqual(self.op("get-last-activity", "box"), when)
        self.assertEqual((self.root / "calls").read_text().count('"capture"'), calls)
        self.op("clear-scrollback", "box")
        self.assertEqual(self.op("peek", "box", "10"), b"\n")
        cache = next(self.state_dir().glob("*.activity"))
        cache.write_text(json.dumps(dict(json.loads(cache.read_text()), sample=-10)))
        self.assertNotEqual(self.op("get-last-activity", "box"), when)
        self.op("send-keys", "box", "C-c", "M-Left", "BTab", "Y", "C-S-F2", "Enter")
        self.op("interrupt", "box")
        self.assertEqual([(key["key"], key["mods"], key["text"]) for key in self.block()["keys"]], [
            ("key_c", "ctrl", ""), ("arrow_left", "alt", ""), ("tab", "shift", ""), ("key_y", "shift", "Y"),
            ("f2", "shift+ctrl", ""), ("enter", "", ""), ("key_c", "ctrl", "")])

    def test_chunked_delivery_and_partial_failure(self):
        self.start(nudge="first turn", ready_prompt_prefix="prompt> ")
        for text in ("x" * 4096, "雪" * 34134 + "\ntail"):
            self.op("nudge", "box", data=text.encode())
        box = self.block()
        self.assertEqual("".join(box["paste"]), "first turn" + "x" * 4096 + "雪" * 34134 + "\ntail")
        self.assertTrue(all(len(chunk.encode()) <= 24576 for chunk in box["paste"]))
        self.assertEqual([key["key"] for key in box["keys"]], ["enter"] * 3)
        self.assertGreaterEqual(box["key_at"] - box["pasted_at"], 0.5)
        self.patch_block(reject=True)
        self.op("nudge", "box", data=b"definitely rejected", code=1)
        self.patch_block(reject=False)
        self.op("nudge", "box", data=b"success after rejection")
        self.patch_block(lose_paste_reply=True)
        self.op("nudge", "box", data=b"may be partial", code=1)
        self.patch_block(lose_paste_reply=False)
        self.op("nudge", "box", data=b"may be partial", code=1)
        self.assertEqual(self.block()["paste"], box["paste"] + ["success after rejection"])
        self.op("interrupt", "box")
        self.op("nudge", "box", data=b"after interrupt")
        self.assertEqual(self.block()["paste"][-1], "after interrupt")

    def test_refused_paste_does_not_latch_before_sending(self):
        self.start()
        self.patch_block(bracketed=False, canonical=True)
        self.op("nudge", "box", data=b"a\nb", code=1)
        self.op("nudge", "box", data=b"a" * 4096, code=1)
        self.op("nudge", "box", data=b"safe")
        self.assertEqual(self.block()["paste"], ["safe"])

    def test_plain_screen_timeout_withholds_turn_and_keeps_session(self):
        self.env["GC_EXEC_DEADLINE_MS"] = "3300"
        self.start(nudge="not ready", ready_prompt_prefix="never appears")
        self.assertEqual(self.op("is-running", "box"), b"true\n")
        self.assertNotIn("paste", self.block())
        self.assertIn(b"timeout", self.op("get-meta", "box", STARTUP_NOTE))
        self.assertFalse(list(self.root.glob("state/*/*.handoff")))

    def test_sigterm_rolls_back_started_window(self):
        p = subprocess.Popen([str(OP), "start", "box"], env=self.env, stdin=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        try:
            p.stdin.write(b'{"nudge":"wait","ready_prompt_prefix":"never appears"}')
            p.stdin.close()
            deadline = time.monotonic() + 5
            fixture = self.root / "backend.json"
            while time.monotonic() < deadline:
                try:
                    if fixture.exists() and self.backend()["blocks"]:
                        break
                except ValueError:
                    pass  # The CLI double writes this test fixture in place.
                time.sleep(0.02)
            else:
                self.fail("no test block appeared")
            p.send_signal(signal.SIGTERM)
            self.assertEqual(p.wait(timeout=2), 143)
            self.assertEqual(self.backend()["blocks"], {})
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            p.stderr.close()

    def test_backend_absence_vs_outage(self):
        self.start()
        self.patch_backend(error=4)
        self.op("is-running", "box", code=1)
        self.op("is-attached", "box", code=1)
        self.op("program-status", "box", code=1)
        self.op("get-meta", "box", "key", code=1)
        self.op("stop", "box", code=1)
        binary = self.env["GC_REX_BIN"]
        self.env["GC_REX_BIN"] = "/missing/rex"
        self.op("is-running", "box", code=1)
        self.env["GC_REX_BIN"] = binary
        self.patch_backend(error=0, blocks={})
        self.assertEqual(self.op("is-running", "box"), b"false\n")
        self.op("program-status", "box", code=66)
        self.op("stop", "box")

    def test_window_create_definite_failure_leaves_name_reusable(self):
        self.start("other")
        for error in (1, 3, 4):
            with self.subTest(error=error):
                self.patch_backend(create_error=error)
                self.start(code=1, env={"GC_INSTANCE_TOKEN": "must-not-persist"})
                self.assertEqual(self.op("get-meta", "box", "GC_INSTANCE_TOKEN"), b"")
                self.assertEqual(self.op("is-running", "box"), b"false\n")
                self.assertEqual(self.op("list-running", ""), b"other\n")
                self.op("stop", "box")
                self.assertFalse(list(self.state_dir().glob("*.handoff")))
                self.assertEqual(len(list(self.state_dir().glob("*.json"))), 2)
        self.patch_backend(create_error=0)
        self.start()
        self.assertEqual(self.op("list-running", ""), b"box\nother\n")

    def test_city_disappears_after_last_block_or_during_create(self):
        self.patch_backend(auto_empty=True)
        self.start()
        first = self.backend()["session_id"]
        self.op("stop", "box")
        self.assertNotIn("session_id", self.backend())
        self.start()
        second = self.backend()["session_id"]
        self.assertNotEqual(first, second)
        self.patch_backend(lose_city=True, blocks={})
        self.start("late")
        self.assertNotEqual(second, self.backend()["session_id"])

    def test_late_create_reply_does_not_reserve_the_name(self):
        self.patch_backend(lose_reply=True, receipt_delay=0.6)
        self.start(code=1, env={"GC_INSTANCE_TOKEN": "must-not-persist"})
        self.assertFalse(list(self.state_dir().glob("*.handoff")))
        self.assertTrue(list(self.state_dir().glob("*.orphan")))
        self.assertEqual(self.op("list-running", ""), b"")
        self.assertEqual(self.op("get-meta", "box", "GC_INSTANCE_TOKEN"), b"")
        self.patch_backend(lose_reply=False, receipt_delay=0)
        self.op("stop", "box")
        deadline = time.monotonic() + 2
        while not list(self.state_dir().glob("*.receipt")) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(list(self.state_dir().glob("*.receipt")))
        self.start()
        self.assertEqual(len(self.backend()["blocks"]), 1)
        self.assertFalse(list(self.state_dir().glob("*.orphan")))

    def test_readers_tolerate_abandoned_pre_create_row(self):
        self.start()
        row_file = self.state_row()
        row = json.loads(row_file.read_text())
        self.op("stop", "box")
        for field in ("block_id", "pid", "meta"):
            row.pop(field)
        # An abandoned attempt must not affect reads. Also model a stale pipe
        # inode left if the launcher itself was killed, not just the controller.
        row_file.write_text(json.dumps(row))
        handoff = self.state_dir() / (row["launch"] + ".handoff")
        os.mkfifo(handoff, 0o600)
        fd = os.open(handoff, os.O_RDONLY | os.O_NONBLOCK)
        try:
            self.assertEqual(os.read(fd, 100), b"")
        finally:
            os.close(fd)
        self.assertEqual(self.op("list-running", ""), b"")
        self.assertEqual(self.op("is-running", "box"), b"false\n")
        self.assertEqual(self.op("get-meta", "box", "GC_SESSION_ID"), b"")
        self.op("program-status", "box", code=66)
        self.op("stop", "box")
        self.assertFalse(handoff.exists())
        self.assertFalse(row_file.exists())
        self.start()

    def test_receipt_mismatch_closes_only_confirmed_window(self):
        self.patch_backend(receipt_mismatch=True)
        self.start(code=1)
        self.assertEqual(self.backend()["blocks"], {})
        self.assertFalse(list(self.state_dir().glob("*.handoff")))

    def test_socket_mismatch_does_not_drive_stored_block(self):
        self.start()
        sock = self.root / "z"
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        listener.bind(str(sock))
        self.env["GC_REX_SOCKET"] = str(sock)
        self.op("stop", "box", code=1)
        self.op("nudge", "box", data=b"untouched", code=1)
        self.assertNotIn("paste", self.block())

    def test_restored_block_is_not_owned_by_this_launch(self):
        for changes in ({"pid": 202}, {"server": "00000000-0000-0000-0000-000000000002"}):
            name = "other" if "server" in changes else "box"
            self.start(name)
            if "server" in changes:
                self.patch_backend(instance_id=changes["server"])
            else:
                self.patch_block(**changes)
            self.assertEqual(self.op("is-running", name), b"false\n")
            self.assertEqual(self.op("get-meta", name, "GC_STARTUP_PROMPT"), b"")
            self.op("program-status", name, code=66)
            self.op("nudge", name, data=b"untouched")
            self.op("stop", name)
            self.assertTrue(self.backend()["blocks"])
            self.assertTrue(all("paste" not in b for b in self.backend()["blocks"].values()))

    def test_city_state_is_stable_across_hostname_changes(self):
        with mock.patch.dict(os.environ, self.env, clear=True):
            with mock.patch("socket.gethostname", return_value="before"):
                before = Store(Budget(1)).root
            with mock.patch("socket.gethostname", return_value="after"):
                self.assertEqual(Store(Budget(1)).root, before)

    def test_symlinked_entry_and_missing_python_or_package(self):
        link = self.root / "runtime with spaces"
        link.symlink_to(OP)
        with_python = subprocess.run([str(link), "is-running", "box"], env=self.env, capture_output=True, timeout=4)
        self.assertEqual((with_python.returncode, with_python.stdout), (0, b"false\n"))
        missing = subprocess.run([str(link), "is-running", "box"], env=dict(self.env, PATH="/nonexistent"),
                                 capture_output=True, timeout=4)
        self.assertEqual(missing.returncode, 1)
        self.assertIn(b"Python", missing.stderr)
        copy = self.root / "incomplete runtime"
        copy.write_bytes(OP.read_bytes())
        copy.chmod(0o700)
        failed = subprocess.run([str(copy), "is-running", "box"], env=self.env, capture_output=True, timeout=4)
        self.assertEqual(failed.returncode, 1)
        self.assertIn(b"runtime package", failed.stderr)

    def test_readers_do_not_wait_for_start_or_same_name_capture(self):
        p = self.starting({"nudge": "hold", "ready_prompt_prefix": "not-present"}, budget="7000")
        until = time.monotonic() + 4
        while time.monotonic() < until:
            if self.op("is-running", "box") == b"true\n":
                break
            time.sleep(0.02)
        else:
            self.fail("launcher never became visible")
        self.patch_block(capture_delay=0.6)
        env = dict(self.env, GC_EXEC_DEADLINE_MS="1000")
        self.env = env
        self.assertEqual(self.op("list-running", ""), b"box\n")
        self.assertEqual(self.op("is-attached", "box"), b"false\n")
        self.assertIn(b"incarnation", self.op("program-status", "box"))
        self.assertEqual(self.op("get-meta", "box", "GC_READY_PROMPT_PREFIX"), b"not-present")
        self.start(code=73)
        self.assertIsNone(p.poll())
        self.env = dict(self.env, GC_EXEC_DEADLINE_MS="10000")
        self.op("stop", "box")
        _, stderr = p.communicate(timeout=2)
        self.assertEqual(p.returncode, 0, stderr)
        self.assertEqual(self.backend()["blocks"], {})

    def test_tui_prompt_above_footer_with_nbsp_and_border(self):
        self.patch_backend(new_block={"screen": "welcome\n│ ❯\u00a0│\n? for shortcuts\n",
                                      "program_status": [{"state": "working", "owner": {"pid": 101, "name": "test-agent"}}]})
        self.start(nudge="first", ready_prompt_prefix="❯ ", ready_delay_ms=90000)
        self.assertEqual(self.block()["paste"], ["first"])
        self.assertEqual(self.block()["keys"][0]["key"], "enter")

    def test_numbered_menu_or_trust_dialog_withholds_start_and_nudge(self):
        screens = ("Confirm option\n❯ 1. Something\n  2. Cancel\n? for shortcuts\n", "Trust this folder?\n[yes/no]\n")
        for screen in screens:
            with self.subTest(screen=screen):
                self.patch_backend(new_block={"screen": screen})
                self.start(nudge="never choose", ready_prompt_prefix="❯ ")
                self.assertIn(b"dialog or menu", self.op("get-meta", "box", STARTUP_NOTE))
                self.op("nudge", "box", data=b"never choose", code=1)
                self.assertNotIn("paste", self.block())
                self.assertNotIn("keys", self.block())
                self.op("send-keys", "box", "Down")
                self.assertEqual(self.block()["keys"][0]["key"], "arrow_down")
                self.op("stop", "box")

    def test_status_idle_or_fixed_delay_readiness(self):
        for state, delay in (("idle", 0), ("working", 300)):
            self.patch_backend(new_block={"bracketed": False, "canonical": True,
                                          "program_status": [{"state": state, "owner": {"pid": 101, "name": "test-agent"}}]})
            self.start(nudge="first", ready_delay_ms=delay)
            self.assertEqual(self.block()["paste"], ["first"])
            self.op("stop", "box")

    def test_no_hints_waits_for_raw_bracketed_paste(self):
        self.patch_backend(new_block={"boot_seconds": 0.45})
        self.start(nudge="first\nsecond")
        self.assertEqual(self.block()["paste"], ["first\nsecond"])
        self.assertGreaterEqual(self.block()["pasted_at"], self.block()["ready_at"] + 0.4)

    def test_program_exit_during_start_rolls_back_when_nudge_was_required(self):
        self.patch_backend(new_block={"exit": {"exit_code": 1}})
        self.start(code=1, nudge="first")
        self.assertEqual(self.backend()["blocks"], {})

    def test_blocked_osc_and_menu_after_paste_prevent_submit(self):
        self.start()
        self.patch_block(program_status=[{"state": "blocked", "owner": {"pid": 101, "name": "test-agent"}}])
        self.op("nudge", "box", data=b"untouched", code=1)
        self.assertNotIn("paste", self.block())
        self.patch_block(program_status=[], post_paste_screen="Do you want to proceed?\n❯ 1. Yes\n  2. No\n")
        self.op("nudge", "box", data=b"may be staged", code=1)
        self.assertEqual(self.block()["paste"], ["may be staged"])
        self.assertNotIn("keys", self.block())

    def test_sigterm_reaps_ignoring_child(self):
        self.start()
        self.patch_backend(hang=True)
        p = subprocess.Popen([str(OP), "is-running", "box"], env=self.env, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 4
            while not (self.root / "pid").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            pid = int((self.root / "pid").read_text())
            p.send_signal(signal.SIGTERM)
            p.communicate(timeout=2)
            self.assertEqual(p.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            if p.poll() is None:
                p.kill()
            p.communicate()

    def test_launcher_consumes_file_and_unsets_env(self):
        status, stdout, stderr, receipt = self.launcher(
            command="printf '%s|%s|%s' \"${DROP-unset}\" \"$ADD\" \"${REX_SESSION-unset}\"",
            updates={"DROP": "", "ADD": "hidden-value", "REX_SERVER": "not-for-child"}, strip_rex_env=True)
        self.assertEqual((status, stdout, stderr), (0, b"unset|hidden-value|unset", b""))
        self.assertEqual(receipt["block_id"], "block:test")
        self.assertTrue(receipt["ready"])

    def launcher(self, *, command="printf ran", updates=None, session="session:test", host=None, **config):
        file = self.root / f"{uuid.uuid4().hex}.handoff"
        args = [sys.executable, "-B", str(ASSETS / "gc_rex/launch.py"), str(file), session, host or machine_id()]
        env = {"DROP": "set", "REX_SESSION": "session:test", "REX_BLOCK": "block:test"}
        p = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            data = dict(uid=os.getuid(), work_dir=str(self.root), env=updates or {}, command=command)
            data.update(config)
            receipt = file.with_suffix(".receipt")
            until = time.monotonic() + 3
            while not receipt.exists() and p.poll() is None and time.monotonic() < until:
                time.sleep(0.01)
            if receipt.exists():
                fd = os.open(file, os.O_WRONLY | os.O_NONBLOCK)
                try:
                    os.write(fd, json.dumps(data).encode() + b"\n")
                finally:
                    os.close(fd)
            out, err = p.communicate(timeout=4)
            if receipt.exists():
                self.assertFalse(file.exists())
            return p.returncode, out, err, json.loads(receipt.read_text()) if receipt.exists() else {}
        finally:
            self.reap(p)
            file.unlink(missing_ok=True)

    def test_launcher_does_not_run_command_on_wrong_uid_host_or_session(self):
        for fields in ({"uid": os.getuid() + 1}, {"host": "another-host"}, {"session": "session:other"}):
            with self.subTest(fields=fields):
                code, out, _, receipt = self.launcher(**fields)
                self.assertEqual((code, out), (1, b""))
                self.assertFalse(receipt.get("ready", False))

    def test_launcher_restores_sigpipe(self):
        code, out, err, _ = self.launcher(command="/usr/bin/yes | /usr/bin/head -n 1")
        self.assertEqual((code, out, err), (0, b"y\n", b""))

    def test_staging_setup_and_copy(self):
        layer = self.root / "layer"
        layer.mkdir()
        (layer / "input").write_text("data")
        work = self.root / "work"
        script = self.root / "setup with spaces"
        script.write_text(f"#!{sys.executable} -B\nfrom pathlib import Path\nPath('shebang').touch()\n")
        script.chmod(0o700)
        self.start(work_dir=str(work), overlay_dir=str(layer), pre_start=["test -f input && touch before"],
                   session_setup=["touch after"], session_setup_script=str(script), session_live=["touch must-not-run"])
        self.assertEqual(sorted(p.name for p in work.iterdir()), ["after", "before", "input", "shebang"])
        self.op("copy-to", "box", str(layer / "input"), "sub/copied")
        self.assertEqual((work / "sub/copied").read_text(), "data")
        self.op("copy-to", "box", str(layer / "input"), "../outside", code=1)
        self.start("pre-failure", code=1, pre_start=["exit 1"])
        self.assertEqual(len(self.backend()["blocks"]), 1)

    def test_tail_does_not_drop_empty_lines_or_carriage_returns(self):
        self.assertEqual(terminal.tail(b"a\nb\r\n\n", 2), b"b\r\n\n")
        self.assertEqual(terminal.tail(b"a\nb", 1), b"b")
        self.assertEqual(terminal.tail(b"\n", 1), b"\n")

    def test_wrapped_dialog_footer_and_history(self):
        dialog = b"Pick an option\nA text field\nEnter to select or Esc\nto cancel\n"
        self.assertEqual(terminal.composer(dialog, "❯ "), "dialog")
        self.assertEqual(terminal.composer(dialog + "❯ \u00a0\n? for shortcuts\n".encode(), "❯ "), "prompt")
