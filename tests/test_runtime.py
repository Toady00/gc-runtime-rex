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

REPO = Path(__file__).resolve().parents[1]
ASSETS = REPO / "assets"
OP = ASSETS / "gc-runtime-rex"
sys.path.insert(0, str(ASSETS))
from gc_rex import terminal
from gc_rex.runtime import ARITY


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
        fake.write_text(f"#!{sys.executable}\n" + (REPO / "tests/fake_rex.py").read_text().split("\n", 1)[1])
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
        data = self.backend()
        data.update(changes)
        (self.root / "backend.json").write_text(json.dumps(data))

    def block(self):
        return next(iter(self.backend()["blocks"].values()))

    def patch_block(self, **changes):
        data = self.backend()["blocks"]
        next(iter(data.values())).update(changes)
        self.patch_backend(blocks=data)

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
        self.patch_block(program_status=[nested, {"state": "idle", "owner": {"pid": 404, "name": "gone"}}])
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
        self.patch_block(image="other")
        silent = read()
        self.assertEqual(silent["state"], "")
        self.assertNotEqual(silent["incarnation"], first["incarnation"])
        self.patch_block(program_status=[dict(root, owner={"pid": 101, "name": "other"}, updated_at="second")])
        self.assertEqual(read(), dict(silent, state="idle"))

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
        self.assertEqual(self.op("get-last-activity", "box"), when)
        self.op("clear-scrollback", "box")
        self.assertEqual(self.op("peek", "box", "10"), b"\n")
        self.assertNotEqual(self.op("get-last-activity", "box"), when)
        self.op("send-keys", "box", "C-c", "M-Left", "BTab", "Y", "C-S-F2", "Enter")
        self.op("interrupt", "box")
        self.assertEqual(self.block()["keys"], ["ctrl+c", "alt+left", "shift+tab", "shift+y", "ctrl+shift+f2", "enter", "ctrl+c"])

    def test_chunked_delivery_and_partial_failure(self):
        self.start(nudge="first turn", ready_prompt_prefix="prompt> ")
        for text in ("x" * 4096, "雪" * 34134 + "\ntail"):
            self.op("nudge", "box", data=text.encode())
        box = self.block()
        self.assertEqual("".join(box["paste"]), "first turn" + "x" * 4096 + "雪" * 34134 + "\ntail")
        self.assertTrue(all(len(chunk.encode()) <= 24576 for chunk in box["paste"]))
        self.assertEqual(box["keys"], ["enter"] * 3)
        self.patch_block(reject=True)
        self.op("nudge", "box", data=b"may be partial", code=1)
        self.patch_block(reject=False)
        self.op("nudge", "box", data=b"may be partial", code=1)
        self.assertEqual(self.block()["paste"], box["paste"])

    def test_refused_paste_does_not_latch_before_sending(self):
        self.start()
        self.patch_block(bracketed=False, canonical=True)
        self.op("nudge", "box", data=b"a\nb", code=1)
        self.op("nudge", "box", data=b"a" * 4096, code=1)
        self.op("nudge", "box", data=b"safe")
        self.assertEqual(self.block()["paste"], ["safe"])

    def test_deadline_cleans_failed_start(self):
        self.env["GC_EXEC_DEADLINE_MS"] = "1400"
        self.start(code=1, nudge="not ready", ready_prompt_prefix="never appears")
        self.assertEqual(self.backend()["blocks"], {})
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
        file = self.root / "test.handoff"
        file.write_text(json.dumps({"uid": os.getuid(), "host": socket.gethostname(), "work_dir": str(self.root),
                                    "env": {"DROP": "", "ADD": "hidden-value"},
                                    "command": "printf '%s|%s' \"${DROP-unset}\" \"$ADD\""}))
        file.chmod(0o600)
        p = subprocess.run([sys.executable, str(ASSETS / "gc_rex/launch.py"), str(file), "session:test"],
                           env={"DROP": "set", "REX_SESSION": "session:test", "REX_BLOCK": "block:test"},
                           capture_output=True, check=True, timeout=4)
        self.assertEqual(p.stdout, b"unset|hidden-value")
        self.assertFalse(file.exists())
        self.assertEqual(json.loads(file.with_suffix(".receipt").read_text())["block_id"], "block:test")

    def test_staging_setup_and_copy(self):
        layer = self.root / "layer"
        layer.mkdir()
        (layer / "input").write_text("data")
        work = self.root / "work"
        self.start(work_dir=str(work), overlay_dir=str(layer), pre_start=["test -f input && touch before"],
                   session_setup=["touch after"], session_live=["touch must-not-run"])
        self.assertEqual(sorted(p.name for p in work.iterdir()), ["after", "before", "input"])
        self.op("copy-to", "box", str(layer / "input"), "sub/copied")
        self.assertEqual((work / "sub/copied").read_text(), "data")
        self.op("copy-to", "box", str(layer / "input"), "../outside", code=1)
        self.start("pre-failure", code=1, pre_start=["exit 1"])
        self.assertEqual(len(self.backend()["blocks"]), 1)

    def test_tail_does_not_drop_empty_lines_or_carriage_returns(self):
        self.assertEqual(terminal.tail(b"a\nb\r\n\n", 2), b"b\r\n\n")
        self.assertEqual(terminal.tail(b"a\nb", 1), b"b")
        self.assertEqual(terminal.tail(b"\n", 1), b"\n")
