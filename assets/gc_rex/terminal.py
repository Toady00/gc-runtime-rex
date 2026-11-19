"""Terminal input and observations, independent of session-name lookup."""

import os
import re

from .support import Failure


KEYS = {
    "enter": "enter", "return": "enter", "escape": "escape", "esc": "escape",
    "tab": "tab", "btab": "shift+tab", "bspace": "backspace", "backspace": "backspace",
    "space": "space", "up": "up", "down": "down", "left": "left", "right": "right",
    "home": "home", "end": "end", "dc": "delete", "delete": "delete", "ic": "insert",
    "insert": "insert", "ppage": "pageup", "pageup": "pageup", "npage": "pagedown",
    "pagedown": "pagedown", **{f"f{i}": f"f{i}" for i in range(1, 13)},
}


def translate(key):
    modifiers = []
    while len(key) > 2 and key[1] == "-" and key[0] in "CMS":
        modifiers.append({"C": "ctrl", "M": "alt", "S": "shift"}[key[0]])
        key = key[2:]
    base = KEYS.get(key.lower())
    if base is None and re.fullmatch(r"[a-zA-Z0-9]", key):
        base = key.lower()
        if key.isupper() and not modifiers:
            modifiers.append("shift")
    if base is None:
        raise Failure("unsupported tmux key name")
    return "+".join(dict.fromkeys(modifiers + [base]))


def chunks(text, limit=24 * 1024):
    """Budget UTF-8 bytes; JSON quotes and escapes can at most double these."""
    raw = text.encode("utf-8")
    at = 0
    while at < len(raw):
        end = min(at + limit, len(raw))
        while end < len(raw) and raw[end] & 0xc0 == 0x80:
            end -= 1
        if end == at:
            raise ValueError("chunk limit too small for one character")
        yield raw[at:end].decode("utf-8")
        at = end


def input_text(text):
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if any((ord(ch) < 32 and ch not in "\n\t") or 127 <= ord(ch) <= 159 for ch in text):
        raise Failure("nudge contains a terminal control character")
    return text


def check_paste(rex, target, text):
    if len(text.encode("utf-8")) < 1024 and "\n" not in text and "\t" not in text:
        return
    snapshot = rex.snapshot(target, "modes", "input_mode")
    bracketed = any(m["number"] == 2004 and m["set"] and not m.get("ansi")
                    for m in snapshot["modes"]["modes"])
    if ("\n" in text or "\t" in text) and not bracketed:
        raise Failure("multiline or tabbed nudges need bracketed paste")
    if snapshot["input_mode"]["canonical"]:
        raise Failure("large or multiline nudge refused in canonical terminal mode")


def tail(data, count):
    if count <= 0:
        return data
    suffix = data[:-1] if data.endswith(b"\n") else data
    return b"\n".join(suffix.rsplit(b"\n", count)[-count:]) + (b"\n" if data.endswith(b"\n") else b"")


def alive(process):
    return process["last_exit"] is None


def status_answer(record, snapshot):
    process = snapshot["process"]
    child = process.get("child") or {}
    front = process.get("foreground") or {}
    roots = [r for r in snapshot["program_status"]["records"] if not r.get("id")]
    if len(roots) > 1:
        raise Failure("Rex supplied multiple program status roots")
    root = roots[0] if roots else {}
    owner = root.get("owner") or {}
    subject = front or child
    names = record.get("process_names", [])
    reporter = record.get("reporter")
    exited = not alive(process)
    # Do not mistake an old report from a shell command for the program
    # Gas City launched. With hints, accept a matching foreground descendant.
    attributable = subject.get("pid") and (process_name(subject, names) if names else
                                           subject["pid"] == record["pid"])
    owner_matches = attributable and owner.get("pid") == subject.get("pid")
    if not exited and reporter and not attributable:
        exited = process_gone(reporter["image"][0])
    image = [subject.get(key) for key in ("pid", "name", "path", "script")]
    marker = [owner.get("pid"), owner.get("name"), root.get("updated_at")]
    if not exited and reporter and attributable and image != reporter["image"]:
        # An observed image change can be a same-PID exec. A retained Rex
        # record from the previous image must not make this run look idle.
        reporter = {"image": image, "serial": reporter["serial"] + 1,
                    "retired": reporter.get("last_report"), "last_report": None}
        record["reporter"] = reporter

    same_name = owner.get("name") == subject.get("name")
    initial_shell_exec = (not reporter and subject.get("pid") == record["pid"] and
                          owner.get("name") in ("sh", "bash", "zsh", "dash", "ksh"))
    reportable = (not exited and owner_matches and
                  (same_name or initial_shell_exec or reporter and marker == reporter.get("last_report")) and
                  (not reporter or marker != reporter.get("retired")))
    if reportable:
        if not isinstance(root.get("state"), str):
            raise Failure("invalid Rex program status state")
        if not reporter:
            reporter = {"image": image, "serial": 0}
            record["reporter"] = reporter
        reporter["last_report"] = marker

    pid = reporter["image"][0] if reporter else record["pid"]
    serial = reporter["serial"] if reporter else 0
    answer = {"state": "", "exited": exited, "incarnation": f'{record["block_id"]}:{pid}:{serial}'}
    if reportable:
        answer["state"] = root["state"]
        for key in ("kind", "app", "progress"):
            if root.get(key) is not None:
                answer[key] = root[key]
    return answer


def process_gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        pass
    return False


def process_name(process, names):
    candidates = (process.get(key, "").rsplit("/", 1)[-1].lstrip("-")
                  for key in ("name", "argv0", "script", "invoked_path"))
    return any(v in names or v.rsplit(".", 1)[0] in names for v in candidates if v)
