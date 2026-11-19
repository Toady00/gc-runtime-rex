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


def key_payload(key):
    *mods, base = key.split("+")
    mods = {mod for mod in mods}
    wire_key = {
        "up": "arrow_up", "down": "arrow_down", "left": "arrow_left", "right": "arrow_right",
        "pageup": "page_up", "pagedown": "page_down",
    }.get(base, base)
    text = ""
    point = 0
    if len(base) == 1:
        wire_key = ("digit_" if base.isdigit() else "key_") + base
        point = ord(base)
        if "ctrl" not in mods:
            text = (")!@#$%^&*("[int(base)] if base.isdigit() else base.upper()) if "shift" in mods else base
    elif base == "space":
        point = 32
        if "ctrl" not in mods:
            text = " "
    return {"key": wire_key, "mods": "+".join(m for m in ("shift", "ctrl", "alt") if m in mods),
            "consumed_mods": "shift" if text and "shift" in mods else "", "text": text,
            "unshifted_codepoint": point, "composing": False, "action": "press"}


def normalized(line):
    return line.replace("\u00a0", " ").strip().strip("│┃").strip()


def prompt_rest(line, prefix):
    prefix = prefix.replace("\u00a0", " ").lstrip()
    if not prefix:
        return None
    if line == prefix.rstrip():
        return ""
    if line.startswith(prefix):
        return line[len(prefix):].lstrip()
    return None


def composer(screen, prefix=""):
    """Classify the recent screen without treating a menu cursor as a prompt."""
    lines = [normalized(line) for line in tail(screen, 120).decode("utf-8", "replace").split("\n")]
    lines = [line for line in lines if line]
    prefixes = tuple(dict.fromkeys(filter(None, (prefix, "❯ ", "› ", "> ", "● ", "→ "))))
    for i in range(len(lines) - 1, -1, -1):
        for marker in prefixes:
            rest = prompt_rest(lines[i], marker)
            if rest is None:
                continue
            if re.match(r"^[0-9]+\.(?:\s|$)", rest):
                return "menu"
            if marker == prefix:
                return "prompt" if not dialog(lines[i + 1:]) else "dialog"
            # A bare generic prompt ends the transcript before it, but does
            # not substitute for a separately configured readiness prefix.
            if not rest:
                return "plain" if not dialog(lines[i + 1:]) else "dialog"
    if dialog(lines):
        return "dialog"
    # Menus without a highlighted row: require consecutive numbered rows.
    # A terminal draft pasted at the real composer is handled above.
    for prev, current in zip(lines, lines[1:]):
        a, b = re.match(r"^([0-9]{1,4})\.\s", prev), re.match(r"^([0-9]{1,4})\.\s", current)
        if a and b and int(b[1]) == int(a[1]) + 1:
            return "menu"
    return "plain"


def dialog(lines):
    # Join the recent rows so a wrapped title or question footer still vetoes
    # delivery. This is a refusal guard, not a parser for answering the dialog.
    text = " ".join(" ".join(lines).lower().split())
    return any(phrase in text for phrase in (
        "trust this folder", "trust project folder?", "quick safety check",
        "do you trust the contents of this directory", "do you trust the files in this folder",
        "trust and continue", "new mcp server found", "hooks need review", "bypass permissions mode",
        "do you want to use this api key", "detected a custom api key", "usage limit reached",
        "you've hit your limit", "/rate-limit-options", "do you want to proceed?",
        "would you like to run the following command", "would you like to make the following edits",
        "would you like to grant these permissions", "would you like to send input to",
        "do you want to approve network access", "do you want to make this edit", "approve edits?",
        "allow this action?", "permission required", "needs your approval", "esc to cancel",
        "enter to confirm", "ready to submit your answers?",
    )) or ("keep current model" in text and "switch to " in text) or (
        "1: bad" in text and "3: good" in text and "0: dismiss" in text)


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
    bracketed = bracketed_paste(snapshot["modes"])
    if ("\n" in text or "\t" in text) and not bracketed:
        raise Failure("multiline or tabbed nudges need bracketed paste")
    if snapshot["input_mode"]["canonical"]:
        raise Failure("large or multiline nudge refused in canonical terminal mode")


def bracketed_paste(modes):
    return any(m["number"] == 2004 and m["set"] and not m.get("ansi") for m in modes["modes"])


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
