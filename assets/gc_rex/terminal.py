"""Terminal input and observations, independent of session-name lookup."""

import os
import re
from typing import NamedTuple

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


class Screen(NamedTuple):
    kind: str
    empty: bool = False


NUMBERED_ROW = re.compile(r"^([0-9]+)\.(?:\s|$)")


def option_number(text):
    match = NUMBERED_ROW.match(text)
    return int(match[1]) if match and len(match[1]) <= 4 else None


def composer(screen, prefix=""):
    """Read the newest composer and distinguish live dialog evidence from history."""
    lines = [line for raw in tail(screen, 120).decode("utf-8", "replace").split("\n")
             if (line := normalized(raw))]
    # A bare '>' is common in shell/transcript quotes. Only treat it as a
    # cursor when the program explicitly configured it as the prefix.
    prefixes = tuple(dict.fromkeys(filter(None, (prefix, "❯ ", "› ", "● ", "→ "))))
    recent = max(0, len(lines) - 16)
    for i in range(len(lines) - 1, -1, -1):
        for marker in prefixes:
            rest = prompt_rest(lines[i], marker)
            if rest is None:
                continue
            # gc's startup scan rejects numbered configured prompts even
            # when descriptions separate the choices. A generic glyph still
            # needs the neighbouring option to rule out ordinary output.
            if marker == prefix and NUMBERED_ROW.match(rest):
                return Screen("menu")
            number = option_number(rest)
            if i >= recent and number is not None and any(
                    0 <= j < len(lines) and option_number(lines[j]) in (number - 1, number + 1)
                    for j in (i - 1, i + 1)):
                return Screen("menu")
            if marker == prefix or not rest:
                below = lines[i + 1:]
                if dialog(below[-16:]):
                    return Screen("dialog")
                # A line under a bare prompt could be a wrapped draft.
                # Only known passive footer rows and box rules prove empty.
                empty = not rest and all(passive_footer(line) for line in below)
                return Screen("prompt" if marker == prefix else "plain", empty)
    return Screen("dialog" if dialog(lines[recent:]) else "plain")


def passive_footer(line):
    # Full rows from gc's Claude approval, composer-clear and idle fixtures.
    # A suffix match alone would mistake part of a multiline draft for a footer.
    text = " ".join(line.lower().split())
    return bool(
        re.fullmatch(r"[─━═╰╯╭╮└┘┌┐┏┓┗┛╌ ]+", text)
        or re.fullmatch(r"⏵⏵ (?:bypass permissions|accept edits|don't ask) on"
                        r"(?: \(shift\+tab to cycle\))?(?: · ← for agents)?", text)
        or re.fullmatch(r"(?:⏸ manual mode on · )?\? for shortcuts(?: · ← for agents)?", text)
        # Codex's idle-after-deny capture has this warning on the shortcuts row.
        or re.fullmatch(r"\? for shortcuts ⚠ [0-9]+ warnings? · f2 to view", text)
    )


def dialog(lines):
    rows = [" ".join(line.lower().split()) for line in lines]
    # Companion cues from gc's startup dialog recognizers. Match whole
    # headings where no second cue is needed, never an isolated substring.
    if any(row in {
        "trust this folder?", "trust project folder?", "do you trust the contents of this directory?",
        "do you trust the files in this folder?", "do you want to use this api key?",
        "usage limit reached", "you've hit your limit",
    } for row in rows):
        return True
    text = " ".join(rows)
    cues = (
        ("choose the text style", "/theme"),
        ("resume from summary", "resume full session as-is", "enter to confirm"),
        ("update available!", "skip until next version", "press enter to continue"),
        ("quick safety check", "trust this folder"),
        ("allow external claude.md", "allow external imports"),
        ("new mcp server found", "use this and all future mcp servers"),
        ("hooks need review", "trust all", "continue without trusting"),
        ("hooks need review", "trust all", "enter to review hooks"),
        ("bypass permissions mode", "yes, i accept"),
        ("detected a custom api key", "no (recommended)"),
        ("rate limit", "keep trying", "stop"),
        ("ready to submit your answers?", "submit answers", "cancel"),
        ("keep current model", "switch to "),
    )
    if any(all(cue in text for cue in group) for group in cues):
        return True
    if any(all(cue in row for cue in ("1: bad", "2: fine", "3: good", "0: dismiss")) for row in rows):
        return True
    # Wrapped bottom action footer. Neither 'esc to cancel' nor 'enter
    # to confirm' on its own identifies a dialog under a live composer.
    for count in range(1, min(3, len(rows)) + 1):
        footer = " ".join(rows[-count:])
        if (re.fullmatch(r"enter to select\b.*\besc to cancel", footer) or
                re.fullmatch(r"press \S.+ to confirm\b.*\b\S+ to (?:cancel|go back)(?: or .* to open thread)?", footer)):
            return True
    return False


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
