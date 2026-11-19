"""Host work carried in a start config, for callers that have not done it."""

import os
from pathlib import Path
import shutil
import sys

from .launch import overlay
from .support import Cancelled, Failure


def destination(work, relative):
    path = work / relative
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise Failure("copy destination must stay within work_dir")
    if not path.resolve().is_relative_to(work.resolve()):
        raise Failure("copy destination resolves outside work_dir")
    return path


def copy(source, target, work, skip=()):
    # Copy source links as links. Do not write through destination links.
    destination(work, str(target.relative_to(work)))
    if source.is_dir() and not source.is_symlink():
        if target.is_symlink():
            raise Failure("cannot stage a directory over a symlink")
        target.mkdir(parents=True, exist_ok=True)
        for item in source.iterdir():
            if item.name not in skip:
                copy(item, target / item.name, work)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        target.unlink()
    if not source.is_symlink() and not source.is_file():
        raise Failure("source is not a regular file or symlink")
    if target.is_dir():
        raise Failure("cannot stage a file over a directory")
    if target.exists():
        # Replace rather than modify a destination that could be hard-linked.
        target.unlink()
    shutil.copy2(source, target, follow_symlinks=False)


def copy_entry(work, source, relative):
    src = Path(source)
    dst = destination(work, relative or ("" if src.is_dir() else src.name))
    copy(src, dst, work)


def prepare(cfg, work, city, budget):
    layers = cfg.get("pack_overlay_dirs", []) + ([cfg["overlay_dir"]] if cfg.get("overlay_dir") else [])
    if layers or cfg.get("copy_files"):
        work.mkdir(parents=True, exist_ok=True)
    for layer in layers:
        # RPP v0 does not send the concrete/family overlay selectors. A caller
        # using fs.host stages those itself. Never copy another provider's slot.
        if (Path(layer) / "per-provider").exists():
            raise Failure("provider overlays must be staged by a Gas City with fs.host support")
        copy(Path(layer), work, work, skip=("per-provider",))
    for entry in cfg.get("copy_files", []):
        copy_entry(work, entry["src"], entry.get("rel_dst", ""))
    env = overlay(os.environ, cfg["env"])
    for command in cfg.get("pre_start", []):
        code, _ = budget.run(["/bin/sh", "-c", command], cwd=work if work.is_dir() else city,
                             env=env, limit=budget.remaining(0.25))
        if code:
            raise Failure("pre_start command failed")
    if not work.is_dir():
        raise Failure("session work_dir does not exist")


def setup(cfg, work, name, budget):
    env = overlay(os.environ, dict(cfg["env"], GC_SESSION=name))
    commands = [["/bin/sh", "-c", command] for command in cfg.get("session_setup", [])]
    if cfg.get("session_setup_script"):
        script = Path(cfg["session_setup_script"])
        commands.append([str(work / script) if not script.is_absolute() else str(script)])
    for argv in commands:
        try:
            code, _ = budget.run(argv, cwd=work, env=env, limit=min(10, budget.remaining(0.25)))
            if code:
                raise Failure("nonzero exit")
        except Cancelled:
            raise
        except (Failure, OSError):
            print("Rex runtime: session setup command failed", file=sys.stderr)
