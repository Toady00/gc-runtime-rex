# gc-runtime-rex

A [Gas City](https://github.com/gastownhall/gascity) runtime pack that runs
agent sessions in [Rex](https://www.superlogical.com/rex/docs) terminals, with
no tmux.

Each city gets one Rex session labelled `GC <city>`. Each Gas City session
gets its own tab. Open it in the Rex app to see the terminal or interact
with it. The pack never selects a session or focuses the app for you.

## Requirements

- macOS with a running, local [Rex](https://www.superlogical.com/rex/docs)
  server. Tested with `0.1.0-preview.21`, API revision 18. Rex must run as
  the same user as Gas City and see the same filesystem.
- Python 3.9 or later on the controller's `PATH`. No Python packages to
  install. On the tested Mac, `/usr/bin/python3` works with a minimal PATH.
- A Gas City build with `carrier.ops`, `idle-boundary`, `fs.host` and exec
  pack `program-status` support. Tested with `1.4.2+local.1e27045d0`.
  Exec pack program status is tracked at
  [gastownhall/gascity#9243](https://github.com/gastownhall/gascity/pull/9243).

## Add it to a city

Add the checkout to the city's `city.toml`. Merge these settings into any
existing `[session]` and `[daemon]` tables:

```toml
[imports.rex]
source = "/absolute/path/to/gc-runtime-rex"

[session]
provider = "rex"
# Optional: read OSC 7501 without using it for idle decisions yet.
program_status = "shadow"

[daemon]
session_reconciler = "legacy"
```

Gas City uses `peek` for its screen-based idle boundary. Once you have checked
that your program reports OSC 7501 states correctly, `program_status = "on"`
also lets eligible states inform idle decisions. An unrecognized or
unattributable status is not an idle verdict.

For a provider that needs its initial prompt typed into the terminal, use
`prompt_mode = "none"` so Gas City puts it in the start nudge. Set
`ready_prompt_prefix` to its actual prompt or set `ready_delay_ms` for a
program without a reliable prompt or status. A prompt that needs startup
interaction can time out before Gas City's post-start dialog handling runs.

## Server and state

The defaults use the real account home from the password database. `HOME` may
point at the city and does not affect Rex discovery. The pack uses the local
socket at `~/Library/Application Support/rex/server.sock`, and the CLI in the
Rex Server app installed by Rex. It never starts or stops the server. To use a
different local server or CLI, set these in the controller's environment:

| Variable | Meaning |
| --- | --- |
| `GC_REX_SOCKET` | Absolute path to an existing Rex Unix socket owned by the runtime user. No named or remote hosts. |
| `GC_REX_BIN` | Absolute path to the `rex` executable. The path may contain spaces. |
| `GC_EXEC_STATE_DIR` | Absolute path to a private state root. Defaults to `~/.local/share/gc-runtime-rex`. Keep it consistent across processes serving the city. |

With a managed supervisor, make these available to the supervisor itself
through its environment configuration. Setting them only in the launched
session's environment does not change pack operation targeting. Stop the
city's Rex terminals before switching its socket; keep the old mapping until
you have verified the original objects are gone. The pack refuses to use
stored IDs with a different socket.

The pack stores full Rex IDs and per-incarnation metadata in private files
under the state root, keyed by host name and city path. The tab label is for
display. The launcher reads session environment from a one-use mode-0600 file,
unlinks it, applies the configured variables over the server's environment,
and unsets keys whose value is empty. Put credentials in environment variables,
not in the launch command. The command runs through `/bin/sh` without a login
shell. An empty command opens an interactive `/bin/sh`.

`stop` closes the exact tab's block and drops its metadata. Rex keeps the city
session when its last tab closes. You can remove an empty city session in Rex;
the pack creates a new one on the next start. The pack does not destroy a Rex
session wholesale because it may now contain manually added tabs. A restart
of a stopped or dead Gas City session always creates a new block. If Rex
loses a create reply and supplies neither an ID nor a launcher receipt, the
pack records the incomplete attempt and refuses to guess by label. Inspect
that session in Rex before clearing an incomplete state record.

## Limits

- Nudges are pasted and submitted with one Enter. Large text is sent in
  UTF-8 chunks; with bracketed paste the program receives a paste group per
  chunk. Multiline or tabbed text requires bracketed paste. Canonical tty
  input is rejected for large messages rather than risking truncation.
  A failed send after input may have gone in blocks further nudges in that
  block until you inspect it and restart the session.
- Rex acknowledges that it queued input, not that the program read it. This
  carrier has no fenced input or typed `input-outcome` support. Gas City
  refuses fenced requests. Open the tab in Rex for interactive access;
  the pack has no CLI `attach` op.
- Attachment uses the owner and size requests of the specific block. The
  app's subscriptions to every session are not treated as viewing every tab.
  Ownership and size requests can linger; Rex has no per-block API that
  proves what is currently visible. An indeterminate read keeps the session
  awake. Check attachment on your client before enabling interactive sleep.
- Rex exposes timestamps for OSC reports but no last-output timestamp.
  Other activity is dated when the capture changes, so changes that are
  overwritten or invisible between samples can be missed. Rex sends all
  scrollback on capture, even when Gas City only needs the last 120 lines.
- Rex can retain an OSC record after a process exits or replaces itself.
  The pack checks the current process against the record, reports terminal
  exit separately, and retires a report on an observed program image change.
  An in-place `exec` to the same image cannot be distinguished through this
  API. The pack has no reconciler v2 inventory or server teardown operation.
- `fs.host` lets Gas City stage overlays, skills and MCP files and run its
  host setup commands. Keep tmux commands out of setup for this runtime.
  Rex closes terminal processes; programs detached from their terminal are
  outside that guarantee. With this legacy profile Gas City does not scan
  this runtime for leftovers.

## Tests

Run `python3 -m unittest` from the checkout. The tests use a fake `rex` and
do not need a server. The live RPP gates start disposable terminals on the
configured server, so run them with `GC_CITY`, `GC_EXEC_CITY_PATH` and
`GC_EXEC_CITY_NAME` unset, and a private scratch `GC_EXEC_STATE_DIR`:

```sh
gc runtime check "$PWD/assets/gc-runtime-rex"
gc runtime conformance --json "$PWD/assets/gc-runtime-rex"
```

After live tests, remove the empty test sessions using only the full IDs
saved in the test state directory's `city.json` files.

## License

MIT. See [LICENSE](LICENSE).
