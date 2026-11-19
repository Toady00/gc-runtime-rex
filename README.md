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

Import the checkout in the city root's `pack.toml`:

```toml
[imports.rex]
source = "/absolute/path/to/gc-runtime-rex"
```

Select the runtime in `city.toml`. Merge these settings into any existing
`[session]` and `[daemon]` tables:

```toml
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

When the city selects the imported runtime by name (`provider = "rex"`),
the tested Gas City build puts the startup prompt in the start nudge even
if the program's prompt mode is `arg` or `flag`. RPP has no argv prompt
field. If you use a direct `exec:` path or a build without that named-pack
routing, set `prompt_mode = "none"` on every provider used with Rex that
needs a startup prompt. The pack's `nudge-fallback` declaration separately
opts into moving prompts that exceed Gas City's argv size limits to the
nudge.

Set `ready_prompt_prefix` for programs with a recognizable composer, or
`ready_delay_ms` for programs without one. A prefix takes priority over a
delay and must remain visible across observations at least 400 ms apart.
Without either hint, the pack waits for attributed OSC `idle` or for the tty
to stay noncanonical with bracketed paste enabled across observations at
least 400 ms apart. OSC `working` does not override that tty evidence;
`blocked` always vetoes a nudge.
For a plain screen with no readiness signal, startup waits at most 15 s
unless you configured a delay. A delay has at most 60 s of probe time.
Gas City's deadline can shorten either wait.

If a dialog or menu is visible, or readiness cannot be confirmed, the tab
stays open and the first turn is withheld. Gas City can run its normal
post-start dialog dismissal after the op returns. The tested version drops
successful-operation stderr and does not replay that text. If a new session
appears idle with no first turn, inspect its composer and read the pack's
stored reason using the controller's socket and state-root settings:

```sh
GC_EXEC_CITY_PATH=/absolute/path/to/city \
  /absolute/path/to/gc-runtime-rex/assets/gc-runtime-rex \
  get-meta 'EXACT_SESSION_NAME' GC_STARTUP_DELIVERY_UNCONFIRMED
```

Resend only after checking the composer. Startup fails and rolls back
the block if the program exits before a required first turn can be sent.

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
| `GC_EXEC_STATE_DIR` | Absolute path to a state root owned by the runtime user. If pre-created, use mode `0700`. Defaults to `~/.local/share/gc-runtime-rex`. Keep it consistent across processes serving the city. |
| `GC_REX_STRIP_ENV` | Set to `1` to strip all `REX_*` variables from the launched program, including ones added by session configuration. Off by default. |
| `GC_REX_MACHINE_ID` | Fallback UUID if the controller cannot get a native machine ID. Set it once per machine and keep it stable. |

With a managed supervisor, make these available to the supervisor itself
through its environment configuration. Setting them only in the launched
session's environment does not change pack operation targeting. Stop the
city's Rex terminals before switching its socket; keep the old mapping until
you have verified the original objects are gone. The pack refuses to use
stored IDs with a different socket.

The pack stores full Rex IDs and per-incarnation metadata in private files,
keyed by machine UUID and city path. The tab label is for display. The
launcher receives its environment through a mode-0600 named pipe, unlinks
it after reading, applies variables over the server's environment, and
unsets keys whose value is empty. An interrupted hand-off cannot leave the
config on disk. Put credentials in environment variables, not in the
launch command. The command runs through `/bin/sh` without a login shell.
An empty command opens an interactive `/bin/sh`.

By default, the program also inherits Rex's `REX_SERVER`, `REX_SESSION`,
and `REX_BLOCK` variables when the server supplies them. If you have installed
Rex integration or startup hooks for your programs, they may tell the program
about the terminal and how to drive Rex. A process running as you may be able
to use the local CLI to drive your other Rex sessions. `GC_REX_STRIP_ENV=1`
removes the inherited variables; it is not a permission boundary.

Access to protected macOS folders such as `~/Documents`, `~/Desktop`, and
`~/Downloads` depends on the privacy grants of the app macOS considers
responsible for Rex Server. A grant to Gas City or to the viewing app does
not grant access to the process in the terminal. Rex's local
`server.apple.privacy_status` method identifies the responsible executable.

`stop` closes the exact tab's block and drops its metadata. Rex can leave
the city session empty after the last tab closes. It can also disappear.
The pack recreates a missing city session on demand. Remove unused empty
city sessions in Rex if you reach its session limit. The pack will not
destroy a session wholesale: another client could add a tab between the
empty check and the destroy request. If Rex loses a window-create reply,
the pack releases the name and can reclaim the block on the next start or
stop if the launcher supplies a receipt. Receipt-less records expire after
eight seconds and are removed by the next start or stop. Without an ID the
pack cannot identify a leftover window. No launch config can be recovered
from an abandoned pipe. Lifecycle locks are per exact name and are retained
in the state root so a waiter cannot acquire a different inode.

After a server restart, the pack will not drive a restored block with a
new server instance or a replacement child PID. It creates a fresh block
in a fresh city session instead. Rex restores saved sessions by default,
but a restored layout does not prove that its programs or every tab belong
to the pack. You may see two sessions labelled `GC <city>`; inspect the old
one before removing its tabs. If you tested a pre-release version keyed by
hostname, stop its sessions with that version before switching to this one.

## Limits

- Nudges check for visible menus, known dialogs, and OSC `blocked` before
  pasting and again after a 500 ms pause before Enter. An explicit
  `send-keys` or `interrupt` bypasses the dialog guard. The check and send
  are separate calls, and no screen matcher recognizes every dialog.
- A numbered row at the configured prompt blocks delivery even without an
  adjacent option. This also refuses a composer draft that starts with `1. `.
  A generic cursor still needs a neighbouring numbered option. Numbered
  transcript lines above the composer do not block delivery. Known dialogs
  use specific headings or multiple cues near the bottom of the capture.
  Unnumbered permission buttons and older single-key approvals may not be
  recognized unless the program reports OSC `blocked`.
- Large text is sent in
  UTF-8 chunks; with bracketed paste the program receives a paste group per
  chunk. Multiline or tabbed text requires bracketed paste. Canonical tty
  input is rejected for large messages rather than risking truncation.
  Literal ESC and other terminal controls are rejected. A definite first
  paste rejection can be retried. If a dialog stops a paste before Enter,
  a later nudge can proceed once a recognized composer is visibly empty.
  Known mode and shortcuts footers do not count as draft text.
  An unknown submit result, a visible draft, or a composer whose contents
  cannot be established still requires inspection and `interrupt` or restart.
- Rex acknowledges that it queued input, not that the program read it. This
  carrier has no fenced input or typed `input-outcome` support. Gas City
  refuses fenced requests. Open the tab in Rex for interactive access;
  the pack has no CLI `attach` op.
- Attachment uses the owner and size requests of the specific block. The
  app's subscriptions to every session are not treated as viewing every tab.
  Rex has no API for what a client is showing. A block's owner is a size
  claim, and the Mac app keeps its claim after you switch to another
  session. So a session reads as attached from the first time the app opens
  its tab, for as long as the app stays connected, and Gas City will not put
  it to sleep. A session whose tab was never opened reads as detached. An
  indeterminate read also keeps the session awake.
- Rex exposes timestamps for OSC reports but no last-output timestamp.
  Other activity is sampled at most once every 2 seconds and dated when
  the capture changes. Rex sends all scrollback on capture, even for a
  120-line peek or dialog check, so the cost rises with scrollback.
  Attachment and status reads do not wait for a capture or startup.
- Rex CLI requests have a two-second timeout and the controller reaps timed
  out groups. On an uncatchable controller kill, an already launched CLI
  can survive briefly under its own timeout. An arbitrary setup command
  has no such independent timer.
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
