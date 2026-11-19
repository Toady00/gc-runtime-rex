# gc-runtime-rex

A Gas City exec runtime pack for Rex. gc runs the pack's script once per
operation; the script talks to a Rex server through the `rex` CLI.

Record project-specific pitfalls here as they are found. Keep each one short
and say how it was verified.

## Rules

- Python 3.9 or later, standard library only. No third-party imports, no
  `pip install`, no dependence on `HOME` for finding code.
- Never stop, restart, upgrade or auto-start a Rex server. Run every `rex`
  call with `REX_AUTOSTART=0`.
- Touch only sessions, windows and blocks this pack created. Never capture,
  type into, rename, resize or close anything else on the server.
- Do not copy code from `gastownhall/gascity-packs` (`runtime-herdr-core`
  included). That repository has no licence. Its structure and ideas are fine
  to follow.
- The contract is gc's `docs/reference/exec-session-provider.md` at the gc
  revision in use. Read it rather than trusting notes here when they disagree.

## gc contract pitfalls

- Until the `protocol` handshake succeeds once, gc treats the pack as
  tmux-first and can send tmux text to `exec`. `protocol` must be fast and
  must not load backend code or contact Rex.
- `gc runtime conformance` reads a `protocol` call slower than the op timeout
  as "no capabilities" and skips every token-gated group without failing.
  `gc runtime check` fails it. Run both, and check that the conformance
  output lists the declared capabilities.
- `exec` and `provision` must exit 2 without reading stdin. The pack declares
  `carrier.ops`, never `proc.exec`, `proc.provision` or `input-fence`.
- Under `carrier.ops` start is one op: `start` waits until the agent is ready
  and types the first turn itself (the start config's `nudge`). gc does not
  type it.
- gc stores the ready prompt with `set-meta <name> GC_READY_PROMPT_PREFIX` and
  reads it back with `get-meta`. It must round-trip byte for byte, and `stop`
  must drop it.
- A canceled op gets SIGTERM to its process group and, 2 seconds later,
  SIGKILL to the script only. Exit promptly on SIGTERM and start no child
  that ignores it.
- gc does not set the script's working directory, and `HOME` may be a city
  directory. Use absolute paths. Key per-city state by `GC_EXEC_CITY_PATH`.

## Rex pitfalls

Use API revision 18 (`0.1.0-preview.21` on macOS) as the tested baseline.

- The `rex` binary is not on a minimal `PATH` and its path contains spaces.
  Resolve an absolute path and never build a shell string from it.
- Set an explicit `REX_SERVER=unix:///...` from the password database, not
  `HOME`. With `REX_AUTOSTART=0`, `whoami` on a missing socket exited 4 on
  rev 18 without falling back to the personal server.
- A terminal gets the server's environment. The launcher must read and
  unlink its private hand-off before applying it. Rex's own `REX_SESSION`
  and `REX_BLOCK` identify the created block even if a start unsets them
  in the program environment.
- In the API, `"shell":"none"` alone still runs under a login shell. Pass
  `"login":false` as well.
- A block cannot be respawned. A restart is a new block with a new id.
- Without `"exit":{"on_completion":false}` a block closes when its program
  exits and its exit status is lost.
- Use `block.event` with `type=paste` for paste semantics, and `send-key
  enter` to submit. Rev 18 preserved 102,414 UTF-8 bytes, including an
  embedded newline, across five independently bracketed paste events in a
  raw tty. Do not infer application acceptance from an RPC acknowledgement.
- `rex capture` always returns the whole scrollback. There is no tail option,
  and its cost grows with scrollback size.
- The app auto-subscribes to newly created sessions. A new background tab
  reported `size.owner: null` and `size.desired: []` even with an `app`
  client in `session.list_clients`. Do not use the session client list by
  itself as a viewing signal.
- `rex do` needs `-s <id>` for block methods. Its Lua bridge drops JSON
  nulls when round-tripping replies, including `process.last_exit: null`.
  Use direct JSON calls for process/status reads that need this distinction.
- OSC root records have no run id or exited flag. An immediate `exec`
  preserved a root with the same PID and the old name `bash` while
  `process` named `sleep`. Distinguish the initial shell hand-off from an
  observed program-image change. Use `last_exit` for terminal exit, even
  when Rex retains an `idle` record. The same-image `exec` case is invisible.
- Rex supplies report `updated_at` timestamps but no last-output timestamp.
  Capture changes supply a sampled lower-resolution activity signal.
- Labels are not unique. Address blocks by full id; a label can be ambiguous.
- Direct block calls on a missing block exit 3; socket failure is an
  outage, not a missing block. `block.close` removed the test child that
  ignored SIGHUP but left the empty Rex session. The API has no atomic
  destroy-if-empty guard, so the pack closes exact blocks only.
- Rex allocates IDs for create requests. Neither `session.create` nor
  `session.new_window` takes an idempotency key. If the create reply is
  lost, only a launcher receipt can recover the block ID; leave an
  unresolved journal entry instead of adopting or deleting by label.

## Host work and startup

- `fs.host` only works for a same-user local server. Require a Unix socket;
  never use a remote Rex host as a fallback. Gas City normally stages
  overlays and executes host setup. The fallback start wire has no provider
  overlay selectors, so reject raw `per-provider` layers rather than stage
  another provider's files.
- The fallback start wire carries `session_live`, but many such commands
  drive a default tmux server. Do not execute them in this runtime.
- Do not use `watch-startup` to hold a child open: gc cancels that op with
  SIGKILL to the script, without the ordinary TERM grace period. Returning
  exit 2 uses gc's capture fallback.
