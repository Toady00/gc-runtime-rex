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
- Under `carrier.ops`, gc's `finishStart` dismisses dialogs only after
  `start` returns. On dialog or readiness timeout, leave the block running
  and record `GC_STARTUP_DELIVERY_UNCONFIRMED`. At `1e27045d0` gc neither
  consumes that key nor retries the withheld text, and discards stderr on
  success. The doctor scans tmux's internal diagnostic files, not an RPP
  diagnostic path; use `get-meta` for this pack.
- The exec wire has no argv prompt field. The exec contract doc says `arg`
  and `flag` prompts are dropped, but `cmd/gc/prompt_delivery.go` at
  `1e27045d0` routes them into a named pack runtime's nudge. Direct `exec:`
  does not get the named-pack rule.
- gc stores the ready prompt with `set-meta <name> GC_READY_PROMPT_PREFIX` and
  reads it back with `get-meta`. It must round-trip byte for byte, and `stop`
  must drop it.
- A canceled op gets SIGTERM to its process group and, 2 seconds later,
  SIGKILL to the script only. Exit promptly on SIGTERM and start no child
  that ignores it.
- gc does not set the script's working directory, and `HOME` may be a city
  directory. Use absolute paths. Key per-city state by `GC_EXEC_CITY_PATH`.
- Python 3.9 on macOS uses a per-process monotonic clock origin. Use wall
  time for persisted sample ages and monotonic time only within one process.
- The macOS system Python can create a relative `nonexistent/Library/Caches`
  tree when `HOME=/nonexistent`. Use `-B` in Python fixture shebangs too;
  the isolated runtime and launcher already use it.

## Rex pitfalls

Use API revision 18 (`0.1.0-preview.21` on macOS) as the tested baseline.

- The `rex` binary is not on a minimal `PATH` and its path contains spaces.
  Resolve an absolute path and never build a shell string from it.
- Set an explicit `REX_SERVER=unix:///...` from the password database, not
  `HOME`. With `REX_AUTOSTART=0`, `whoami` on a missing socket exited 4 on
  rev 18 without falling back to the personal server.
- Rex supplies the terminal environment. Use a FIFO for the launch
  config so even a kill before create cannot leave credentials on disk.
  The receipt uses `REX_SESSION` and `REX_BLOCK` before any overrides or
  stripping. Reset Python's ignored SIGPIPE and file-size signals before
  exec; a shell pipeline otherwise reports a broken pipe.
- In the API, `"shell":"none"` alone still runs under a login shell. Pass
  `"login":false` as well.
- A block cannot be respawned. A restart is a new block with a new id.
- Without `"exit":{"on_completion":false}` a block closes when its program
  exits and its exit status is lost.
- Use `block.event` for paste and key presses. It bypasses the Lua binding
  path (`client.key`); direct events produced CR, Ctrl-C, and Down in the
  test receiver. Wait 500 ms after paste and recheck for dialogs before
  Enter. Terminal mode 2004 is visible in `modes` and can establish readiness
  once `input_mode` is noncanonical. Rev 18 preserved 102,414 UTF-8 bytes,
  including an embedded newline, across five bracketed paste events in a
  raw tty. `rex send` to that kind of receiver sent LF as LF with no paste
  markers. It accepted 60,000 bytes and refused 65,536 without typing them.
  Do not infer application acceptance from an RPC acknowledgement.
- Use the newest prompt, tolerating NBSP, a box border, and a footer. A
  numbered row needs a cursor and a neighbouring option to be a menu.
  Auto-recover only a paste stopped by a dialog before Enter, and only
  after a recognized composer is empty. An uncertain Enter is different.
- `rex capture` always returns the whole scrollback. There is no tail option,
  and its cost grows with scrollback size.
- The app auto-subscribes to newly created sessions. A new background tab
  reported `size.owner: null` and `size.desired: []` even with an `app`
  client in `session.list_clients`. Do not use the session client list by
  itself as a viewing signal. A `rex new` terminal had no owner after the
  CLI exited on rev 18; the stale CLI owner seen on rev 11 did not recur.
- `rex do` needs `-s <id>` for block methods. Its Lua bridge drops JSON
  nulls and turns empty arrays into objects. The batched read uses an
  explicit sentinel for `last_exit: null` after validating the child PID;
  normalize empty status/size arrays at the boundary. Do not cache the
  server instance across invocations.
- OSC root records have no run id or exited flag. An immediate `exec`
  preserved a root with the same PID and the old name `bash` while
  `process` named `sleep`. Distinguish the initial shell hand-off from an
  observed program-image change. Use `last_exit` for terminal exit, even
  when Rex retains an `idle` record. The same-image `exec` case is invisible.
- Rex supplies report `updated_at` timestamps but no last-output timestamp.
  Sample capture changes separately so `program-status` and `is-attached`
  never wait behind startup, paste debounce, or a capture.
- Labels are not unique. Address blocks by full id; a label can be ambiguous.
- Direct block calls on a missing block exit 3; socket failure is an
  outage. `block.close` removed the test child that ignored SIGHUP. Empty
  sessions have persisted and disappeared in different observations; do
  not assume either. `exit_empty` controls server shutdown once its last
  session and connection close. It does not control empty session retention.
  The API has no atomic destroy-if-empty guard: close exact blocks only.
- Verify both `server.status.instance_id` and the live block's child PID;
  a restored layout can retain IDs while the program changes. The
  replacement-process case is tested with a double, without a server restart.
- Rex allocates IDs for create requests. Exit 1 can be a definite server
  rejection or a lost reply. Use the structured rejection code, never
  print the raw response. A pending create is absent to readers. Unlink
  its pipe before releasing the name and use a late receipt to reap only
  that block. Expire receipt-less records after the launch pipe wait and
  CLI timeout. Never adopt or delete by label.

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
