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

Observed on Rex server `0.0.1793981048` (API revision 11), macOS. The server
has since been upgraded to `0.1.0-preview.21` (API revision 18); recheck each
item there before relying on it, and update this list.

- The `rex` binary is not on a minimal `PATH` and its path contains spaces.
  Resolve an absolute path and never build a shell string from it.
- With `HOME` changed, `rex` looks for the server socket under the new `HOME`
  and can start a second server there. Set `REX_RUNTIME_DIR` (or
  `REX_SERVER`) from the real account home, found through the password
  database, not `HOME`.
- A terminal gets the server's environment, not the caller's. There is no
  env option. Pass session env through an `env`-style wrapper, and treat an
  empty value in the start config as "unset".
- In the API, `"shell":"none"` alone still runs under a login shell. Pass
  `"login":false` as well.
- A block cannot be respawned. A restart is a new block with a new id.
- Without `"exit":{"on_completion":false}` a block closes when its program
  exits and its exit status is lost.
- `rex send` types raw bytes and never brackets a paste. A trailing `\n` is
  not Enter; send the `enter` key. One call carries about 64,000 bytes, and a
  refused call delivers nothing.
- `rex capture` always returns the whole scrollback. There is no tail option,
  and its cost grows with scrollback size.
- Rex has no per-block metadata store and no last-output timestamp. The pack
  keeps both itself.
- Program status records have no run id and no exited flag. Rex drops a
  `working` record when the foreground program exits and keeps `idle` and
  `done` records with a dead `owner.pid`. Compare `owner.pid` with the
  block's current process before trusting a record.
- Labels are not unique. Address blocks by full id; a label can be ambiguous.
- Every command on a missing block or session exits 3.
- Stopping or restarting the Rex server ends every program in every session.
