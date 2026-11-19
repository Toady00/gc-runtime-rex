# gc-runtime-rex

A [Gas City](https://github.com/gastownhall/gascity) runtime pack that runs
agent sessions in [Rex](https://www.superlogical.com/rex/docs) terminals, with
no tmux.

Work in progress. Nothing here is usable yet.

## What it will do

- Start each agent as a terminal in a Rex session, so the agents show up in
  the Rex app next to your own terminals.
- Drive agents through Rex: read the screen, type input, send keys.
- Report each agent's own status (idle, working, blocked) from Rex's OSC 7501
  program status, instead of guessing from the screen.

## Requirements

- A gc build with `carrier.ops`, `idle-boundary` and `program-status` for exec
  runtime packs. `program-status` is
  [gastownhall/gascity#9243](https://github.com/gastownhall/gascity/pull/9243),
  which is not merged yet.
- Rex, with its server running.
- Python 3.9 or later. The pack uses only the standard library.

## License

MIT. See [LICENSE](LICENSE).
