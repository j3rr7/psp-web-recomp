# Cheats

The page can load a cheat file and apply it to the running game: poking values
in the game's memory (extra lives, max ammo, and so on) or, for a few built-in
actions, changing how the emulated PSP behaves (for example freezing the clock
so timers stand still).

Cheat files are **not** shipped with this repository and none are built in. You
supply your own, the same way you supply your own disc image. The engine is
game-agnostic: every address comes from your file.

## Opening the panel

Click **Cheats** in the toolbar. The panel lists the cheats in the loaded file
with an on/off state; click a row to toggle it, or use **Enable all** /
**Disable all**. **Load file…** opens a `.cheat` file from your computer. The
list is kept until you load another file or reload the page.

Any parse errors are shown at the bottom of the panel (and in the console log).
A bad line is reported with its line number and skipped; the rest of the file
still loads.

## The file format

A cheat file is plain text, close to the CWCheat format so existing knowledge
carries over. Lines starting with `#` are comments. Blank lines are ignored.

```
# Anything after a # is a comment.
cheat <ID> "<name>"
  <entries...>
```

Each cheat has a short **id** (used to toggle it) and a quoted **name** (shown
in the panel). A cheat with no entries is dropped. An entry is one of these:

### A plain poke

```
  <address> <value> [width]
```

Writes `value` to `address` **every frame** while the cheat is on. `address` and
`value` accept `0x...` or decimal. `width` is `b8`, `b16` or `b32` (default
`b32`) and says how many bytes to write. Re-applying every frame is what most
cheats need, because the game usually recomputes the value.

### A one-shot poke

```
  once <address> <value> [width]
```

Written once, the frame the cheat is turned on, then left alone. Use this for a
value the game does not overwrite.

### A conditional (joker) poke

```
  cond [test] <check_address> <check_value> <address> <value> [width]
```

Written every frame, but only while the condition at `check_address` holds.
`test` is `eq` (equal, the default), `ne` (not equal), `lt` (less than) or `gt`
(greater than). Use this to gate a poke on some other state — for example only
when a menu flag is set.

### A block write

```
  block <address> <byte> <byte> ...
```

Writes a run of bytes starting at `address`, each of which may be `0x...` or
decimal.

### A host action

```
  hle <action> [arg ...]
```

Runs a named host action instead of poking memory. Actions are built into the
emulator and cannot run arbitrary code — a file can only choose from the list
below. Arguments are written as `0x...` or decimal.

## Host actions

| Action | What it does |
|---|---|
| `freeze_clock` | Holds the game's clock at the current frame, so countdowns and timers stop. Releasing the cheat (turning it off) lets time run again. |

More actions are added as they are needed; a file that names an unknown action
is reported as an error when it loads rather than doing nothing quietly.

## Finding addresses

The cheat engine applies addresses; it does not find them. To discover an
address for a game, use the tools described in [internals.md](internals.md):

- `PSPWEB_TRACE_HLE=1` logs every system call, which is how you find the code
  path behind a value you want to change.
- The headless runner can be driven with `--press` and `--stick`, and dumps
  frames with `--dump-every`, so you can reach the state and watch it change.
- PSPRecomp's write watch (`PSPRECOMP_WATCH_WRITE=<address>`, with
  `PSPRECOMP_WATCH_WRITE_SIZE`) logs whenever guest code writes an address,
  with the thread and the instruction pointer — useful for finding where a
  health value lives.

CWCheat databases for a game are a reasonable starting point, but addresses are
specific to the exact executable. If a cheat has no effect, the usual cause is
an address from a different build of the game.

## Testing a cheat with the headless runner

The native runner can load and toggle cheats without a browser, which is the
quickest way to check a file:

```bash
# Load a file, enable every cheat in it, and print each probed word per frame.
build/native-<game>/profiles/web/pspweb_<game> games/<game>/root/EBOOT.BIN \
    --disc games/<game>/root/disc --ms games/<game>/root/ms0 --frames 120 \
    --cheat my.cheat --cheat-probe 0x08900000

# Load a file but enable only one cheat by id.
... --cheat my.cheat --cheat-enable INF_HEALTH
```

`--cheat-probe <address>` prints the 32-bit word at an address every frame, so
you can see a poke land (or not) directly. `--cheat-enable <id>` enables just
that cheat; with no `--cheat-enable`, every cheat in the file is enabled.

## Notes and limits

- **Every frame, or once.** Most cheats must be re-applied every frame; a value
  that "reverts itself" is almost always a poke that should be `once` or should
  be gated with `cond`.
- **Build-specific.** Addresses belong to one exact executable. A mismatch does
  not fail loudly — the write just lands somewhere harmless or, rarely,
  somewhere harmful — so keep files labelled with the game and version they
  were made for.
- **Saves are separate.** Cheats change memory as the game runs; they do not
  edit save files. Exporting and importing saves works as described in the
  README.
- **Legally.** Cheat files are yours to supply. Do not commit them here, and do
  not redistribute a game's own data. See the Legal section of the README.

## Deferred: code-level cheats

Cheats that need to intercept the game's code rather than its memory (setting a
breakpoint on an address and rewriting a register, or replacing a routine
outright through `Runtime::register_native_fast_path`) are **not implemented**.

When this is built, note the trap: hot leaf routines are reached through the
runtime's cross-unit call chaining and never hit the outer dispatch hooks, so a
breakpoint layer must arm **both** the outer hooks
(`set_runtime_pre_dispatch_hook`) and the chained-call hooks
(`set_runtime_pre_chained_call_hook`) or it will silently miss exactly the
addresses it most wants. This is why it is parked rather than done quickly.
