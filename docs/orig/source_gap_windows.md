# Retail source gap windows

This pass fills one remaining workflow gap in the retail-backed source-boundary tooling.

`source_gap_packets.py` could already tell us which missing source names likely sit between two anchors. What it could not do was split one large EN gap into estimated per-file windows for those missing names.

That left the worker with a correct neighborhood but no concrete first-pass boundaries inside it.

## Tool

- `python tools/orig/source_gap_windows.py`
  - starts from the committed retail-backed gap packets
  - pulls exact debug split sizes for the uniquely resolved gap names
  - proportionally fits those debug sizes back onto the current EN gap and snaps the boundaries to current EN function edges
  - emits per-file EN window estimates plus ready markdown briefs under [source_gap_window_briefs/README.md](/C:/Projects/SFA-Decomp/docs/orig/source_gap_window_briefs/README.md)
  - intentionally stays focused by default so the normal summary does not explode into hundred-file corridors
  - `--broad-exact-intervals` raises the exact-interval cap to a ready exploratory preset when a larger exact debug corridor is worth projecting

## Highest-value findings

### 1. `expgfx.c -> curves.c` still gives the cleanest five-file render/effects skeleton

The strongest focused boundary result remains the render/effects corridor:

- `dll/modgfx.c` -> `0x8009FF68-0x800C2BA8`
- `dll/modelfx.c` -> `0x800C2BA8-0x800C8284`
- `dll/dim_partfx.c` -> `0x800C8284-0x800D6778`
- `dll/df_partfx.c` -> `0x800D6778-0x800D8FE0`
- `dll/objfsa.c` -> `0x800D8FE0-0x800E556C`

The main value is that the current EN gap no longer has to be attacked as one anonymous `0x45604`-byte block.

### 2. `objhits.c` is now directly bounded between `objanim.c` and `objHitReact.c`

The single-file packet is still the cleanest direct gap result:

- `main/objhits.c` -> `0x80030780-0x8003549C`

That turns one retail-backed hole into a concrete missing-file window instead of a vague neighborhood note.

### 3. `curves.c -> camcontrol.c` can be viewed in two useful modes now

Focused mode keeps the short named gap packet:

- `dll/gameplay.c`
- `dll/pickup.c`
- `dll/modanimeflash1.c`
- `dll/modcloudrunner2.c`

Broad exact mode surfaces the full exact-debug interval:

- `python tools/orig/source_gap_windows.py --broad-exact-intervals --search curves camcontrol`
- current EN gap: `0x800E56A4-0x80102D3C`
- projected files: `111`
- early named windows include `dll/gameplay.c`, `dll/foodbag.c`, `dll/savegame.c`, `dll/screens.c`, and `dll/pickup.c`

This is the important workflow change. The short packet is still the safest first split seed, but the broader mode now exposes a much better source-order skeleton for the whole corridor.

### 4. `DIMBoss.c -> SHthorntail.c` is now a strong broad exact-debug corridor

The new preset exposes a high-value larger plan:

- `python tools/orig/source_gap_windows.py --broad-exact-intervals --search DIMBoss SHthorntail`
- current EN gap: `0x801BD7F4-0x801D5764`
- projected files: `69`
- EN/debug ratio: about `1.05x`
- confidence: `high`

This corridor now yields one address-ordered skeleton covering named files such as:

- `dll/DIM/DIMbosstonsil.c`
- `dll/DIM/DIMbossspit.c`
- `dll/DF/DFcradle.c`
- `dll/DF/DFpulley.c`
- `dll/DF/DFbarrel.c`
- `dll/NW/NWmammoth.c`
- `dll/NW/NWtricky.c`
- `dll/SH/SHmushroom.c`
- `dll/SH/SHkillermushroom.c`
- `dll/SH/SHrocketmushroom.c`
- `dll/SH/SHspore.c`

That makes the DIM/DF/NW/SH neighborhood materially easier to recover as a coherent source-order island instead of one anonymous pre-split blob.

## Confidence model

The tool keeps its confidence intentionally conservative:

- `high`
  for fully resolved local packets where debug sizes cover the EN gap closely, including larger exact-debug intervals when enabled
- `medium`
  for usable local skeletons where the names resolve cleanly but the broader corridor may still contain unnamed neighbors
- `low`
  for exploratory partial fits

The focused packets stay mostly `medium`, which matches the evidence quality. The main current `high` broad-exact result is `DIMBoss.c -> SHthorntail.c`.

## Practical use

- focused summary:
  - `python tools/orig/source_gap_windows.py`
- inspect one focused gap or file:
  - `python tools/orig/source_gap_windows.py --search expgfx curves`
  - `python tools/orig/source_gap_windows.py --search objhits`
- inspect larger exact-debug corridors:
  - `python tools/orig/source_gap_windows.py --broad-exact-intervals --search DIMBoss SHthorntail`
  - `python tools/orig/source_gap_windows.py --broad-exact-intervals --search curves camcontrol`
- spreadsheet dump:
  - `python tools/orig/source_gap_windows.py --format csv`
- machine-readable dump:
  - `python tools/orig/source_gap_windows.py --format json`
- packet briefs:
  - `python tools/orig/source_gap_windows.py --materialize-all`

## Why this matters

This is the bridge between "the retail data names the missing files" and "here are the first EN windows to split."

That makes it directly useful for the current phase of the repo:

- start a real multi-file source skeleton without hand-partitioning the whole gap
- give side agents bounded EN windows for missing files like `modgfx.c`, `objhits.c`, or the wider DIM/DF/NW/SH corridor
- keep the output grounded in retail-backed anchors and debug split sizes rather than inventing arbitrary file cuts
