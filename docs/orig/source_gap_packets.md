# Retail Source Gap Packets

This pass adds a more actionable layer on top of the existing `orig/` source-anchor tooling.

`source_skeleton.py` and `source_corridors.py` can already show where retail-backed source names land in current EN text. What they do not do is package the in-between filenames into a ready-to-work corridor packet.

That matters because the next recovery step is often not "name one anchor", but "recover the one or five files sitting between these two anchors".

## Tool

- `python tools/orig/source_gap_packets.py`
  - Starts from the same retail EN source-tag anchors used by `source_recovery.py`, `source_skeleton.py`, and `source_corridors.py`.
  - Builds source-order corridor packets between those anchors.
  - Resolves each in-between basename to the best debug-side path hint available.
  - Attaches the current EN function gap and current `splits.txt` coverage status so the next split pass can open the right address window immediately.

## High-Value Findings

### 1. `objanim.c -> objHitReact.c` resolves to one missing file: `main/objhits.c`

This is the strongest current packet:

- left anchor: `main/objanim.c`
- right anchor: `objHitReact.c`
- missing file: `main/objhits.c`
- current EN gap: `0x80030780-0x8003549C`
- uncovered current EN functions: `21`

This is exactly the kind of packet that can drive first-pass split work quickly. The retail anchors already framed the neighborhood; the new report closes the loop by resolving the missing filename directly.

### 2. `expgfx.c -> curves.c` resolves a clean five-file render/effects corridor

The next strong packet is:

- `modgfx.c -> dll/modgfx.c`
- `modelfx.c -> dll/modelfx.c`
- `dim_partfx.c -> dll/dim_partfx.c`
- `df_partfx.c -> dll/df_partfx.c`
- `objfsa.c -> dll/objfsa.c`

Current EN gap:

- `0x8009FF68-0x800E556C`
- `0x45604` bytes
- `337` current EN functions

This is too large for a one-file recovery pass, but it is now a clearly named effects/render neighborhood instead of an anonymous block between two anchors.

### 3. `curves.c -> camcontrol.c` now has concrete path hints, but the exact debug interval is much larger

The short packet view resolves:

- `dll/gameplay.c`
- `dll/pickup.c`
- `dll/modanimeflash1.c`
- `dll/modcloudrunner2.c`

However, the exact debug split interval between those anchors contains `111` files.

Practical read:

- the four resolved names are still useful local seeds
- they should not be mistaken for the full corridor
- this is best treated as a targeted neighborhood around `curves.c` and `camcontrol.c`, not a whole-file interval proof

### 4. `DIMBoss.c -> SHthorntail.c` exposes a broad but structured cross-DIM/DF/NW/SH neighborhood

This packet is not short, but it is still useful because many names resolve cleanly:

- `dll/DIM/DIMbosstonsil.c`
- `dll/DIM/DIMbossspit.c`
- `dll/DF/DFcradle.c`
- `dll/DF/DFpulley.c`
- `dll/DF/DFbarrel.c`
- `dll/NW/NWmammoth.c`
- `dll/NW/NWtricky.c`
- `dll/SH/SHmushroom.c`

Only a small minority of the `23` in-between basenames stay unresolved.

That makes it a good "recover the neighborhood shape first" packet even though it is too broad for a single-file split.

## Practical Use

- Summary:
  - `python tools/orig/source_gap_packets.py`
- Inspect one corridor:
  - `python tools/orig/source_gap_packets.py --search objanim objhits`
  - `python tools/orig/source_gap_packets.py --search expgfx curves`
  - `python tools/orig/source_gap_packets.py --search DIMBoss SHthorntail`
- Spreadsheet-friendly dump:
  - `python tools/orig/source_gap_packets.py --format csv`

## How It Fits

- Use `source_skeleton.py` to find retail-backed EN islands.
- Use `source_corridors.py` to judge whether an anchor is too small, too wide, or sitting near likely missing files.
- Use `source_gap_packets.py` when you want the next recoverable filename packet between two anchors, with the current EN gap functions already attached.

The new value here is packaging. It turns source-order evidence into concrete filename packets that are easier to hand to the next decomp pass.
