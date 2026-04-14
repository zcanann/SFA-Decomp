# `orig/GSAE01/files/*.tab` notes

This pass focuses on retail `.tab` families that can already drive file-boundary recovery, instead of treating every `.bin` payload as one opaque blob.

## Tool

- `python tools/orig/tab_catalog.py`
  - Audits every non-special EN `*.tab` under `orig/GSAE01/files/`.
  - Resolves same-name `.bin` / `.BIN` payloads in the same directory or disc root.
  - Classifies each table as `split-ready`, `partial`, `empty-payload`, `no-payload`, or `unresolved`.
  - Reports whether the table behaves like raw 32-bit offsets or flagged low-24-bit offsets.

By default it skips `MAPS.tab`, `OBJECTS.tab`, and `mod*.tab` because dedicated tools already cover those families.

## High-value findings

### 1. Several map-asset families are already split-ready across EN

The useful families are:

- `ANIM.TAB`: all 53 EN instances classify cleanly as split-ready
- `MODELS.tab`: all 53 EN instances classify cleanly as split-ready
- `VOXMAP.tab`: 28 EN instances are split-ready and the other 25 simply point at empty `VOXMAP.bin` payloads
- `ANIMCURV.tab`: 52 EN instances are split-ready; the only outlier is `wallcity/ANIMCURV.tab`, which still looks valid but leaves a `0x70`-byte tail

This is directly useful for split scaffolding. Those tables already recover chunk boundaries without needing Ghidra guesses.

### 2. A few root-only families are also ready-to-use boundary maps

Useful root cases:

- `AMAP.TAB`
- `PREANIM.TAB`
- `HITS.tab`
- `MODLINES.tab`
- `SAVEGAME.tab`
- `SCREENS.tab`
- `SPRITES.tab`

These are good testcase families when someone wants to validate an extractor or define real per-entry structs before touching more complicated map assets.

### 3. `TEX0`, `TEX1`, and `TEXPRE` look close, but not safe yet

All three families behave like flagged low-24-bit tables, but the recovered monotonic prefix only covers part of the payload:

- `TEX0.tab`: tail gaps range `0x62F0..0x30650`
- `TEX1.tab`: tail gaps range `0x15C70..0x13FA10`
- `TEXPRE.tab`: tail gap `0x3ADA0`

Each family also ends with one footer-like outlier entry after the clean prefix. That is strong evidence of a real table format, but not enough to treat them as finished split maps yet.

### 4. Several families still need family-specific decoding

Still not generic-offset tables:

- `GAMETEXT.tab`
- `MODANIM.TAB`
- `OBJSEQ.tab`
- `OBJSEQ2C.tab`
- `TRKBLK.tab`
- `DLLS.tab`

These are better attacked with dedicated parsers than with a generic splitter.

## Practical use

- Summary:
  - `python tools/orig/tab_catalog.py`
- CSV:
  - `python tools/orig/tab_catalog.py --format csv`
- Search:
  - `python tools/orig/tab_catalog.py --search ANIM.TAB MODELS.tab`
  - `python tools/orig/tab_catalog.py --search status:partial TEX1.tab`
  - `python tools/orig/tab_catalog.py --search wallcity/ANIMCURV.tab`

The main workflow is simple:

1. Use the catalog to find a `split-ready` family.
2. Use its tab offsets as real chunk boundaries.
3. Treat `partial` families as leads for further format work, not as finished split scaffolds.
