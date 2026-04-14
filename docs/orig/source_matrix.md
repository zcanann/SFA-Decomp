# Cross-Bundle Source Audit

This pass compares the bundled EN v1.0, EN rev1, PAL, and JP retail leftovers before turning them into naming or stub decisions.

## Tool

- `python tools/orig/source_matrix.py`
  - Scans source-tagged strings out of every bundled `orig/*/sys/main.dol`.
  - Compares direct `.c.new` / `.h.bak` artifacts across bundles.
  - Crosswalks the EN v1.0 names back to current EN xrefs and debug-side split paths only as side evidence.
  - Flags likely cross-version aliases such as `curves.c` versus `hcurves.c` instead of pretending every bundle used the same filename.

## High-value findings

### 1. Most useful source tags are stable across all four bundled versions

The following names appear in EN v1.0, EN rev1, PAL, and JP:

- `camcontrol.c`
- `DIMBoss.c`
- `expgfx.c`
- `laser.c`
- `objanim.c`
- `objHitReact.c`
- `SHthorntail.c`
- `textblock.c`
- `dvdfs.c`
- `n_attractmode.c`

For active EN work, this matters because it means these are not one-off retail leftovers. They survived multiple revisions and regions.

### 2. JP preserves one filename variant EN does not: `hcurves.c`

EN v1.0, EN rev1, and PAL all use:

- `curves.c: MAX_ROMCURVES exceeded!!`

JP uses the same warning text, but names the file:

- `hcurves.c: MAX_ROMCURVES exceeded!!`

The local conclusion is modest: JP likely preserves an alternate filename for the same subsystem. That is strong enough to annotate [curves.c](/C:/Projects/SFA-Decomp/src/dll/curves.c), but not strong enough to pretend EN had a separate `hcurves.c` translation unit.

### 3. `n_attractmode.c` is weak in EN alone, but strong across bundles

`n_attractmode.c` still has no direct EN text xref, but it appears in all four bundled `main.dol` files.

In EN v1.0 it sits beside movie-facing strings such as:

- `starfox.thp`
- `malloc for movie failed`

That is enough to justify a non-built placeholder file at [n_attractmode.c](/C:/Projects/SFA-Decomp/src/unknown/n_attractmode.c) so the title-movie code cluster has a concrete source target.

### 4. Direct source artifacts are not distributed evenly across bundles

Shared across all four bundles:

- [starfox.h](/C:/Projects/SFA-Decomp/src/disc_artifacts/audio/starfox.h)
- `files/gametext/Boot/{English,French,German,Italian,Spanish}.c.new`

Present in EN v1.0, EN rev1, and PAL but not JP:

- `files/Boot/{English,French,German,Italian,Spanish}.c.new`

Present in EN v1.0, EN rev1, and JP but not PAL:

- `files/gametext/Boot/Japanese.c.new`

That tells us which missing source artifacts are real bundle differences versus missing extraction accidents.

## Practical use

- Summary:
  - `python tools/orig/source_matrix.py`
- Chase cross-version weak leads:
  - `python tools/orig/source_matrix.py --search n_attractmode dvdfs`
- Inspect alias cases:
  - `python tools/orig/source_matrix.py --search curves hcurves`
- Dump spreadsheet-friendly rows:
  - `python tools/orig/source_matrix.py --format csv`

The intended use is simple: before inventing a file name from one retail leftover, check whether the other bundled versions agree, disagree, or preserve a stronger alias.
