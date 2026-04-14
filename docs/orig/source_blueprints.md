# Retail source blueprint blocks

This pass adds one missing handoff layer over the existing `orig/` source-tag tooling.

The repo already had:

- retail source-name recovery
- current EN anchor windows
- whole-file size estimates
- source-order gap packets
- a prioritized worklist

What it still did not have was one address-ordered view that reconciles those pieces into local source skeleton neighborhoods.

That matters because the practical recovery task is usually not:

> "what single retail file name survived?"

It is:

> "what is the next bounded neighborhood of files, windows, and in-between names I can turn into a first-pass source skeleton?"

## Tool

- `python tools/orig/source_blueprints.py`
  - Starts from the committed `source_worklist.py` and `source_gap_packets.py` signals.
  - Chooses one current EN planning span per retail-backed anchor:
    - suggested whole-file window when one exists
    - otherwise shared-island span
    - otherwise current seed span
  - Bridges adjacent anchors into one blueprint block when either:
    - their planned spans overlap, or
    - a short resolved gap packet connects them
  - Keeps overlap warnings explicit instead of pretending the current window guesses are already final file boundaries.
  - Can emit JSON or CSV when a worker wants to script against the blocks instead of reading markdown.
  - Can materialize ready neighborhood briefs under [source_blueprint_briefs/README.md](/C:/Projects/SFA-Decomp/docs/orig/source_blueprint_briefs/README.md).

## High-value findings

### 1. The current retail-backed skeleton collapses into five practical blueprint blocks

The new report currently finds:

- `5` blueprint blocks
- `2` blocks bridged by short resolved gap packets
- `1` block with overlapping planned windows
- `2` residual names with no current EN window: `dvdfs.c`, `n_attractmode.c`

That is a better starting shape than treating the current source anchors as nine isolated clues.

### 2. `objanim.c -> objhits.c -> objHitReact.c` is now one direct skeleton neighborhood

The strongest compact block is:

- span: `0x8002EC4C-0x80035728`
- anchors:
  - `main/objanim.c`
  - `objHitReact.c`
- resolved in-between file:
  - `main/objhits.c`

The useful detail is not just that `objhits.c` exists. The blueprint keeps all three pieces in order:

- `objanim.c` is still a shrink-first boundary
- `objhits.c` is the one missing file between the anchors
- `objHitReact.c` is the next named packet on the far side

That is exactly the kind of neighborhood a first-pass split worker can attack without cross-referencing three other reports.

### 3. `expgfx.c -> curves.c -> camcontrol.c` is now one ordered render/camera skeleton chain

The second bridged block is:

- span: `0x8009B36C-0x80103648`
- anchors:
  - `dll/expgfx.c`
  - `dll/curves.c`
  - `dll/CAM/camcontrol.c`
- resolved in-between files:
  - `dll/modgfx.c`
  - `dll/modelfx.c`
  - `dll/dim_partfx.c`
  - `dll/df_partfx.c`
  - `dll/objfsa.c`
  - `dll/gameplay.c`
  - `dll/pickup.c`
  - `dll/modanimeflash1.c`
  - `dll/modcloudrunner2.c`

This is still a large region, but it now reads like one ordered first-pass skeleton instead of two unrelated anchor/gap reports.

### 4. `textblock.c` and `laser.c` are correctly exposed as an overlap problem, not a solved split

The blueprint does something the older reports did not present in one place:

- `textblock.c` contributes a tiny shared-island span
- `laser.c` contributes a much larger suggested window
- those two planned spans overlap directly

That means the current retail evidence is already enough to define the neighborhood, but not enough to assert final file boundaries cleanly. The right next step is to work that block as one local skeleton problem.

### 5. Two DLL anchors are isolated enough to stay as direct split-now skeleton seeds

These remain clean single-anchor blocks:

- `dll/DIM/DIMboss.c`
- `dll/SH/SHthorntail.c`

The blueprint view confirms they do not need short-gap packet context before first-pass file work.

## Practical use

- Summary:
  - `python tools/orig/source_blueprints.py`
- Focus one neighborhood:
  - `python tools/orig/source_blueprints.py --search objanim objhits`
  - `python tools/orig/source_blueprints.py --search expgfx curves camcontrol`
  - `python tools/orig/source_blueprints.py --search textblock laser`
- Write neighborhood briefs:
  - `python tools/orig/source_blueprints.py --materialize-all`
  - writes one markdown brief per visible block under [source_blueprint_briefs/README.md](/C:/Projects/SFA-Decomp/docs/orig/source_blueprint_briefs/README.md)
- Machine-readable dump:
  - `python tools/orig/source_blueprints.py --format json`
- Spreadsheet-friendly dump:
  - `python tools/orig/source_blueprints.py --format csv`
- Tighten or relax the block-merging rule:
  - `python tools/orig/source_blueprints.py --max-gap-paths 4`
  - `python tools/orig/source_blueprints.py --max-gap-paths 12`

## How it fits

- Use `source_worklist.py` to decide whether an anchor is split-now, resize-first, or packet-style.
- Use `source_gap_packets.py` when you want the exact in-between filenames between two anchors.
- Use `source_blueprints.py` when you want those answers merged into one ordered skeleton neighborhood that a worker can recover directly.

The new value here is not new evidence. It is better packaging of the evidence already present in `orig/`.
