# Retail source boundary worklist

This pass turns the existing `orig/` source-tag tooling into one boundary-planning queue.

The repo already had separate reports for:

- retail source-name recovery
- current EN source islands
- debug-side source-order corridors
- exact debug split size comparisons

What was still missing was one answer to the practical question:

> Which retail-backed file boundary should we recover next, and should we split it now, expand it, shrink it, or treat it as a corridor packet first?

## Tool

- `python tools/orig/source_worklist.py`
  - merges the committed `source_boundaries.py`, `source_corridors.py`, and `source_skeleton.py` signals
  - keeps the retail EN xref span, debug split size, source-order corridor neighbors, and shared-island context together
  - can emit machine-readable JSON or ready-to-work packet briefs under [source_worklist_packets/README.md](/C:/Projects/SFA-Decomp/docs/orig/source_worklist_packets/README.md)
  - classifies each source into one of:
    - `split-now`
    - `expand-window`
    - `shrink-window`
    - `shared-island`
    - `corridor-packet`
    - `seed-only`
    - `no-en-xrefs`

## Current highest-leverage findings

The current symbol map has absorbed the earlier clean `split-now` wins. A fresh
`python tools/orig/source_worklist.py` run now reports no remaining clean
split-now candidates; the useful work is in one shrink job and four packet /
ownership jobs.

### 1. `objanim.c` is still real, but the current EN seed is too wide

- `objanim.c` -> `main/objanim.c`
- retail label: `setBlendMove`
- current EN seed: `0x8002EB54-0x80030688`
- debug target size: `0x3A8`
- best compact candidate from the current pass: `0x8002EB54-0x8002F50C`

This is not yet a clean split-now file. It is a shrink-first target.

### 2. `expgfx.c`, `laser.c`, `SHthorntail.c`, and `objHitReact.c` are packet work

- `expgfx.c`
  - current EN seed: `0x8009DDEC-0x8009FCDC`
  - strongest retail xref density among the unsized cases
  - still best handled as a corridor packet before a final file boundary is claimed

- `laser.c`
  - retail label: `Init`
  - current EN seed: `0x80209074-0x802090A0`
  - suggested ownership packet: `0x80209074-0x802099A8`
  - overlaps existing `laser_unsupported.c`, `laserObj.c`, `fire.c`, `textblock.c`, and adjacent object stubs

- `SHthorntail.c`
  - current EN seed: `0x801D5174-0x801D550C`
  - remains a near-fit retail anchor, but the current owner is `dll_1E8.c`
  - handle as an ownership packet before moving the source boundary

- `objHitReact.c`
  - current EN seed: `0x800353A4-0x80035630`
  - sits between `objhits.c` and the `objlib.c` / `objprint.c` corridor
  - best handled as a corridor packet before a final narrow file boundary is claimed

## Low-signal leftovers

Two names still matter, but do not yet resolve to an EN work window:

- `dvdfs.c`
- `n_attractmode.c`

These stay useful as naming / SDK context, but they are not current split targets.

## Practical use

- summary:
  - `python tools/orig/source_worklist.py`
- inspect one file or action:
  - `python tools/orig/source_worklist.py --search SHthorntail`
  - `python tools/orig/source_worklist.py --search expand-window`
  - `python tools/orig/source_worklist.py --search corridor`
- spreadsheet dump:
  - `python tools/orig/source_worklist.py --format csv`
- machine-readable dump:
  - `python tools/orig/source_worklist.py --format json`
- packet briefs:
  - `python tools/orig/source_worklist.py --materialize-all`
  - writes one markdown packet per visible work item under [source_worklist_packets/README.md](/C:/Projects/SFA-Decomp/docs/orig/source_worklist_packets/README.md)

## Why this matters

The bundled `orig/` leftovers were already good enough to name several files, but the hard part was deciding what kind of recovery job each one actually represented.

This worklist makes that distinction explicit:

- split the near-fit DLL files now
- expand the undersized seeds before naming them
- shrink the oversized seed before materializing it
- keep packet-style cases grouped until the surrounding corridor is understood

The packet export closes the last handoff gap: a worker can open one generated markdown brief and immediately see the recommended EN window, the functions inside it, and the corridor neighbors that bound the next split attempt.
