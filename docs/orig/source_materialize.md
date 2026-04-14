# Retail Source Materialization

This pass turns the `orig/` audit work into concrete files under `src/` without touching the active build configuration.

## Tool

- `python tools/orig/source_materialize.py`
  - Copies literal source/header artifacts preserved on disc into `src/disc_artifacts/`.
  - Generates non-built `.c` stubs for EN `main.dol` source-recovery candidates directly into `src/`.
  - Can also promote weak EN candidates when the same source tag repeats across multiple bundled retail versions.
  - Writes a machine-readable manifest to [source_materialize.json](/C:/Projects/SFA-Decomp/docs/orig/source_materialize.json).
  - Treats previously generated stubs as managed outputs, so reruns can refresh them in place while still refusing to overwrite unrelated real sources.

## What It Materialized

The current run produced two different classes of output.

### 1. Exact disc artifacts

These are copied straight from `orig/GSAE01` with the `.new` / `.bak` suffixes normalized away:

- [English.c](/C:/Projects/SFA-Decomp/src/disc_artifacts/binary/Boot/English.c)
- [French.c](/C:/Projects/SFA-Decomp/src/disc_artifacts/binary/Boot/French.c)
- [German.c](/C:/Projects/SFA-Decomp/src/disc_artifacts/binary/Boot/German.c)
- [Italian.c](/C:/Projects/SFA-Decomp/src/disc_artifacts/binary/Boot/Italian.c)
- [Spanish.c](/C:/Projects/SFA-Decomp/src/disc_artifacts/binary/Boot/Spanish.c)
- [English.c](/C:/Projects/SFA-Decomp/src/disc_artifacts/gametext/Boot/English.c)
- [French.c](/C:/Projects/SFA-Decomp/src/disc_artifacts/gametext/Boot/French.c)
- [German.c](/C:/Projects/SFA-Decomp/src/disc_artifacts/gametext/Boot/German.c)
- [Italian.c](/C:/Projects/SFA-Decomp/src/disc_artifacts/gametext/Boot/Italian.c)
- [Japanese.c](/C:/Projects/SFA-Decomp/src/disc_artifacts/gametext/Boot/Japanese.c)
- [Spanish.c](/C:/Projects/SFA-Decomp/src/disc_artifacts/gametext/Boot/Spanish.c)
- [starfox.h](/C:/Projects/SFA-Decomp/src/disc_artifacts/audio/starfox.h)

These are the strongest possible recovery wins because they are not inferred.

### 2. Retail-backed source stubs

These files are generated placeholders, not source-truth. Each one carries:

- the retail EN `main.dol` string address
- the exact retail string text
- any retail-authored function label extracted from that string
- current EN xrefs resolved through `config/GSAE01/symbols.txt`
- cross-version bundle evidence when PAL, JP, or EN rev1 preserve the same source tag
- debug-side path/function hints kept clearly separate from retail evidence

Current generated stubs:

- [camcontrol.c](/C:/Projects/SFA-Decomp/src/dll/CAM/camcontrol.c)
- [curves.c](/C:/Projects/SFA-Decomp/src/dll/curves.c)
- [laser.c](/C:/Projects/SFA-Decomp/src/dll/CF/laser.c)
- [DIMboss.c](/C:/Projects/SFA-Decomp/src/dll/DIM/DIMboss.c)
- [SHthorntail.c](/C:/Projects/SFA-Decomp/src/dll/SH/SHthorntail.c)
- [objanim.c](/C:/Projects/SFA-Decomp/src/main/objanim.c)
- [expgfx.c](/C:/Projects/SFA-Decomp/src/unknown/expgfx.c)
- [n_attractmode.c](/C:/Projects/SFA-Decomp/src/unknown/n_attractmode.c)
- [objHitReact.c](/C:/Projects/SFA-Decomp/src/unknown/objHitReact.c)
- [textblock.c](/C:/Projects/SFA-Decomp/src/unknown/textblock.c)

The `unknown/` outputs are deliberate. Retail evidence was strong enough to justify a file, but not strong enough to justify a directory assignment yet.

Two immediate examples of why this matters:

- [objanim.c](/C:/Projects/SFA-Decomp/src/main/objanim.c) now carries both the retail label `setBlendMove` and the debug-side bridge `Object_ObjAnimSetMove`.
- [textblock.c](/C:/Projects/SFA-Decomp/src/unknown/textblock.c) now materializes a concrete `Init` placeholder from the retail string even without any usable debug-side names.
- [curves.c](/C:/Projects/SFA-Decomp/src/dll/curves.c) now records the JP-only alias `hcurves.c` next to the shared `MAX_ROMCURVES exceeded!!` warning.
- [n_attractmode.c](/C:/Projects/SFA-Decomp/src/unknown/n_attractmode.c) is now present because the same weak source tag repeats in EN v1.0, EN rev1, PAL, and JP.

## Skips That Matter

- `dvdfs.c` was not materialized as a stub because the active tree already has [dvdfs.c](/C:/Projects/SFA-Decomp/src/dvd/dvdfs.c).

## Practical Use

- Regenerate everything:
  - `python tools/orig/source_materialize.py`
- Also include debug-path-only files that do not yet have an EN xref:
  - `python tools/orig/source_materialize.py --include-debug-path-only`
- Also include weak EN candidates that are repeated across multiple bundled retail versions:
  - `python tools/orig/source_materialize.py --include-cross-version-weak`

The intent is not to declare these files solved. The intent is to reduce the activation energy between "retail evidence exists" and "there is a concrete file in-tree someone can start recovering right now."
