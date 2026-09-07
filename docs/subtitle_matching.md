# Subtitle matching frontier

Measured on 2026-09-07 with the current common GC/1.3 compiler, starting from
staging `d446e6dd2f`. This investigation does **not** complete the TU:
`main/subtitle.c` remains NonMatching at 99.11308% fuzzy similarity, with three
of four functions and all 3,104 data bytes exact. No source or compiler-profile
change from the probes is retained.

## Current mismatch

`subtitleUpdateAndDraw` emits 137 instructions against retail's 134. Its three
extra instructions are in line-table indexing, not the subtitle-command loop:

- The timestamp check scales the current line index into a temporary. The next
  text lookup scales the original index again; retail keeps the scaled index.
- The temporary text-table alias introduces an extra register move.
- The final text lookup emits `add; lwz` where retail has `lwzx`.

The ordinary and diagnostic compiler objects agree byte for byte. The trace
captures six stages and replays the 88-node GPR graph and 51 color decisions.
The low optimization profile skips the global optimization passes seen in the
recently completed sky and screen-transition TUs. This locates the differences;
it does not establish that a clean source reconstruction is impossible.

## Whole-TU profile comparison

All rows keep GC/1.3, disabled scheduling, and the configured
`noauto,deferred` inline policy. `nopeephole` is retained except in the last row.
Cells below are emitted instruction counts / differing mnemonic-aligned rows;
the row count includes branches whose destinations move with function size.

| Optimization selection | Build line table | Stop | Update and draw |
|---|---:|---:|---:|
| Configured `level=1` | 240 / 0 | 46 / 0 | 137 / 16 |
| `level=2` | 222 / 107 | 44 / 23 | 134 / 0 |
| `level=3` | 368 / 324 | 46 / 1 | 134 / 0 |
| `level=1,cse` | 229 / 115 | 46 / 0 | 136 / 11 |
| `level=1,propagation` | 240 / 0 | 46 / 27 | 138 / 18 |
| `level=1,peephole` | 239 / 4 | 46 / 0 | 132 / 28 |

Explicitly enabling CSE or propagation at level 1 is live on this compiler.
Do not infer otherwise from old measurements that merely disabled passes
already absent at level 1. Higher levels recover the renderer but remove
retail loads in the builder, and level 3 also transforms its loops. Peephole
optimization merges a builder pointer move and comparison into `mr.`, and
removes the renderer's four retail color-narrowing instructions. These are
concrete regressions, so no profile switch is accepted.

## Source and storage checks

Direct array indexing, pointer-to-array views, inline line accessors, local
index/base lifetimes, and explicit shared byte offsets did not recover the
complete renderer. Artificial addressable single-element alias arrays can
change lowering but do not constitute recovered source structure.

The builder uses a common base for the three adjacent 256-entry arrays. A
single native owning record was therefore tested, retaining their retail
blocks/lines/times order and total size. It regresses the builder from 240 to
270 instructions and does not solve the renderer. Keep the independent arrays.
`textrender_drawbox.c` also initializes the block table, so an eventual storage
change must audit that consumer as well.

The confirmed TU remains intact. The alternative-profile matches provide
transformations to investigate, not permission to split it or introduce
per-function pragmas. A useful next experiment must account for both the
renderer’s shared index and the builder's repeated loads under one profile.

## Reproduction

```sh
python3 tools/strucdiff.py main/main/subtitle subtitleUpdateAndDraw
python3 tools/fn_flag_probe.py main/main/subtitle --all --absolute \
  --profiles as-configured,prop,nocse,noprop
python3 tools/tricky_backend_trace.py \
  --unit main/main/subtitle --function subtitleUpdateAndDraw --graph \
  --output build/flag_probe/subtitle_backend
```

The flag prober previously called a profile “sound” when it retained only one
of three existing matches, then asserted that the TU's flags or boundaries
must be wrong. It now lists lost matches explicitly and describes alternate
matches as diagnostic evidence requiring whole-TU review. Successful comparison
results remain visible even when a profile loses every existing match; an
unsuitable profile does not invalidate those measurements.
