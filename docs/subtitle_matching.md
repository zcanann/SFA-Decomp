# Subtitle matching

Completed on 2026-09-07 with the common GC/1.3 compiler and a user-authorized
per-function optimization exception. All four functions (1,804 code bytes) and
all 3,104 data bytes match EN v1.0. `main/subtitle.c` is MatchingFor GSAE01.

`subtitleUpdateAndDraw` uses `#pragma optimization_level 2`; the source restores
the TU's configured level 1 immediately afterward. The other three functions
retain their existing profile. This is a matching workaround, **not evidence
that the original source contained a pragma**. The user authorized this fallback
after requesting further source-level investigation. The exception is recorded
in AGENTS.md and does not apply to other functions or units.

The final source-only probes tested an inline renderer, passing both tables to
that renderer, an incremented timestamp pointer, and signed/unsigned inline
output accessors. None recovered the retail renderer. The inline renderer
emitted 136 instructions with 22 differing rows, versus the baseline's 137 with
16; the timestamp pointer emitted 138 with 19. The output accessors retained
the baseline mismatch. The three existing exact functions remained exact.

Validation: `python3 configure.py --matching`, `ninja all_source`, the strict
`ninja` checksum target, and an objdiff whole-unit report. The matching link uses
the compiled subtitle object, and the resulting DOL equals the retail EN v1.0
DOL (SHA-1 `e750e8e894707a52446118a4b84f1b58b677b269`).

The investigation below records the original baseline, starting from staging
`d446e6dd2f`, before accepting this exception.

## Baseline mismatch

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
concrete regressions, so no whole-TU profile switch is accepted.

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

The confirmed TU remains intact. Alternative-profile matches alone do not
justify splitting it or introducing per-function pragmas; the retained pragma
is an explicit user-authorized exception. Replacing it with ordinary source
would require accounting for both the renderer’s shared index and the builder's
repeated loads under one profile.

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
