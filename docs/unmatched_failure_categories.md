# Unmatched Failure Categories

Snapshot: `GSAE01` report after `c060bed9f`, generated with:

```sh
python3 tools/categorize_near_misses.py --min-pct 0 --max-size 0 --limit 2500
```

This is a heuristic first-diff taxonomy for all functions that have a
`fuzzy_match_percent` below 100 in `build/GSAE01/report.json`. It is not a proof
of the exact fix for any one function. Its job is to point sweeps at the most
common residual classes.

## Overall Counts

| Category | Functions | Bytes | First sweep |
|---|---:|---:|---|
| GPR register coloring / value spelling | 798 | 672256 | Try value-spelling changes: named locals, declaration order, saved pointer aliases, no-op conversion nodes, and avoid collapsing two semantic values into one expression. |
| Branch target / block layout | 495 | 383296 | Inspect switch/range guards, dead cases, imported empty branches, early-return shape, and block order. Many are real structure bugs, not branch-address noise. |
| Stack local layout / temp-slot order | 320 | 359200 | Reorder local declarations, merge/split stack arrays, check address-taken outparams, and audit Ghidra-split aggregates. |
| Mixed structural/codegen drift | 309 | 200744 | Do manual shape work first: source-set drift, wrong struct fields, missing inlines, bad widths, or imported temporaries. |
| Register coloring cascade | 117 | 69016 | Look for swapped loop variables or two live induction values; declaration order and explicit named temporaries are usually cheaper than broad rewrites. |
| Off-by-one/immediate constant | 59 | 87092 | Treat as likely source truth: parser skip counts, loop bounds, switch upper bounds, object offsets, and wrong constants. |
| Branch sense / control-flow shape | 33 | 14012 | Recheck condition polarity and whether Ghidra imported an inverted guard. |
| FP register coloring | 32 | 27944 | Try local declaration order, preserving separate FP temps, or literal/constant ownership changes. |
| Compare width/immediate/sign | 32 | 17472 | Audit signedness and pointer-vs-int compares (`cmpwi` vs `cmplwi`). |
| Loop bound or compare sense | 21 | 14324 | Recast `<= K` vs `< K+1`, loop start/end values, and table counts. |
| FP operand order / constant ownership | 9 | 38244 | Check whether the expression should use an earlier live constant instead of a visually similar later label. |
| Immediate/displacement constant | 3 | 2500 | Audit struct member ownership and swapped offsets. |
| Unknown/no parsed diff | 1 | 860 | Use `cosmetic_audit.py` or raw byte diff; disasm normalization can hide the only byte. |
| Size/symbol boundary drift | 1 | 200 | Check split/symbol boundaries and dead stripped tail stubs. |

## Top Source Files

These are the largest partial-function clusters and their dominant bucket:

| Source | Partial funcs | Dominant bucket |
|---|---:|---|
| `src/main/dll/player.c` | 128 | 41 register/value spelling, 36 branch/block layout |
| `src/main/dll/gameplay.c` | 53 | 23 mixed structural/codegen drift, 12 stack/temp layout |
| `src/main/track_dolphin.c` | 40 | 16 register/value spelling, 8 stack/temp layout |
| `src/main/dll/curves.c` | 36 | 13 register/value spelling, 7 branch/block layout |
| `src/track/intersect.c` | 34 | 14 stack/temp layout, 8 register/value spelling |
| `src/main/model.c` | 33 | 21 register/value spelling, 4 branch/block layout |
| `src/main/pi_dolphin.c` | 32 | 11 register/value spelling, 9 branch/block layout |
| `src/main/shader.c` | 30 | 16 register/value spelling, 4 stack/temp layout |
| `src/main/dll/baddie/Tumbleweed.c` | 29 | 12 register/value spelling, 7 branch/block layout |
| `src/main/dll/anim.c` | 29 | 13 branch/block layout, 8 register/value spelling |
| `src/main/dll/genprops.c` | 29 | 9 branch/block layout, 9 register/value spelling |
| `src/main/objprint.c` | 29 | 16 register/value spelling, 4 branch/block layout |
| `src/main/objseq.c` | 27 | 11 register/value spelling, 6 branch/block layout |
| `src/main/dll/objfsa.c` | 25 | 8 register/value spelling, 6 register-coloring cascade |
| `src/main/dll/DR/sandwormBoss.c` | 25 | 10 register/value spelling, 6 branch/block layout |
| `src/main/textrender.c` | 24 | 12 register/value spelling, 4 branch/block layout |
| `src/main/dll/baddieControl.c` | 24 | 7 register/value spelling, 6 branch/block layout |
| `src/main/sky.c` | 23 | 9 mixed structural/codegen drift, 7 register/value spelling |
| `src/main/dll/modgfx.c` | 22 | 16 register/value spelling, 3 branch/block layout |
| `src/main/object.c` | 22 | 6 register/value spelling, 5 branch/block layout |
| `src/main/audio.c` | 21 | 9 register/value spelling, 6 branch/block layout |

## Practical Sweep Order

1. Run the categorizer on the current tree before choosing a batch:

   ```sh
   python3 tools/categorize_near_misses.py --min-pct 99 --max-size 3000 --limit 200
   ```

2. For near-100 functions, prioritize exact source mistakes over allocator
   grinding:
   - `off-by-one/immediate constant`
   - `loop bound or compare sense`
   - `compare width/immediate/sign`
   - `FP operand order / constant ownership`

3. For broad file sweeps, use the dominant source-file bucket:
   - Register/value files: try declaration order, semantic temp names, saved
     pointer aliases, and expression splitting.
   - Branch/block files: inspect real control-flow structure, especially dead
     imported switch cases, inverted guards, and block order.
   - Stack/temp files: reconcile local stack aggregates before touching
     instruction-selection details.

4. After any fix, trust `report.json`, not a visually clean `--diff`. Refresh
   with the strict build loop from `CLAUDE.md`.

## Validation

This taxonomy has already produced a real sweep win. The
`compare width/immediate/sign` bucket flagged `EventHandler` as
`cmplwi r3,0` target vs `cmpwi r3,0` current. The root cause was the
`hwIsActive` type: MusyX/reference code declares `u32 hwIsActive(u32)`, while
this repo still had signed declarations in the shared header and one local
extern. Aligning the declaration/definition, plus adding the explicit unsigned
declaration to `synth_voice.c`, produced:

| Function | Before | After |
|---|---:|---:|
| `EventHandler` | 99.40000 | 100.00000 |
| `macHandle` | 99.26829 | 100.00000 |
| `macStart` | 99.37755 | 99.98980 |

Takeaway: for the signedness bucket, first audit shared callee declarations
against reference SDK/MusyX sources and existing local externs. A single wrong
return type can affect multiple caller functions.
