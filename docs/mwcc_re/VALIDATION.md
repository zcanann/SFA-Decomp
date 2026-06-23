# Validation: the decompiled allocator reproduces a real compilation

**Result: the decompiled `Coloring.c` model predicts every register choice in a
byte-identical real compile.** No hand-waving — measured against the live compiler.

## Setup
- Unit: `src/main/dll/LGT/lgtcontrollight.c` (`-O4,p -opt nopeephole,noschedule`,
  so the output is pure register-allocation — no scheduling/peephole noise).
- Ran `mwcceppc.exe` under `wibo` + `gdb`, breaking inside `Color_Select`
  (0x508900) at the assignment sites, and dumped the per-class register tables.
- The `.o` produced under the debugger is **byte-identical** to the project's
  built `build/GSAE01/src/main/dll/LGT/lgtcontrollight.o` — so the registers
  observed ARE the real compilation's, not a perturbed run.

## What the model predicted vs. what happened
The decompiled `Select` says: register = **lowest set bit of the available mask**,
where the mask = the class's allocatable set minus every interfering neighbor's
register. Checked over **all 87** primary assignments in the TU:

```
chosen == lowest-set-bit(avail):  87/87 PASS, 0 FAIL
```

Non-trivial cases (interference actually cleared low bits — proving it's not just
"always r0"):
- avail=0x1ff0 (r0,r3 cleared) → chose r4
- avail=0x1ff8 (r0 cleared)    → chose r3
- avail=0x3ffe (r0 cleared)    → chose r1

## The register tables (dumped from the live compiler, image base 0x400000)
Primary allocation mask comes from `GetAllocRegMask` (0x4fe4d0) over table
`0x5e3b68[class*32 + i]`:
- **GPR (class 4)** order = `[0, 3,4,5,6,7,8,9,10,11,12]` (the volatiles r0,r3–r12)
- **FPR (class 3)** order = `[0..13]` (f0–f13 volatiles)

Fallback pool `GetReservedReg` (0x4fe470) over table `0x5e3e68[class*32 + i]`,
used only when the primary mask is empty (web interferes with every volatile):
- **GPR (class 4)** pool = `[31,30,29,28,…,15,14]` (all 18 saved GPRs, **r31-first
  descending**), walked by a persistent rotating counter `0x5e97d4[class]`.
- **FPR (class 3)** pool = `[31,30,…,14]` (saved FPRs, f31-first).

## The complete, validated allocation rule
1. **Volatiles first, lowest-numbered free** (87/87 exact, incl. neighbor clears).
2. **Saved registers only on volatile exhaustion** — i.e. when a web interferes
   with *all* volatiles (classically: live across a call / across the function).
   Handed out **r31, r30, r29 … descending** in the order webs hit the fallback.
   Observed fallbacks here: `F 31, F 30, F 31` (saved r31, r30, and f31) — and the
   function's asm uses exactly r31, r30, f31 + volatiles. 3/3 exact.

## Why this matters for matching
This mechanically explains the project's hardest intuitions, now proven:
- "Value X wants a saved register" ⟺ X is **live across all volatiles** (a call,
  or a whole-function live range). Force/avoid that and you move X in/out of
  r14–r31. No knob — a real lifetime change.
- "Which saved register" (r31 vs r30 vs …) ⟺ the **order** webs hit the fallback,
  which follows web creation/coloring order ⟹ the decl/first-use-order lever, with
  the mechanism finally pinned (LEVERS.md lever 2/3).
- A volatile register diverging ⟺ a different interference set cleared a different
  low bit. Fix the liveness, not the spelling.

## Second experiment — saved-register-heavy unit (`src/main/fileio.c`)
Also byte-identical to the project build. Results:
- primary (volatile) assignments: **63/63** lowest-free, 0 spills.
- **19 fallback (saved-register) assignments**, handed out in order:
  `31 30 | 31 30 29 28 | 31 30 29 28 27 26 | 31 30 29 28 27 26 25` (distinct
  {25,26,27,28,29,30,31}). The resets to 31 are function boundaries: **each
  function allocates its saved registers r31, r30, r29 … descending**, in coloring
  order. So "the Nth long-lived web (in coloring order) gets the Nth saved reg
  counting down from r31" — which is exactly the blog's r31-vs-r29 puzzle, now
  mechanical: r29 == the 3rd web to need a saved register.

## Confidence
- Volatile path: **rigorously** validated (87/87 + 63/63, interference cases, two
  byte-exact .o's).
- Saved-register path: validated on **22 fallbacks across two functions/files**,
  clean r31-descending-per-function. The fallback is interference-correct because
  Select ORs each newly-introduced saved reg back into the running mask
  (0x5089d3), so later interfering webs clear it and pull the next one down.
- Harness is reusable: `tools/mwcc_re/validate_select.sh <unit.c>` (or
  `select_dump.gdb` directly); swap the `-c <unit>.c` to validate any function.
