# MWCC compiler RE — function/address maps

Groundwork for understanding `mwcceppc.exe`'s codegen decisions (register allocator,
scheduler, CSE, unroller) instead of black-box differential matching. Background:
the GC/Wii decomp community has **no** public RE of MWCC internals — this is greenfield.

## Why this is tractable
`mwcceppc.exe` (GC/2.0, ~2 MB x86 PE) retains its original **source filenames** and
`assert(cond, file, line)` strings. Each assert call site does
`push <line>; push offset <FILE.c>; push offset <cond>; call`, so a reference to a
source-filename string tells you which `.c` the enclosing function came from. The
backend is cleanly modularized into recognizable TUs — `Coloring.c` (register
allocator), `InterferenceGraph.c`, `SpillCode.c`, `Scheduler.c`, `IroCSE.c`,
`IroUnrollLoop.c`, etc.

## The tool
`tools/mwcc_assert_map.py <mwcceppc.exe>` (needs `pefile` + `capstone`):
- extracts all C-source-filename strings,
- linear-disassembles `.text` (resyncing past data gaps),
- collects `call` targets + prologues as function starts,
- attributes each assert reference to its enclosing function + recovers the line number,
- infers each TU's contiguous **address band** from its assert anchors and lists every
  function start in that band.

Run: `python3 tools/mwcc_assert_map.py build/compilers/GC/2.0/mwcceppc.exe`
(GC/2.0 = the `"lib": "main"` game code; byte-identical to 2.0p1.)

Output: `docs/mwcc_re/assert_map_GC2.0.txt`.

## How to read the map
- `<-- assert anchor` = function provably in that `.c` (contains its assert).
- untagged funcs in a band = inferred same-TU (call-target inside the anchor band).
- `WARNING: band also contains anchors from BitVector.h` etc. = header-inlined asserts;
  expected noise, not a misattribution of the TU itself.

## Limitations (v1)
- Only TUs that **contain asserts** are anchored; bands run first-anchor..last-anchor, so
  functions before/after the anchored region of a TU are missed. The biggest pass
  (`Coloring.c`) is under-covered — treat bands as a lower-bound seed, not a full listing.
- Function starts come mainly from direct `call` targets; never-directly-called functions
  (tail-called/indirect) are missed.

## Using it for the actual goal
1. **Debugger (recommended first):** breakpoint the `Coloring.c` / `Scheduler.c` function
   entries while compiling a stuck `.c`, and dump the interference graph / allocation
   order. This converts the #108/#130 "within-class regalloc scramble" frontier from blind
   permutation into deterministic ground truth.
2. **Ghidra/IDA:** import the anchors as named functions (e.g. `Coloring__<va>`) to seed a
   static read of the allocator. IDAMagicStrings can auto-rename by source file.
