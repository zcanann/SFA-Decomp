# ObjSeq_onMapSetup matching investigation

With the game GC/1.3 compiler and the existing engine DLL 2 flags,
`ObjSeq_onMapSetup` is **99.947365%** matching in all five supported retail
versions: EN `GSAE01`, EN rev1, JP, PAL, and PAL rev1. Each input DOL was
verified against its configured hash before the regional comparisons.

The source emits the retail function's 760 bytes / 190 instructions. This pass
improves the match from 99.789474%; the preceding pass improved it from
99.210526% / 764 bytes. Only two instructions now differ, both because the
word-indexed address temporary uses r3 instead of r10:

```text
retail: add r10,r3,r0       source: add r3,r3,r0
retail: addi r29,r10,13284  source: addi r29,r3,13284
```

The other 188 instructions match. Other functions' machine code, allocated
non-text sections, and non-text symbol layouts are unchanged. The complete DLL
remains `NonMatching`.

## Loop reconstruction

The bulk loop processes ten groups of eight slots. Indexing its tables by
`group * 8` lets MWCC generate the pointer induction variables, instead of
advancing twelve source-level pointer cursors. Advancing the group counter
before the slot counter preserves the retail instruction order. Declaring the
count cursor before the handle cursor then reproduces the tail's r29 handle
register. Neither counter adds instructions to the resulting function.

The preceding pass removed a duplicate `marks[0]` store for each of the last
five slots. Sharing the cleared signed-byte value between the first two flag
stores keeps the tail rolled without adding a memory access. Simply removing
the duplicate from the older source caused MWCC to unroll the tail again,
growing the function to 984 bytes.

LLDB captures distinguish two unrollers. The frontend `IRO_LoopUnroller`
rejects the separately written tail because its index is not initialized in
the preheader. The unwanted extra unroll occurs during backend loop
transformations, after code motion and before late simplification. The
backend's loop-size-dependent limit sees the shared byte value before it
simplifies away in the final instructions. Ordinary and traced compiler
outputs were checked for identical object hashes.

Register-graph replay explains the remaining difference. In an isolated
native-array experiment, compiler-generated loop setup reuses the float
address virtual register for the word-indexed base. The current source gives
that base a separate virtual register. The experiment reproduces all retail
register choices but puts the arrays in `.data` instead of retail `.bss`; it
was discarded. Native uninitialized-array experiments instead change BSS
allocation order. Neither is an acceptable storage reconstruction.

Scoped cursors, pointer-role permutations, indexed-tail forms, and alternate
base expressions have not resolved the remaining temporary. Compiler settings
and translation-unit boundaries are unchanged.

## Reset oracle

`tools/objseq_map_setup_probe.py` executes the complete function in Unicorn PPC
emulation. It verifies the EN DOL against its configured hash before running.
The expectations come from the retail stores, independently of the source
overlay: twelve tables across 85 slots, seven globals, 1,027 writes, untouched
padding and guards, and callee-preserved registers.

Install the optional `unicorn` and `pyelftools` packages, then run:

```sh
python3 tools/objseq_map_setup_probe.py --retail-only
python3 tools/objseq_map_setup_probe.py --object path/to/candidate/2.o
```

Retail and the improved source pass all four deterministic initial storage
patterns, including the exact write count. The oracle supplements objdiff and
does not establish an exact assembly match.

Validation: `ninja all_source` passes, the strict matching build reports
`build/GSAE01/main.dol: OK`, and `clang-format --dry-run --Werror` passes for
the active TU. Running the formatter introduced no additional source changes.
