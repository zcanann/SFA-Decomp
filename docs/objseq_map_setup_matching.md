# ObjSeq_onMapSetup matching investigation

With the game GC/1.3 compiler and the existing engine DLL 2 flags,
`ObjSeq_onMapSetup` is **99.789474%** matching in all five supported retail
versions: EN `GSAE01`, EN rev1, JP, PAL, and PAL rev1. Each input DOL was
verified against its configured hash before the regional comparisons.

The source now emits the retail function's 760 bytes / 190 instructions, up
from 99.210526% and 764 bytes. The first 135 instructions match. Six instructions
in the remainder differ only in register operands: the temporary word-indexed
base uses r3 instead of r10, and the handle cursor uses r31 instead of r29.
The other functions' machine code, allocated non-text sections, and non-text
symbol layouts are unchanged. The complete DLL remains `NonMatching`.

## Tail-loop reconstruction

The previous source wrote `marks[0]` twice for each of the last five slots.
Simply removing the duplicate causes MWCC to unroll the tail again, growing the
function to 984 bytes. Sharing the cleared signed-byte value between the first
two flag stores keeps the tail rolled without adding a memory access. Retaining
separate byte-indexed and word-indexed base lifetimes also improves the register
allocation. The duplicate write is now removed.

LLDB frontend and backend captures distinguish two unrollers. The frontend
`IRO_LoopUnroller` rejects this tail because its index is not initialized in the
preheader. The extra unroll instead occurs during the backend loop
transformations, after code motion and before late simplification. Inspection
of the GC/1.3 backend shows a loop-size-dependent unroll-factor limit. The
shared byte value affects this earlier representation, then simplifies away
in the final instructions. Ordinary and traced compiler outputs were checked
for identical object hashes.

Scoped tail cursors, pointer-role permutations, indexed accesses, and alternate
base expressions have not resolved the remaining registers. Direct native-table
experiments suggest a plausible path toward recovering the original loop, but
also change BSS ordering and offsets; those experiments were discarded.
Compiler settings and translation-unit boundaries are unchanged.

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
