# DetectObjectPair matching

`ObjHits_DetectObjectPair` matches **100%** in EN, JP, PAL, EN revision 1 and
PAL revision 1: 308 instructions / 1,232 bytes. The previous score was
99.902596%, with six differing floating-point register operands. The complete
EN ObjHits TU improves from 99.95767% to 99.96229%, with 52 of 54 functions
exact. It remains `NonMatching` because other functions and data still differ.

## Retained source

`ObjHits_SweepPointDistance` now expresses its result directly using the
existing `SQUARE` macro from `include/global.h`. It keeps the same sum grouping,
`Z² + (X² + Y²)`, and the same projected-coordinate differences. The helper's
reused `delta` and three squared-component temporaries are removed. The
caller, collision decisions, nearest-distance updates and response logic are
unchanged.

The macro arguments contain only arithmetic and non-volatile reads. The
compiler shares their repeated expressions; the final code contains no extra
loads or calculations. No new macro, additional helper, compiler flag, pragma,
assembly, layout or TU-boundary change is needed.

## Compiler evidence

The compiler SHA-256 is
`4e502c38465500d4fda8d966b268151a6c74c730508e3d9b7efd23d1a6083715`.
Existing `../mwcc` allocator and expression-walker reconstructions guided the
LLDB investigation; no additional compiler body was retained for this result.

The baseline has the correct instruction count, operations and order, but
keeps object B's Y coordinate in f9 and Z coordinate in f7. Retail uses f7
for Y and f9 for Z; X already occupies f8. Those values are shared between
the projection calculation and the swept-distance helper.

The frontend trace first exposes the shared-coordinate assignments after
`IRO_CommonSubs`. With the sequential helper, the optimizer creates shared
loads in Z/X/Y order, despite placing their initial assignments into the
caller's expression trees. Declaration order alone cannot reorder these
generated identities. Reordering the helper statements instead changes the
arithmetic instruction order, so that approach was rejected.

Expressing the squared terms directly lets common-subexpression elimination
choose the shared values within the complete expression tree. This reproduces
the retail register operands while preserving all instruction order and
floating-point operations. Replacing the expression macro with a scalar inline
square function was also tested and does not reproduce this code generation.
The evidence establishes the retained expression's output, not the original
source spelling or macro provenance.

The exact backend trace records 13 stages and 308 aligned instructions with
zero differences. Its 126-node FPR graph replays simplification and all 91
physical color choices exactly, without high-degree removals or spill retries.
The traced object is byte-identical to an ordinary build, SHA-256
`42140fefb6e931d4feba5fa96909f2693753db972d08a35e687d4c95a11713c4`.

Reproduce the captures with:

```sh
python3 tools/mwcc_frontend_trace.py --unit main/main/objhits \
  --function ObjHits_DetectObjectPair --output build/objhits_pair/frontend_exact
python3 tools/tricky_backend_trace.py --unit main/main/objhits \
  --function ObjHits_DetectObjectPair --graph --register-class fpr \
  --output build/objhits_pair/exact_trace
```

## Validation

- Original DOL hashes verified before all five regional comparisons. Each
  region improves from 99.902596% to 100%; no other function score changes.
- Only this function's EN instruction bytes change. The other 53 bodies,
  allocated non-text sections, and named symbol offsets/sizes remain unchanged.
- Anonymous literal names are renumbered, but relocation sites, types,
  addends, destination sections/offsets and named targets are unchanged.
- Formatting preserves the complete object byte for byte. The TU and
  `include/main/objhits.h` pass `clang-format --dry-run --Werror`.
- `ninja all_source build/GSAE01/ok` passes, including the unchanged strict
  retail DOL checksum. Since the TU remains `NonMatching`, the checksum gates
  build integrity rather than claiming a complete ObjHits source link.
