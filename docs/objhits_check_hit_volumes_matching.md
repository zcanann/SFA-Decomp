# CheckHitVolumes matching

`ObjHits_CheckHitVolumes` matches **100%** in EN, JP, PAL, EN revision 1 and
PAL revision 1: 898 instructions / 3,592 bytes. Its previous score was
99.38196%. The complete EN ObjHits TU improves from 99.84577% to 99.9312%,
with 50 of 54 exact functions; it remains `NonMatching`.

## Retained reconstruction

The mask-construction loops now have their own `maskIndexA` and `maskIndexB`
counters, separate from the sphere-pair traversal counters. The local
register-backed declarations are ordered to reproduce retail allocation.
The two packed linked-sphere traversals use `link <<= 4` rather than
`link = link << 4`.

Both shift spellings promote the unsigned halfword to `int`, shift a value
no larger than 65,535 by four, and truncate back to the unsigned halfword.
Their behavior is equivalent, but their compiler-generated temporary identities
are different. The compound assignment puts the zero-extended link in r6 and
the loop's constant one in r7, matching retail. With the same declarations and
separate counters, the expanded assignment retains ten differing instruction
words and scores 99.94432%.

The mask widths, signed literal `1`, partial fallback initialization,
collision arithmetic, call order and public interface remain unchanged.
No assembly, compiler flags, pragmas, artificial storage or TU splits were added.

## Compiler evidence

The existing sibling `../mwcc` GC/1.3 recovery and the local LLDB capture tools
were sufficient for this target; no additional compiler body was needed.
The verified compiler SHA-256 is
`4e502c38465500d4fda8d966b268151a6c74c730508e3d9b7efd23d1a6083715`.
The recovered object/register identity rules explain why source declaration
order and compiler-generated loop identities affect coloring.

The baseline emitted the correct instruction shapes and count, with 101
instruction words differing in their register operands. LLDB exposed generated
identities for the reused traversal counters. Separating the mask counters
made the traversal identities controllable through declarations. A local
captured-graph search predicted a declaration order with ten remaining
differences; ordinary compilation independently confirmed that prediction.
The compound shift removed the final r6/r7 swaps in both linked-sphere loops.

The exact capture records 22 stages and 898 aligned instructions with zero
retail differences. Allocation retries from a 267-node graph to a 352-node
graph. Only the final attempt is replayed: its simplification, one high-degree
removal (register 80, degree 29, weight 1,154), and 320 physical color choices
agree with the live compiler. The preceding spill selection is **not verified**
by this capture and is not claimed as explained.

Reproduce the capture with:

```sh
python3 tools/tricky_backend_trace.py --unit main/main/objhits \
  --function ObjHits_CheckHitVolumes --graph --final-allocation-attempt \
  --output build/objhits_check/exact_trace
```

The traced object is byte-identical to an ordinary build. Its SHA-256 is
`ba65288cb00246e8b32fa2b2eea24ffe5582ade34e61ba0bf36304c3bcda8ddb`.

## Validation

- All five original DOLs were hash-verified before regional comparison.
  Each region improves this function from 99.38196% to 100%; no other
  function score changes.
- Only this function's EN code bytes change. The other 53 bodies, allocated
  non-text sections, and named symbol offsets/sizes remain unchanged.
- Anonymous literal names are renumbered, but relocation sites, types,
  addends, destination sections and offsets, and named targets are unchanged.
- Formatting preserves the complete generated object byte for byte.
  The TU and `include/main/objhits.h` pass `clang-format --dry-run --Werror`.
- `ninja all_source build/GSAE01/ok` passes, including the unchanged strict
  retail DOL checksum. The TU remains `NonMatching`, so this checksum gates
  build integrity rather than claiming a complete ObjHits source link.
