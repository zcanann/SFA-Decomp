# ObjHits_Update matching

`ObjHits_Update` matches **100%** in EN, JP, PAL, EN revision 1 and PAL
revision 1: all 434 instructions / 1,736 bytes. The previous score was
99.60368%, with 28 differing instruction words. The complete EN ObjHits TU
improves from 99.9312% to 99.95767%, with 51 of 54 functions exact. It remains
`NonMatching` because other functions and data still differ.

## Retained source

The list-building/reset pass now uses `listAttachedObj` and `attachedState`
for the attachment it resets, separately from the later collision-pass
`attachedObj` and the object's own `listState`. The reset state is read directly
from the canonical `anim.hitReactState` field, using the same narrow type cast
as the adjacent owner-state read. Both resets retain the existing inline
`ObjHits_ResetFrameContacts` helper.

Sweep setup initializes `nextEntry` before `entrySlotBase`, matching retail's
instruction order. Register-backed local declarations are ordered to match
allocation, including the relative order of `nextEntry` and `entrySlot`.
The scratch buffers retain their relative order and exact frame offsets.

These changes preserve object filtering, pair traversal, calls, contact reset
behavior, and collision arithmetic. No compiler settings, pragmas, assembly,
TU boundaries, globals, or shared accessors changed.

## Compiler investigation

The existing recovered GC/1.3 allocator and register-identity rules in
`../mwcc` were sufficient; no new compiler body was required. The compiler's
verified SHA-256 is
`4e502c38465500d4fda8d966b268151a6c74c730508e3d9b7efd23d1a6083715`.

After correcting setup instruction order, LLDB exposed a generated identity
for the reused attachment pointer. Fixed-graph solver queries rejected an
exact solution using named declaration order alone. Splitting the reset-pass
attachment and searching declaration order reached 99.769585%, leaving 17
instructions differing by an r6/r8 swap during list construction.

The remaining generated state identity required both a separate attachment
state local and the direct canonical-field read. Neither change alone removed
the swap. Together they reduced the remaining mismatch to seven instructions:
the two sweep cursors had r6/r7 exchanged. Swapping those declarations produced
the exact ordinary object. These are observed compiler consequences, not a
claim to have recovered the original variable names or declaration order.

The final LLDB capture has 23 stages, 434 aligned instructions and zero retail
differences. Its 191-node GPR graph replays simplification and all 153 physical
color choices exactly, without high-degree removals or spill retries. The
traced object is byte-identical to the ordinary compiler output, SHA-256
`507300345219482e3173ed481243445692d7797e2541c0af86b8b41cc7d28bbd`.

Reproduce the capture with:

```sh
python3 tools/tricky_backend_trace.py --unit main/main/objhits \
  --function ObjHits_Update --graph --output build/objhits_update/exact_trace
```

## Validation

- Hash-verified original DOLs precede all five regional comparisons. Each
  region improves from 99.60368% to 100%; no other function score changes.
- Only `ObjHits_Update` instruction bytes change in the complete EN object.
  All other 53 function bodies, allocated non-text sections and named symbol
  offsets/sizes are unchanged, including the newly exact `CheckHitVolumes`.
- Anonymous literal names are renumbered, but relocation sites, types,
  addends, destination sections/offsets, and named targets are unchanged.
- Formatting preserves the complete object byte for byte. The TU and
  `include/main/objhits.h` pass `clang-format --dry-run --Werror`.
- `ninja all_source build/GSAE01/ok` passes, including the unchanged strict
  retail DOL checksum. Since the TU remains `NonMatching`, this checks build
  integrity rather than claiming a complete ObjHits source link.
