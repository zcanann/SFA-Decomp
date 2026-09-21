# ObjSeq_update matching

Current result: **100%** in EN, EN rev1, JP, PAL, and PAL rev1. All 978
instructions match. The complete EN TU reaches **99.99766%** and remains
`NonMatching`: only `ObjSeq_ExecuteActionCommand` has instruction differences.

## Recovered callback contract

`ObjAnimSequenceConditionCallback` takes three arguments:

```c
int callback(void* context, u8* object, int conditionOpcode);
```

The old typedef and invocation omitted the third argument. This was a real
source-level ABI defect, not just an allocation preference. Retail loads the
condition opcode into r5 and retains it through dispatch to the callback.
The three registered handlers independently corroborate the contract:

- `warpstone_testEvent` switches on its third `option` argument, including 0x14.
- `PaymentKiosk_testEvent` switches on its third `eventId` argument.
- `ShopKeeper_handlePromptChoice` tests its third `dispatch` argument.

The typedef in `include/main/objanim.h` and the call in
`ObjSeq_CheckConditionOpcode` now include that argument. All three handler
objects remain byte-identical after rebuilding with the corrected shared header.
Their existing casts remain necessary for their differing context/unused-argument
and return types.

## Other retained allocation fixes

Caching `sequenceControlFlags` in a `u8 controlFlags` local makes its load and
the restart decision use retail's r4/r3 pair. The declaration position affects
allocation. This change alone improved 98.578735% to 98.61452%.

The final timed-stream slot assignment explicitly casts through `u8` and then
`s8`. It preserves signed slot interpretation while making MWCC load the raw
byte into r0 and sign-extend into r4, as retail does. Omitting the unsigned view
produces `lbz r4` followed by `extsb r4,r4`. Moving that byte load into a separate
statement instead puts it before the -1.0f literal load and changes instruction
order. The retained expression changes neither slot semantics nor storage layout.

These source changes build at the existing GC/1.3 TU profile. No compiler flags,
per-function pragmas, assembly, globals, or TU boundaries were changed.

## Resolved allocator constraint

At the 98.69632% checkpoint, native LLDB capture reproduced the ordinary
complete object exactly. Retail projection established that only these three
identities required different physical colors:

| Value | Virtual | Current | Retail | Referencing instructions |
| --- | --- | --- | --- | --- |
| Object parameter | v32 | r29 | r30 | 49 |
| Sequence state | v52 | r30 | r31 | 177 |
| Runtime-buffer base | v104 | r31 | r29 | 29 |

One instruction references two of these values, so the counts total 255 while
254 instruction words differ. Placement now correctly uses r28.

The previous low-degree-only search model cannot replay this function. The
existing full `replay_simplification` implementation does reproduce it, including
three high-degree choices. Its final removals are:

| Value | Virtual | Removal | Degree | Weight |
| --- | --- | --- | --- | --- |
| Repeat counter | v49 | High degree | 31 | 41 |
| Frame step | v48 | High degree | 30 | 65 |
| Placement | v53 | High degree | 29 | 325 |
| Object | v32 | Low degree | 28 | 4157 |
| Sequence state | v52 | Low degree | 27 | 19743 |
| Buffer base | v104 | Low degree | 26 | 491 |

The threshold is 29. These are simplification choices, not actual stack spills.
Coloring reverses the removal order, explaining the remaining r31/r30/r29
assignment. The corrected third callback argument is precolored to r5 and changes
this pressure calculation; omitting it previously left placement in the wrong
register too.

Reproduce the capture and retail projection with:

```sh
python3 tools/tricky_backend_trace.py \
  --unit main/dlls/engine/2/2 --function ObjSeq_update --graph \
  --output build/objseq-update-trace
python3 tools/mwcc_retail_registers.py \
  build/objseq-update-trace/trace.json --function ObjSeq_update
```

The final source stores the callback result in a local before returning it:

```c
if (cb != NULL) {
    int result = cb(state->callbackContext, (u8*)obj, conditionOpcode);
    return result;
}
```

Although the local disappears from the emitted instructions, MWCC retains an
additional fixed r3 alias in the interference graph. This raises the final
three values' degree by one. The buffer base is consequently selected as a
fourth high-degree removal, before the object and sequence state:

| Value | Virtual | Removal | Degree | Weight | Final register |
| --- | --- | --- | --- | --- | --- |
| Repeat counter | v49 | High degree | 32 | 41 | r26 |
| Frame step | v48 | High degree | 31 | 65 | r27 |
| Placement | v53 | High degree | 30 | 325 | r28 |
| Buffer base | v105 | High degree | 29 | 491 | r29 |
| Object | v32 | Low degree | 28 | 4157 | r30 |
| Sequence state | v52 | Low degree | 27 | 19743 | r31 |

The final native capture contains 469 GPR nodes and 21 stages. Simplification
and all 422 physical-color choices replay successfully. Retail projection
requires zero color changes, and the traced complete object is byte-identical
to the ordinary build. This is evidence for the compiler effect of the local;
it does not prove the original author's exact source spelling.

Declaration reordering of the original object/state/placement locals, simpler
state aliases, merged lookup temporaries, and local records did not complete the
match. Opaque-parameter experiments changed identities but also disturbed the
prologue and are not retained. Do not treat the low-degree solver's replay
failure as evidence that the captured graph is invalid, or claim its UNSAT
results for this high-pressure function.

## Verification

- Verified all five original DOL hashes before regional objdiff comparisons;
  PAL inputs came from the sibling SFA checkout.
- `ObjSeq_update` improves from 98.578735% to 100% in every region.
- Only `ObjSeq_update` changes machine code/function score. `ObjSeq_runBgCmds`
  remains 100%, and `ObjSeq_ExecuteActionCommand` remains 99.960236%.
- Named symbol layouts, non-text bytes/sizes/alignment, and resolved relocation
  sites/types/addends/targets remain unchanged.
- All three registered condition-callback handler objects are byte-identical.
- `ninja all_source build/GSAE01/ok` passes with the strict retail checksum.
- `clang-format --dry-run --Werror` passes for the TU. The shared header edit is
  restricted to its callback typedef.
