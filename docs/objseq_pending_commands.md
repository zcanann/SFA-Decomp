# Pending sequence-command queue

**Completion (2026-09-20):** `ObjSeq_ExecuteActionCommand` now matches 100% in
all five regions, and the complete EN TU is matching with an exact final DOL.
See [the completion report](objseq_action_matching.md) for compiler recovery,
source changes and regional source-link validation. The progress figures below
record the earlier investigation, before this completion.

The queue used by `ObjSeq_ExecuteActionCommand`,
`ObjSeq_RebuildCurveStateToFrame`, and `ObjSeq_update` holds 20 eight-byte
`ObjSeqPendingCmd0B` records. Its EN symbol is `lbl_8039944C`, at runtime-buffer
offset 0x2b34, with a retail BSS extent of 0xa0 bytes. The declaration and both
consumers previously used the unrelated `ObjSeqBgCmd` object/flags layout.
They now use the producer's actual record type.

| Offset | Field | Evidence |
| --- | --- | --- |
| 0 | `cmd`, pointer | Condition action stores the byte following its four-byte header; consumers pass it to `seqDoSubCmd0B`. |
| 4 | `commandCount`, signed halfword | Producer copies `cmd->param`; the interpreter loops over that many four-byte subcommands. This is not a repetition count. |
| 6 | `frame`, signed halfword | Producer snapshots `curFrame`; interpreter subcommand 4 restores `curFrame` and `prevFrame` from this argument. |

The producer guards the queue with `gObjSeqPendingCmd0BCount < 0x14` and then
advances the main command cursor by the block's subcommand count. Assertions
record every field offset, the eight-byte record size, and the 0xa0-byte table
extent. Global declaration order and the existing symbol identity are preserved.

## Earlier matching investigation

`ObjSeq_update` now computes its queue cursor with ordinary array indexing:

```c
entry = (ObjSeqPendingCmd0B*)(base + 0x2b34) + k;
```

This removes the previous pointer-to-integer-to-pointer arithmetic and lets
MWCC form the queue argument directly in r8. The address-add instruction
previously wrote r3 before the following instruction transferred it to r8.
The function remains 978 instructions, with differing instruction words
reduced from 274 to 273. This queue cleanup alone improves objdiff from **98.568504% to 98.578735%** in
all five regions. The complete EN TU reaches 99.83489% and stays `NonMatching`.

Every other function retains identical machine code, including the already
exact `ObjSeq_runBgCmds` and `ObjSeq_RebuildCurveStateToFrame`. The final
`reps` to `commandCount` field rename preserves the complete object byte-for-byte.

Later callback and allocation work is recorded in
[ObjSeq_update matching](objseq_update_matching.md).

## Action-command investigation

`ObjSeq_ExecuteActionCommand` remains at **99.960236%**. Native LLDB capture
reproduces the ordinary object and isolates its four instruction differences
to two compiler-generated GPR identities:

| Value | Virtual identity | Current | Retail |
| --- | --- | --- | --- |
| Payload address, `cmd + 1` | v152 | r3 | r0 |
| Queue index scaled by eight | v153 | r0 | r3 |

The sibling MWCC allocator model reproduces the capture. Its complete-color
query is UNSAT even allowing all named identities to permute. This only rules
out that captured graph/order search, not other source implementations.

Local pointer aliases, small inline queue/store helpers, alternative array
spellings, and signed/unsigned index casts reproduce the same swap. A complete
local record copy changes load/store ordering; explicit cursor and byte-offset
forms introduce additional instructions or different ordering. None of these
experiments is retained. The remaining work concerns temporary creation and
expression lowering, not another blind named-declaration permutation.

A follow-up capture after `ObjSeq_update` became exact independently reproduces
the complete ordinary object (SHA-256
`cf090915c966cd549e92f689d54800310bcbdfb9152f312091b87333ef64660e`).
It records 18 stages, 292 GPR nodes, 251 physical-color choices, and no
high-degree removals. Before global optimization, the payload `addi` already
defines v152 and the stride `slwi` defines v153; the combined entry base is
v154. The four final differences therefore originate in expression lowering,
not a spill retry or the pressure mechanism fixed in `ObjSeq_update`.

Additional probes of inline payload/entry getters, callback-style return
locals, store-helper argument orders, payload member views, single-word record
copies, and separate frame/index locals do not reverse those two identities.
Taking a local payload's address adds a stack store and widens the frame.
Explicit byte offsets commonly replace the displaced store with an indexed
store plus an extra address instruction. Incrementing a queue cursor or deriving
the next count from an offset also changes the instruction sequence. These
experiments are not retained. A further investigation should inspect the
front-end-to-PCode lowering of the assignment and its requested destination
registers, rather than repeat these source spelling families.

The compiler follow-up recovers `GC13_GenerateAdd` (0x4516e0, 845 bytes)
and `GC13_FindPostUpdateAddress` (0x448830, 197 bytes) in the sibling MWCC
project. Its `ExpressionLowering.h` exposes their consumer-backed expression
and type views. The hardened offline original/native oracle passes 5,488
cases, including child evaluation order, preferred-register forwarding,
wide-pointer normalization, multiply-fusion dispatch, and register-backed
post-update eligibility. See that project's
`docs/fixtures/objseq_expression_lowering_20260920.json`.

A named queue-base assignment inside the store lvalue preserves instruction
order but changes nine register operands; a separate assignment moves the
payload addition after the base calculation. Both agree with the recovered
preferred-register distinction, and neither is retained. The action function
still has its original four differences. The next unrecovered caller boundary
is the full assignment handler containing 0x44ff15 and its memory-store path
at 0x45044e; the recovered addition/post-update helpers do not claim to model
that complete handler or the preceding frontend propagation passes.


The next compiler pass recovers the complete `GC13_GenerateAssignment`
handler (0x0044fdb0, 2,602 bytes) and `GC13_AssignmentStoreGPR`
(0x004e07e0, 382 bytes). Hardened offline original/native comparisons pass
12,880 assignment cases and 3,120 store cases, respectively; the earlier
5,488 addition/post-update comparisons also pass after extending the shared
expression layout. The sibling fixtures are
`docs/fixtures/objseq_assignment_lowering_20260920.json` and
`docs/fixtures/objseq_gpr_store_20260920.json`. Compiler `ninja check` passes.

The full handler confirms that a scalar memory assignment lowers and forces
its RHS with requested register zero before evaluating its lvalue. A
register-backed local instead requests its metadata register. The store
emitter normalizes the address and selects displaced/indexed opcodes; it does
not independently forbid r0 for the scaled index. Nested RHS assignments to
existing locals, parameters, or a promoted record member collapse to the same
four differences. Keeping the payload live for the command-count load adds a
negative-offset load difference without correcting the swap; reloading the
stored pointer adds instructions. These experiments are not retained.

No additional action-command match is claimed. The retained source object
remains byte-identical to the LLDB-captured baseline above, and the function
remains 99.960236%. Assignment and store lowering are now executable models;
the unresolved step is finding a source construction whose preceding frontend
transforms retain a different temporary identity or interference pattern while
preserving the retail instruction sequence.

The subsequent `ObjSeq_update` investigation resolved its register partitions
and final three-register rotation. It now matches 100% in all five regions;
see [the callback and allocator findings](objseq_update_matching.md).

## Validation

- Original DOL hashes verified for EN, EN rev1, JP, PAL, and PAL rev1 before
  regional objdiff comparisons. PAL inputs came from the sibling SFA checkout.
- Only `ObjSeq_update` changes machine code in EN or function score in any region.
- Named symbol layouts and every non-text section remain identical; relocation
  sites, types, addends, target sections and target offsets remain identical.
- `clang-format --dry-run --Werror` passes for the TU.
- `ninja all_source build/GSAE01/ok` exits zero with the strict retail checksum.
