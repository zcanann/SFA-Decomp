# ObjSeq action-command completion

`ObjSeq_ExecuteActionCommand` now matches all 503 instructions (2,012 bytes)
in EN, JP, PAL, EN revision 1 and PAL revision 1. The previous retained source
scored 99.960236% in each region. The complete EN `dlls/engine/2/2.c` unit
now scores 100% and is enabled in the matching source link. JP and EN revision
1 are also recorded in their matching manifests after isolated source-link
verification. Compiler version, optimization flags and TU boundaries are unchanged.

## Source reconstruction

The remaining mismatch was the register allocation of the pending-condition
queue's payload and stride. The condition arm now captures
`gObjSeqPendingCmd0BCount` in `pendingIndex` in the bounds check. The first two
stores use that captured index; the third retains the global post-increment.
Typed field views express each eight-byte record stride with `sizeof` ratios
and recover field offsets with `offsetof(ObjSeqPendingCmd0B, ...)`.

This preserves the runtime buffer's existing scratch-pointer storage shape.
An ordinary cached-index struct-array spelling emits two extra instructions;
independent field views without the cached index retain the four register
mismatches. Extending the cached index through the global update also changes
code generation. The retained expression therefore records the proven index
lifetimes as well as the queue's recovered field layout.

Comparing complete EN objects before and after this final change showed that
only `ObjSeq_ExecuteActionCommand` instruction bytes changed. Named symbol
layouts, resolved relocations and all non-text section bytes were unchanged.
The formatted source object SHA-256 is
`f08ad31311e0573920d0b1fc569693767b2a1fc2dcec41f572aa83ac22870e16`.

## Compiler recovery and LLDB evidence

The sibling `../mwcc` project gained four GC/1.3 source files reconstructing
five original bodies, totaling 536 bytes:

- `IROExpressionWalk.c`: recursive preorder/postorder expression traversal.
- `IROExpressionRange.c`: expression-range extension and first-node lookup.
- `IROMutationPredicate.c`: opcode-table mutation classification.
- `IRODeadAssignment.c`: removal of a referenced dead assignment.

The connected original/native oracles passed 3,590 traversal/range cases and
5,248 dead-assignment/predicate cases. Original machine-code execution was
confined to hardened offline Docker. Dependency adapters and unrecovered
caller liveness analysis are explicitly documented in the sibling fixtures;
these are semantic reconstructions, not claimed Win32 binary matches.
`ninja check` passed in `../mwcc`.

LLDB frontend capture exposed the removal of a nested payload assignment,
explaining why that attempted source anchor did not survive optimization.
The successful source instead gives the shared stride an object-backed
frontend temporary. Backend capture records 18 stages and 503 aligned
instructions with zero differences; the traced object is byte-identical to
the ordinary compiled object. Its GPR graph has 290 nodes and 249 physical
choices, compared with 292 and 251 before the change, with no high-degree
removals. At the queue stores, the payload is allocated to r0 and the shared
stride to r3 as in retail.

Local reproducible capture commands:

```sh
python3 tools/mwcc_frontend_trace.py --unit main/dlls/engine/2/2 --function ObjSeq_ExecuteActionCommand --output build/objseq_action/frontend_exact
python3 tools/tricky_backend_trace.py --unit main/dlls/engine/2/2 --function ObjSeq_ExecuteActionCommand --graph --output build/objseq_action/exact_trace
```

The sibling fixtures are `docs/fixtures/objseq_iro_expression_walk_20260920.json`
and `docs/fixtures/objseq_iro_dead_assignment_20260920.json`. They retain the
original identity, source hashes, exact oracle commands and dependency scope.

## Final-link validation

Objdiff alone did not establish retention. The source linker initially dropped
the unused 40-byte `ObjSeq_SetCameraTransformOverride` entry and the initialized
zero word `lbl_803DB744` before the default color. The relevant configs now
retain those existing retail symbols. JP and EN revision 1 also retain
`seqClearTaskTexts`. No source padding or section-placement workaround was added.

Both the all-retail link and the link substituting this complete source TU
reproduce the hash-verified original in each claimed region:

| Version | DOL SHA-1 |
| --- | --- |
| GSAE01 | `e750e8e894707a52446118a4b84f1b58b677b269` |
| GSAJ01 | `a0646def31229c051f5143e6551840e6560b0556` |
| GSAE01_rev1 | `8bde4669c75260cc058b8b44ef36bacff3a67d20` |

After enabling the EN source TU, `ninja all_source build/GSAE01/ok` passed,
including the unchanged strict retail checksum. `clang-format --dry-run
--Werror` passed for the TU and `include/main/objanim.h`.

PAL function matching is verified, but full-TU completion is not claimed.
The PAL v1.0 target data begins 16 bytes later in the shared source's data
sequence: the source emits an additional four-word prefix, and the retail
resource descriptor still has a generic symbol in the PAL config. The retail
resource-registry audit identifies slot 2 and its 35 callbacks, but data
ownership and regional retention need a separate audit. PAL manifests remain
unchanged.
