# trackGetHeight initialization and BSS recovery

## Retained result

EN `trackGetHeight` remains 98.341774%, with 158 instructions. No game-source
change is retained from this investigation. The full track object remains
`5c353e528455ac0a2bbba4f84c61881d13c8fa8fa2be6b6ba3c5a2584522a677`;
27 of 30 functions are exact and the TU score is 99.94134%.

Retail initializes the descriptor cursor before the mode branch and broadphase
call. It then initializes the hit-write cursor before the hit-order pointer.
Moving the descriptor initialization earlier and reversing those stores recovers
the instruction sequence, but changes the actual BSS offsets. The near-exact
objdiff score (99.96203%) is not an acceptable match: normalized relocations do
not establish the three buffers' addresses.

## LLDB evidence

An entry hook on GC/1.3's uninitialized-storage reservation at 0x004b2d10 records
these calls between the preceding function's final dump and `trackGetHeight`'s
first backend dump. The baseline traced object equals the ordinary object.
The early candidate's traced/ordinary object hash is
`6602f81be3f38e184680e14cddd1db468c4cf6ed05cea55205dbb4bfbbd36c8f`.

| Buffer | Size | Retail/baseline BSS offset | Early candidate offset |
| --- | ---: | ---: | ---: |
| gTrackGroundHitOrder | 140 | 80 | 1400 |
| gTrackGroundHits | 840 | 220 | 560 |
| gTrackBlockDescriptors | 480 | 1060 | 80 |

The baseline reservation order is order, hits, descriptors; the early candidate
uses descriptors, hits, order. All three calls have object flag 0x01000000 and
mode zero. At `BEFORE GLOBAL OPTIMIZATION`, each baseline deferred entry has
active=1 and assigned=1. This is an allocation-order change before backend code
motion, not a later reordering of otherwise-correct storage.

A compact durable capture is in the sibling compiler project's
`docs/fixtures/gc13_track_height_storage_20260921.json`. Full scratch traces are
under `build/track_finish/height_storage_*`.

## Compiler reconstruction

The sibling `StorageFinalize.c` now reconstructs all 214 bytes at
0x004b4530--0x004b4605. Its hardened offline original/native oracle passes 4,096
cases and visits all 61 instructions. Finalization stages, output-handle handling
and buffer alignment/growth are explicit dependency adapters. This is functional
handler equivalence, not a complete compiler replay or a Win32 binary match.

The finalizer allocates offsets only for active, non-excluded, unassigned entries.
It preserves already-assigned offsets, does not set the assigned byte itself,
clears only the list head, transfers the finalized output handle into the
existing definition profile, and publishes storage totals. Consequently, late
finalization cannot repair the early-initialization candidate's shifted buffers.

## Rejected source paths and validation

Sixteen whole-function inline-helper variants passed selected query buffers as
parameters while varying descriptor timing and store order. They either retain
late initialization or change allocation/register behavior. Automatic const and
register pointer aliases preserve the desired allocation order but introduce
extra address lifetimes. Static const pointer aliases also fail. These complement
the previously rejected deferred definitions, local/static arrays, and simple
address accessors. No extra volatile, forced section, padding, or invented
workspace aggregate is retained.

A diagnostic compiler comparison keeps all track flags fixed and substitutes
only GC/1.2.5 or GC/1.2.5n in scratch builds. Both produce 203 instructions and
137 aligned differences for each baseline/early source, versus retail's 158.
This does not support a compiler-profile exception. Production remains GC/1.3.

The input DOL SHA-1 matches its configured
`e750e8e894707a52446118a4b84f1b58b677b269`. A scan of its loaded sections finds
no aligned literal pointer to any of the three buffer starts, so there is no
such missing static initializer to use as an earlier reservation anchor.

The remaining task is to recover a source/storage relationship that preserves
the allocation order while generating retail's early descriptor address. The
new evidence rules out late finalization as that mechanism; it does not prove
that no valid source solution exists.

## Shared-address initialization follow-up

The sibling `SharedAddressInit.c` reconstructs the complete initializer emitter
at 0x00434e00 (290 bytes) and record-count predicate at 0x004df110 (44 bytes).
All 6,144 combined original/native cases pass, with 111 instructions visited.
Operand construction/forcing, metadata lookup, diagnostics and instruction
emission remain explicit adapters; the original predicate executes in the oracle.

LLDB at the emitter entry sees exactly one cached object in both the baseline
and early-descriptor candidate: `...bss.0`, kind 0, field37 0, metadata flag 2,
virtual register 51. Each traced object equals its ordinary build. Thus the
shared-address initializer does not independently cache the descriptor array;
the early candidate's descriptor load comes from the function body. The compact
capture is `../mwcc/docs/fixtures/gc13_track_height_shared_init_20260921.json`.

Pointer/end spelling changes preserve the baseline difference. Indexed loops,
cached block counts and pointer-count loops produce 157--162 instructions and
24--27 aligned differences. Empty aggregate initializers still move the buffers
into initialized storage. None is retained.

Thirty-two additional local-pointer variants vary const qualification and use
of the hit/order aliases in cursor initialization, sorting setup and final output.
Unused aliases do not reserve storage; used aliases either shift allocation order
or extend address lifetimes across broadphase. No variant matches both the
instruction sequence and buffer addresses. Scratch results are in
`build/track_finish/probe_height_sort_alias.log`.

After this follow-up, `ninja all_source` and the explicit strict target
`ninja build/GSAE01/ok` pass. The built DOL SHA-1 equals the verified retail hash
above, and the production track object hash is unchanged.

## Complete declaration-handler follow-up

Reconstructed the full 1,063-byte GC/1.3 declaration handler at
0x00509220--0x00509646 in the sibling `DeclarationStorage.c`. Its 8,192-case
original/native oracle compares callbacks, object changes, deferred registration
and context restoration. Another 8,192 comparisons connect the recovered type
eligibility body, visiting 442 instructions across both routines. Parser/class
callbacks and final emission remain adapters; this is functional recovery.

LLDB shows the baseline and early candidate register the same descriptor array,
segment table, hit-order array and hit-storage array, in that order before any
function. All enter with flags zero, category zero, token semicolon, C++ mode
zero and type kind 12. This confirms the ordinary C tentative-definition path;
registration does not itself reserve the buffer offsets. Both traced objects
match their ordinary builds. The compact fixture is
`../mwcc/docs/fixtures/gc13_track_height_declaration_20260921.json`.

A fresh uninitialized function-local static hit-order/hit-storage probe also
retains the bad early-candidate offsets (descriptors 80, hits 560, order 1400).
Moving these private buffers into function scope does not eagerly reserve them.
No game-source change is retained; the score and production object remain as
recorded above. The unsolved requirement is still the connection between first
address use and retail's early descriptor initialization, not declaration-list
registration or end-of-file storage finalization.

## Expression-preparation reservation boundary

Recovered two complete helpers in sibling `AddressPreparation.c`: reference
registration at 0x004defd0 (86 bytes) and symbol-operand construction at
0x004e23a0 (27 bytes). All 4,096 combined original/native cases pass. The former
can cause context selection/reservation; the latter only clears a 24-byte operand
and stores kind 8 and the object pointer. Lookup, context and recording callbacks
remain adapters, including controlled mutations to verify decision order.

LLDB at shared-context selection 0x004d0020 records the first buffer queries
returning to 0x004dc50e in the expression-preparation walker, before the first
backend dump. Baseline order is hit-order, hit-storage, descriptors; later
queries return to 0x004df08f. The larger walker at 0x004dc2e0 has inlined copies
of the recovered registration helper but is not itself reconstructed. These
captures locate reservation before backend instruction selection and scheduling.

The early load and the 80/220/1060 buffer offsets were also cross-checked in
EN rev1, JP, PAL and PAL rev1 retail objects. All five input DOLs match their
configured SHA-1 hashes, and all five versions have the same relevant seven
instructions (indices 13--15 and 49--52). This confirms a shared target pattern;
it does not validate the nonmatching source or establish a new source layout.

Both LLDB captures identify AST kind 0x38 at the first reservation sites. The
baseline first selects order/hits/descriptors; the early candidate first selects
descriptors/hits/order, all at return site 0x004dc50e. Traced objects equal the
ordinary builds. The compact captures and regional input hashes are preserved in
`../mwcc/docs/fixtures/gc13_track_height_address_preparation_20260921.json`.

Twelve branch-setup variants tested whether branch merging could separate
reservation order from emitted initialization. The variants duplicate the setup
in both mode branches (or all three nested arms), varying reference order. They
produce 163 or 168 instructions against retail's 158; the compiler retains
branch-local setup instead of producing the required early descriptor load.
The variants with correct BSS offsets still fail. None is retained.
