# Scarab (object DLL 262)

EN v1.0, GC/1.3, 2026-09-07. All seven functions (5,288 text bytes) and
all 240 assigned data bytes match. The unit is `MatchingFor("GSAE01")` and
links from C. The TU boundary and compiler flags are unchanged.

## Matching contact state

`ScarabContactState` groups the update's selected ground-hit index and collision
flag. Both fields are initialized explicitly, index first, and keep their
existing roles through tumbling, slope avoidance, and the stunned ground query.
This models transient query state; it does not claim an extra-state allocation
or an original type name from the Dinosaur Planet reference.

The grouped fields resolve the former instruction-26 difference at `0x80184998`:
`mr r30,r31` replaces `li r30,0`. The other 868 update instructions are unchanged.
The other six functions, all allocated data bytes, section sizes, alignments,
and named symbol layouts are unchanged. Compiler-generated literal names may
renumber, but their linked destinations and bytes remain exact.

A GC/1.3 LLDB trace observes the copy appearing after the second value-numbering
pass as `gpr65 <- gpr67`. Coalescing redirects its source to `gpr43` while retaining
the copy; physical allocation yields `r30 <- r31`. The capture has 20 stages,
869 aligned final instructions, no retail differences, and 201 replayed physical
color decisions. Ordinary and instrumented objects are identical. Unlike the
earlier scalar-reuse probes, this form preserves both complete field lifetimes.

The diagnostic C-substitution link reproduces every allocated section of the
matching ELF, including addresses and bytes. Both `ninja all_source` and the
strict matching checksum build pass with the source object selected.

The following sections record the earlier recovery and diagnostic controls.

## Collection helper

Dinosaur Planet's `src/dlls/objects/297_scarab/scarab.c` defines
`scarab_collect(self, player, objData)`. Its local byte table is
`{1, 5, 10, 50}`; it awards the indexed amount, sets the destruction delay
to 80, and clears the lifetime. Its callers are the queued pickup reply,
ordinary proximity collection, and the stunned rainbow-scarab hit.

The EN function contains that same operation at the same three behavioral
sites. `Scarab_collect` recovers this shared inline helper, replacing three
expanded bodies, three union temporaries, and the packed-word currency table.
The helper precedes the emitted collision functions so its initializer stays
at the beginning of the constant pool. Defining it immediately before
`Scarab_update` preserves instructions but reorders the pool; that variant
was rejected. `gScarabMoneyValues` in the target config now identifies a local
initializer rather than an exported object.

Compared with staging `dd8fa982c5`, every emitted function byte and every
allocated section byte is unchanged. Other named symbol layouts and
relocation destinations are unchanged; the currency-table references now
use the compiler's anonymous initializer. A diagnostic link substituting
the reconstructed object for the retail object differs only at
`0x80184998` through `0x8018499B`. All section addresses and lengths,
including the complete linked constant pool, match retail.

## Frame query initializers

Dinosaur Planet initializes its two `Vec3f` query endpoints locally, between
the ground-index and collision-flag declarations. The corresponding EN
initializers now use that local form, replacing two exported zero-vector
definitions and their later assignments. No other source consumes those
definitions. Their target pool labels remain in the symbol config with
local scope.

Before the expression cleanup, this recovery preserved all seven function
bodies and every allocated section's bytes, size, and alignment. Only the two former global symbols
and anonymous relocation names change; the initializer relocation targets
remain `.rodata+0` and `.rodata+12`. The complete object SHA256 is
`030b14ff068ffd446194b5e36a1d0c080e476fc22850425d24d5f3815e59bfa0`.
Both build gates pass. A diagnostic source-substitution link still differs
from retail only at the four bytes `0x80184998` through `0x8018499B`.

## Earlier scalar zero initialization

At instruction 26 of `Scarab_update`, retail emits `mr r30,r31`; the scalar
baseline emits `li r30,0`. The earlier `li r31,0` and its store initializing
the ground-hit pointer are exact. Dinosaur Planet's source and MIPS assembly
both support separately initialized scalar ground-index and collision locals;
they do not support restoring the former one-element index array.

The existing LLDB provider can trace this unit directly:

```sh
python3 tools/tricky_backend_trace.py \
  --unit main/dlls/objects/262/262 --function Scarab_update --graph \
  --output build/flag_probe/scarab_backend
python3 tools/tricky_backend_trace.py \
  --read build/flag_probe/scarab_backend/trace.json \
  --function Scarab_update --instruction 8 --instruction 26
```

The pre-recovery baseline capture contains 20 stages and 869 final
instructions. Its instrumented and ordinary objects have the same SHA256:
`3f6b9af298a7395a7d1cd6068f073a1c6c749b9b088bc8cd1971cbeea5c20bde`.
Both register graphs validate, and all 202 physical-color choices replay.
The recovered helper was traced again with the same stage counts, register
numbers, and remaining instruction. Its ordinary and instrumented SHA256 is
`73c6eac6b8dafec48197fddba763cb7f9e0801fcd79f800f5b41b842ed33ee0e`.

The baseline zero loads already exist before global optimization. The initial
ground index uses virtual GPR 52, within the observed late value-numbering
range `[46, 237]`; the collision flag uses GPR 44, outside it. The pass
combines the ground-pointer zero with GPR 52 but leaves the flag's `li`
unchanged. Thus this particular instruction is not first introduced by
allocator rematerialization, as the older `priced_classes.md` discussion
suggested.

Reusing the collision-result scalar for the gold-climb swept query moves its
initial lifetime to GPR 50. LLDB observes the desired `mr` after the second
value-numbering pass, but register coalescing subsequently removes it and
changes other register assignments: 868 instructions, 99.75835%. This variant
was rejected. It demonstrates that source lifetimes can reach the copy;
it does not reproduce retail's allocation.

Separate query-result locals, ground-loop index reuse, scalar widths,
declaration initializers, a shared closest-hit reduction, and the collection
helper do not resolve the remaining instruction. Diagnostic changes to
lifetimes, propagation, CSE, optimization level, and deferred inlining also
fail to produce an exact unit. Production compiler flags
and TU boundaries are unchanged. These observations describe the tested
source forms, not a proof that matching clean C is impossible.

## Frontend investigation

`tools/mwcc_frontend_trace.py` exposes the compiler's own earlier IR listings:

```sh
python3 tools/mwcc_frontend_trace.py \
  --unit main/dlls/objects/262/262 --function Scarab_update \
  --output build/flag_probe/scarab_frontend
```

The tool hash-checks GC/1.3, verifies the hook instructions, and enables only
the disabled listing gates in a private LLDB/Wibo process. It copies the
input source into the diagnostic output directory and compares ordinary
and instrumented objects byte for byte. A successful manifest records the
source, compiler, object, and listing hashes alongside the actual command.
The default debugger deadline is 60 seconds; incomplete captures publish
no success manifest.

The pre-initializer-recovery source at `fa8042be9c` produces 79 stage dumps.
Its initial `collisionDetected = bestGroundHitIndex` is an `EASS` from an
indirect scalar read in `IRO_BuildflowGraph`. The first `Copy and constant
propagation` stage replaces that read with `Operand 0`. Later, between the
last `IRO_EvaluateConditionals` and `Before RebuildCondExpressions`, the
initial/stunned ground-index component becomes an anonymous temporary;
the active ground-index component and initial collision component retain
their original names. GC/1.3's lifetime-partition routine at compiler VA
`0x45D090` creates these anonymous variables. This explains why changing
only the initializer's spelling does not repair the backend mismatch.

The local-initializer source was traced separately: 79 stages again, with
ordinary and instrumented object hash `030b14ff...e59bfa0` as recorded above.
EN rev1, JP, PAL, and PAL rev1 all retain `mr r30,r31` at the corresponding
instruction 26. This corroborates the instruction's retail identity without
establishing the missing source form. None of the diagnostic scalar, alias,
aggregate, guard, or optimizer variants is retained.

## Direct collision records and expressions

The former `ScarabCollisionScratch` joined two independent stack locals:
`TrackLineIntersectResult` at update-frame offset `0x7C`, and `TrackHitResults`
at `0xD0`. The latter already owns the plane array, radii, surface bytes, query
bytes, and object pointers. Both records now use their canonical types, with
normal field access such as `hitResults.radii` and `hitResults.planes[0]`.
The three private collision overlays and their duplicate assertions are gone.

This is supported by the EN collision callee, not just a matching stack shape.
`trackGetIntersect` writes its result count at `+0x6C` (`0x80067998`) and mask
at `+0x6E` (`0x80067B64`); its object slots start at `+0x5C`. The collision
helper's former `solidFlags` array therefore contains hit-object pointers.
It now uses `TrackHitResults.objects` and the complete `0x70`-byte record.
The helper remains byte-exact, including its frame size and stack accesses.
Canonical result layout assertions remain beside the shared definition in
`include/main/track_hit_results.h`.

The cleanup also removes constant-only scopes and locals, assignments inside
normalization and movement expressions, vector-address casts, and unnecessary
contact-byte pointer casts. The orientation helper accesses `ScarabState`
fields directly. Inlining the rise, bounce, movement, and knockback constants
and replacing the sphere aliases preserve instructions. Direct plane access
through the old wrapper introduced an extra pointer copy; using separate
canonical locals removes that copy and reproduces retail's stack offsets.

Removing the zero temporaries changes only the operand order of two `fcmpu`
instructions: `0x801846A4` in `Scarab_applyOrientation` and `0x80184DE4` in
`Scarab_update`. Their equality/unordered tests are equivalent. The original
`li r30,0` versus `mr r30,r31` difference at `0x80184998` remains. Relative
to the pre-cleanup object, exactly four instruction bytes change; section
sizes, alignment, data bytes, named symbols, and relocation destinations are
unchanged. Anonymous literal names are renumbered. The normal object SHA256
is `db55c4874fe91c6ea3aa0b7d0f990611c56ec15ea3f03f37c4a8132bb0c261ba`.

Both `ninja all_source` and the strict retail checksum gate pass. A diagnostic
link substituting the cleaned source object differs from retail at exactly
eight bytes across the three instructions above; every allocated section
retains its address and length, and all other bytes match.

This cleanup established a cleaner baseline. The previous higher percentage
does not establish the discarded expressions as original source.

## Magnitude checks

Using C's scalar truth test, `if (magnitudeSquared)` and `if (speed)`, produces
the two retail `fcmpu cr0,f1,f0` instructions without zero temporaries. These
conditions have the same nonzero and unordered behavior as `!= 0.0f`. Explicit
integer zero, reversed operands, negated equality, and a conditional expression
retained the comparison mismatch; a greater-than test changes the condition
and was rejected.

Relative to the cleanup object, only the four bytes in those two comparisons
change. All section layouts, named symbols, and relocation records remain
identical. The normal object SHA256 is
`807ca3ffea301d016e4320256457a2e782d470566d771fda15c2fe7390373cf8`.
`Scarab_applyOrientation` is exact again; `Scarab_update` retains only its
integer initialization mismatch.

The cleaned-source backend capture puts that initialization in virtual GPR 42,
outside the late value-numbering range `[44, 237]`; the old sphere aliases
accounted for two additional named registers in the earlier capture. Gold-query
reuse still reaches a copy which coalescing removes (868 instructions,
99.75835%). Separating tumbling and slope flags instead adds an initialization
and changes the saved-register range (870 instructions, 98.37745%). Neither
variant is retained.

## Zero-copy controls

Exact GC/1.3 game functions provide positive controls for the remaining copy.
`GameUI_releaseMenuResources`, `Obj_ResetObjectSystem`, and
`Obj_FlushDeferredFreeList` acquire their zero copies after the second
value-numbering pass. Their copied destinations are anonymous registers
inside that pass's eligibility range. In `Obj_FlushDeferredFreeList`, the
named loop counter remains a separate `li`, outside the range. Ordinary and
instrumented objects agree byte for byte, and the captured register graphs
and physical coloring replay successfully. Indexed stores in these controls
are supported by the backend validator's checked `stwx` mapping.

Using Scarab's collision scalar as the stunned ground-loop ordinal, without
a second loop initialization, also retains the required entry copy. It loses
the retail `li r6,0` and carries the ordinal in `r30`, however: 868 instructions,
99.86766%. This diagnostic is not retained. It demonstrates a distinct
lifetime constraint rather than resolving the function.

A shared `const int zero = 0`, used for both entry initializations or throughout
the update, leaves every function and allocated section byte unchanged.
`static const int` and `static const f32` initializers do likewise. The remaining
instruction is still `li r30,0`; only anonymous symbol names are renumbered.
These constants are not retained because they do not help the match.
