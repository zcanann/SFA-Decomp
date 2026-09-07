# ObjHits literal recovery

## Source model

The four one-element `gObjHitsScalar*` arrays supplied only `0.0f`,
`1.0f`, `2.0f`, and `0.1f` to this TU. No other source consumed them.
Use ordinary float literals, including at the four sites that cast an array
element's address back to `f32*`. These are not recovered game-owned arrays.
Keep the existing arithmetic, including explicit zero additions, until retail
instruction evidence establishes the original expressions or vector helpers.

The native literals do not yet reproduce the retail compilation model. Do not
restore artificial arrays or force sections to hide that remaining work.

## GC/1.3 comparison

Baseline: `91e55140aa`, EN GSAE01, common game compiler profile.

| Measure | Array baseline | Native literals |
| --- | ---: | ---: |
| TU fuzzy match | 99.701866% | 99.48638% |
| Exact functions | 45/54 | 44/54 |
| Generated text bytes | 25988 | 25976 |
| Generated `.sdata2` bytes | 88 | 88 |

Only five function bodies change:

- `ObjHits_CollectSkeletonHitsXZ`: 1124 -> 1120 bytes.
- `ObjHits_CollectSkeletonHits3D`: 988 -> 980 bytes.
- `ObjHits_CalcTaperedCapsuleNormal`: 612 bytes, equality-compare operands swap.
- `ObjHits_DetectObjectPair`: 1232 bytes, equality operands and FPR allocation change.
- `ObjHits_CheckSkeletonPair`: 1116 bytes, GPR allocation and argument scheduling change.

The collectors fold literal-zero additions into two-term squared distances.
This removes loads and changes multiply/FMA evaluation order; it is not a
bit-exact floating-point transformation. The capsule normal loses its 612-byte
exact-function credit. No other function loses exact credit.

The literal pool retains its size and values but changes physical order,
losing 88 bytes of exact-section credit. In particular, `0.1f` and `2.0f` now
appear at their later first-use positions. All other non-text sections and
surviving named storage offsets are unchanged. All other built source objects
are byte-identical to the baseline.

`pool_value_sequence.py src/main/objhits.c` reports SAME 21, DIFF 0 against
retail. The other 33 functions have no relevant loads. The tool collapses
consecutive identical values, so this verifies the value progression, not
load counts or physical pool layout; the baseline also passes this check.

## Behavioral checks and limits

`test_objhits_capsule_normal.py` executes the production normal calculation
and three production vector helpers at host O0/O2, with separate and aliased
point/output buffers: 50 cases, 200 calls. It checks endpoints, equal and
unequal radii, oblique axes, collapsed length, and zero normals. Both retail
endpoint branches use point-minus-tip; the tapered interior reverses radial
direction through two cross products. The test preserves these behaviors.
Reversing the radius equality predicate produces 64 failures and no errors.
This is a geometric host check, not a PPC floating-point emulator or a test of
the two collector functions.

`ninja all_source` and the strict DOL gate pass. ObjHits remains NonMatching,
so the strict link uses retail code and does not validate these C changes.

## Native zero-test follow-up

Using the scalar conditions `!radiusDelta` and `dist` recovers the retail
`fcmpu` operand order without restoring named constants. Against `f92f0bf6e2`,
only one comparison instruction changes in each of the capsule-normal and
object-pair functions; the other 52 bodies, all allocated non-text sections,
symbol layouts, and relocations remain unchanged.

`ObjHits_CalcTaperedCapsuleNormal` is exact again (612 bytes); the object-pair
function improves from 99.74026% to 99.77273%, with its remaining FPR allocation
differences unchanged. The TU reaches 45/54 exact functions and 99.489456%
fuzzy match. The native literal pool ordering remains unresolved. The 200-call
capsule harness still passes; these scalar conditions preserve zero, nonzero,
and unordered comparison results.

## Native collision work-state storage

The `803DCBC8..803DCBF0` small-BSS range belongs to `objhits.c`:
`ObjHits_InitWorkBuffers` allocates the reset-object list, priority work slots,
work buffer, and four hit-volume scratch buffers. `ObjHits_CheckObjectHitVolumes`
saves and restores both model sphere-buffer banks through each scratch pair.
The primary and secondary scratch pairs are now real two-pointer arrays;
indexing past a declared scalar no longer supplies their second entries.

| Offset | Definition | Bytes |
|---|---|---:|
| `+00` | `gObjHitsSecondaryHitboxScratchBuffers[2]` | 8 |
| `+08` | `gObjHitsPrimaryHitboxScratchBuffers[2]` | 8 |
| `+10` | `gObjHitsWorkBuffer` | 4 |
| `+14` | `gObjHitsPriorityHitStates` | 4 |
| `+18` | `gObjHitReactResetObjectCount` | 4 |
| `+1C` | `gObjHitReactResetObjects` | 4 |
| `+20` | `gObjHitsPriorityHitTickDelta` | 4 |

GC/1.3 emits 36 bytes with eight-byte section alignment, matching the 40-byte
retail span including its trailing alignment. Sized array definitions precede
their consumers so the compiler can select small-data addressing; public extern
array declarations remain unsized. All seven symbols have their retail offsets.
The tick delta is a four-byte float, not an eight-byte allocation.

Against `95bb0fe7d2`, all 54 function bodies and every pre-existing allocated data
section and named data-symbol position are byte-identical. Objdiff credits 40
additional matched data bytes (8,352 to 8,392); code remains 99.61259% fuzzy and
45/54 exact functions. The TU remains NonMatching, so its source storage is
verified by object comparison, while the strict DOL link still uses its retail
object. The strict checksum and `ninja all_source` both pass.

## Squared-length helper recovery (2026-09-07)

Both skeleton-hit collectors now share a private inline three-component
squared-length helper. Their root and midpoint culls pass zero for the vertical
component: these broadphase checks remain horizontal even in the 3D collector.
The helper computes `x*x + y*y + z*z` in that order. No named literal storage,
compiler flags, or TU boundaries change.

With GC/1.3, substituting the zero argument during inlining preserves the
retail multiply-add sequence. The earlier explicit `x*x + 0.0f + z*z`
expression lost its zero addition before that stage and compiled into a
multiply followed by a differently ordered multiply-add. This recovery matters
for floating-point rounding as well as instruction matching; algebraic equality
alone did not justify the earlier generated sequence. The XZ collector also
uses a scalar joint-length condition, recovering the retail zero-comparison
operand order while preserving zero, nonzero, and unordered behavior.

| Function | Before fuzzy | After fuzzy | Generated bytes before / after / retail |
| --- | ---: | ---: | ---: |
| `ObjHits_CollectSkeletonHitsXZ` | 98.20285% | 99.786476% | 1120 / 1124 / 1124 |
| `ObjHits_CollectSkeletonHits3D` | 98.44129% | 99.75709% | 980 / 988 / 988 |

Both complete mnemonic streams now match retail. Each retains eight differing
register operands around the midpoint calculation; neither is claimed exact.
The TU improves from 99.61259% to 99.73111%, retaining 45/54 exact functions.
The other 52 function bodies, all allocated non-text section bytes, and all
named data-symbol layouts remain unchanged. Passing temporary `Vec` records
instead changes allocation and does not improve this scalar helper result.

Validation includes the existing capsule-normal host suite, full source build,
and strict retail checksum, plus direct object and whole-report comparisons.
The host suite checks the neighboring capsule calculation, not these collectors;
the instruction comparisons establish the collector improvements. The TU remains
`NonMatching`, and its unresolved literal-pool ordering is unchanged. Formatting
the active source and canonical header leaves the complete object unchanged.

## Shared horizontal joint cull: both collectors exact

The remaining register differences above are resolved by sharing the complete
midpoint cull in `ObjHits_JointPassesHorizontalCull`. Both callers compare the
horizontal squared distance from the doubled query point to the sum of the two
joint positions against the square of the query diameter, joint length, and
larger joint diameter. The XZ collector retains its preceding vertical-range
test. Strict comparison, arithmetic association, endpoint radii, and joint-length
loads are preserved. The private helper name and boundary are reconstructed,
not recovered historical symbols.

The helper owns the two delta temporaries and radius-limit calculation that
were duplicated in the collectors. Declaring `deltaZ` before `deltaX`, while
still calculating X before Z, gives the retail FPR allocation. With X declared
first, each collector still differs in four operands; the helper extraction
and declaration order are both needed. Moving the original locals into an
inner scope is byte-neutral, and grouping them into a record or reusing the
root-distance locals does not resolve the mismatch.

A diagnostic compiler capture reproduces the ordinary object byte for byte.
Its baseline 3D graph colors the endpoint-X values before the two caller-owned
delta values, giving the latter `f6`/`f7` instead of retail's `f4`/`f5`. The
matching helper capture verifies all 247 3D instructions and all 281 XZ
instructions with zero retail differences. The captured FPR simplification and
coloring both replay successfully, without high-degree removals. No compiler
file or production flag is modified.

Against `ca11c15ec0`, both collectors become 100% exact: 988 and 1,124 bytes,
respectively. ObjHits rises from 45/54 to 47/54 exact functions, gaining 2,112
bytes of exact-code credit; its fuzzy score moves from 99.73111% to 99.74958%.
The other 52 function bodies, all allocated data bytes, every named symbol
layout, and relocation destinations are unchanged. The TU remains
`NonMatching` for its other residuals and literal-pool ordering.

The existing capsule-normal tests, `ninja all_source`, and strict retail
checksum pass. Formatting is a separate commit and preserves the complete
object bytes. The compiler trace can be reproduced with
`python3 tools/tricky_backend_trace.py --unit main/main/objhits --function ObjHits_CollectSkeletonHits3D --function ObjHits_CollectSkeletonHitsXZ --graph --register-class fpr --output /tmp/objhits-cull-trace`.

## Skeleton-pair dispatcher exact

`ObjHits_CheckSkeletonPair` now uses the existing
`ObjAnim_GetPriorityHitState` accessor for both objects. The accessor returns
the same state pointer as the former direct casts. Its inline boundary changes
GC/1.3's virtual-register assignment, restoring retail's `r31` state pointer
and `r30` active model. All 279 instructions now match, recovering 1,116 bytes
of exact-code credit. A direct model lookup and local-declaration changes do
not fix the swap; using the state accessor for object B alone is sufficient.
Both objects use the canonical accessor in the retained source.

The collector result is now named `hasHits`: the collectors return `hit != hits`,
not a count. The float output is `inverseDistanceSum`, reflecting their
accumulated inverse-distance weights and its subsequent use in response
normalization. It is not a capsule axial coordinate. These local renames do
not change generated bytes. The two shape branches retain their distinct scale
expressions, temporary point copies, and response clamps.

The instrumented compiler produces the same raw object as an ordinary compile.
Its GPR graph replays simplification and coloring and verifies all 279 final
instructions with zero retail differences. An audit of all nineteen comparable
direct state casts in this TU found that replacing all of them regresses four
other functions, including two exact functions; that broader rewrite is not
retained. This result supports the accessor at this caller, not a mechanical
whole-file migration.

Against `6d5ed0b6a6`, ObjHits improves from 47/54 to 48/54 exact functions and
99.74958% to 99.7642% fuzzy match. All other 53 function bodies, allocated
non-text sections, named layouts, and relocation destinations are unchanged.
The TU remains `NonMatching`. The existing capsule-normal host tests,
`ninja all_source`, and strict retail checksum pass; the host tests cover the
neighboring geometry routine, while the instruction comparison proves this
dispatcher's match. Formatting is a separate, byte-neutral commit.

## Work-slot invalidation and frame-contact reset

`ObjHitbox_SetStateIndex` now delegates its work-slot scan to the private
`ObjHits_InvalidateObjectWorkSlots` helper. A state change invalidates only
active slots whose object pointer matches the caller. An unchanged state still
returns before the scan. The model-count clamp and its original branch order
are retained, while `modelCount` and the helper's `slotIndex` replace the
former local shared between those two roles.

This boundary recovers the retail slot-address and byte-stride registers:
`r7` and `r9`, respectively. All 35 instructions (140 bytes) now match. The
diagnostic compiler reproduces the ordinary object and successfully replays
GPR simplification, coloring, and final instruction operands. Merely extracting
an indexed slot getter does not match. No compiler settings change.

The slot's canonical header now asserts its 60-byte size, active-counter
offset zero, and object-pointer offset eight. Retail allocates
3,000 bytes for fifty slots; both the invalidation and tick loops use the same
60-byte stride. The remaining bytes stay opaque.

The adjacent frame-contact reset also has one private helper shared by the
main object and qualifying attached object. `ObjHits_ResetFrameContacts` clears
the applied-response bit, contact flags and partner pointer, and sets the
contact-volume sentinel. It uses the existing `hitObject` field instead of an
integer-pointer cast over the state prefix. All its caller's instruction bytes
are unchanged. Adding the helper renumbers three later anonymous literal names;
their bytes, locations, and relocation destinations are unchanged.

Against `ac1324bc62`, ObjHits rises from 48/54 to 49/54 exact functions and
99.7642% to 99.770355% fuzzy match. Only the state-index setter changes function
bytes. All allocated non-text sections, named layouts, and normalized relocation
destinations remain unchanged. The TU remains `NonMatching` for five other
functions and its literal-pool ordering. Full source compilation, the strict
retail checksum, and the formatter checks pass. Formatting produces no further
source changes and preserves the final semantic object byte for byte. Rebuilding
the header's consumers changes no other source object.

## Hit-volume cache dispatcher partial match

`ObjHits_CheckObjectHitVolumes` now obtains object A's priority state through
the existing `ObjAnim_GetPriorityHitState` accessor. This recovers the retail
model register throughout the repeated sphere-cache copies. The 348-instruction
stream retains its exact mnemonic sequence; operand differences fall from 73
to 28, improving the function from 98.95115% to 99.583336%. Remaining differences
are state-pointer register assignments and the two initial state loads. Using
the accessor for both objects regresses this caller, so object B retains its
direct cast. Extracting the full cache operation into a helper also performs
worse than the retained change.

The model local and selected sphere-buffer index now describe their actual
roles. All sixteen copy lengths use `hitVolumeCount * sizeof(ObjModelHitSphere)`
instead of a raw four-bit shift. The canonical model header already proves the
16-byte sphere record and byte-sized count. These size expressions and local
renames preserve the accessor-only object's generated code. The primary and
attachment scratch-buffer pairs, copy directions, and cache-flag behavior are
unchanged; the flag is still set only in the attachment save branch.

Against `e99d77cabe`, the TU's fuzzy score rises from 99.770355% to 99.804214%.
It remains `NonMatching`, with 49/54 exact functions. All other 53 function
bodies, allocated non-text sections, named symbol layouts, and relocation
destinations are unchanged. Nine anonymous literal names are renumbered without
moving their storage. Full source compilation and the strict retail checksum
pass. Formatting is a separate commit and preserves the complete object bytes;
the active source and canonical header pass the formatter check.
