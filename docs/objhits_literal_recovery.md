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
