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
