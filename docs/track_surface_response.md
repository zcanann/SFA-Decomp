# Surface penetration response

`trackResolveSurfacePenetration` now names its input contract and shares the
normal-projection operation between its two response branches. The private
inline helper preserves the complete arithmetic sequence, including the initial
radius-relative adjustment. No response modes, plane layout, thresholds or
floating-point operations change.

The sole source caller, `trackGetIntersect2`, establishes the arguments:

| Argument | Meaning |
| --- | --- |
| `startPosition` | Start of the sweep in collision space. |
| `position` | Current collision-space position, updated by the response. |
| `contactPosition` | Contact position found by the sweep. Mode 3 uses this as its line endpoint. |
| `plane` | Four floats: normal X/Y/Z followed by the plane constant. |
| `radiusDistance` | `dot(position, normal) + planeConstant - sphereRadius`. |
| `clearance` | Sphere radius plus the collision epsilon. |
| `responseMode` | The caller's byte-sized response selector. |

The start, contact and plane pointers are read-only in this routine and now
carry `const`. The output remains mutable. These are pointer qualifiers, not
new non-aliasing assumptions. The existing three-component scratch arrays retain
their storage and lifetimes.

## Response geometry

Mode 3 first copies the contact position into the output. It intersects the
start-to-contact line with the plane offset by `clearance`, using the two signed
distances to compute the interpolation fraction. Equal distances select the
start position. The fraction is not clamped, so the result may lie beyond the
segment. Retail normalizes the scratch displacement and then recomputes it;
the apparently redundant normalization remains.

For other modes, the strict test `-0.707f < normalY < 0.707f` selects the
wall-like branch. Equality belongs to the floor/ceiling branch.

| Branch | Modes | Response |
| --- | --- | --- |
| Wall-like | 1, 8, 10 | If penetrating, correct horizontally along the projected normal; leave Y unchanged. |
| Wall-like | All other modes except 3 | Apply the normal projection. |
| Floor/ceiling | 5, 8 | Apply the normal projection. |
| Floor/ceiling | All other modes except 3 | If penetrating, correct vertically; leave X/Z unchanged. |

The horizontal correction uses cosine of the normal's inclination and a
normalized horizontal normal. The vertical correction uses sine of that
inclination. Their trigonometric calls and the horizontal zero-divisor guard
remain intact. The shared normal-projection helper first subtracts
`radiusDistance * normal`, then evaluates and applies the remaining plane
correction. Unlike the constrained branches, it does not skip negative
corrections. Numeric mode values remain numeric because the wider gameplay
meaning of each selector has not been established.

The explicit cast in the `normalY` load remains intentional. Replacing it with
plain array indexing removes two retail instructions and changes register
allocation. Retaining the cast with a read-only pointer preserves the original
1076-byte body. The mutable `clearance` and correction locals keep their existing
lifetimes; naming does not split them into extra temporaries.

## Validation

`python3 tools/test_track_surface_response.py -v` compiles the production
response, inline helper and vector normalizer at O0 and O2. An independent
geometric oracle checks **622 cases per build**, including horizontal and
vertical constrained projections, normal projections, all selector branches,
both exact slope thresholds and their neighbors, positive/zero/negative
corrections, line intersections outside the segment and equal-distance fallback.
Output guards and read-only input snapshots are checked on every call.
Host libm replaces the game's approximations; this verifies geometry, not exact
Gekko arithmetic. The existing ground-query, wrapper and sphere-edge tests also
pass (seven test methods in the combined track suite).

The retail response has the same normalized instruction signature in EN v1.0,
EN revision 1, JP and PAL revision 1 after verifying each DOL's configured hash.
Before/after object audits preserve every function body in the complete track
TU, all allocated data, all named symbol layouts and resolved relocations.
Anonymous compiler labels renumber; formatting is separate and preserves the
raw object. Match scores and unit classifications do not change.

## GC/1.3 operand-order improvement

The constrained horizontal and vertical branches now spell the Z product as
`normalZ * position[2]`, consistent with their `normalX * position[0]` product.
The surrounding sum grouping, locals and control flow are unchanged. This is
an operand-order improvement, not a newly exact function or TU.

The probe was guided by independent GC/1.3 expression-lowering recovery in the
sibling MWCC research repository. Its newly reconstructed binary-float helper
at `0x0044bed0` demonstrates ordered operand evaluation/materialization before
destination selection; 5,920 original/native differential cases validate that
body with explicit dependency adapters. The contracted multiply-add emitter is
a separate dependency, so the ordinary compiled-object comparison is the
source-facing evidence here, not a claim of complete lowering replay.

Across all five configured retail versions, the function improves from
**99.27881% to 99.31599%** and the TU from **99.66211% to 99.663536%**.
Exactly two four-byte instructions change, at function offsets `+0x1d8` and
`+0x3c4`. Every other instruction, all relocation sections, the symbol/string
tables and allocated data remain byte-identical. The function stays 1,076
bytes, and the TU remains `NonMatching` with 23 of 30 functions exact.

The existing surface-response tests pass at O0 and O2 (622 cases each).
`clang-format -i` makes no additional source change and preserves the raw
object hash; its dry-run check passes. All five `all_source` builds and strict
retail checksums pass. The strict link still uses the retail object for this
nonmatching TU and is an integration gate, not proof of a complete source match.
