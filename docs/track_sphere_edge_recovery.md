# Sphere-edge sweep packet

The subsequent [surface response](track_surface_response.md) documents how the
coordinator uses the resulting contact plane to correct the sphere position.

EN v1.0 passes one 48-byte packet from `trackGetIntersect2` to
`trackSweepSphereAgainstEdge`. The old C declared four separate arrays (`va`,
`vb`, `evec`, `rdata`) and passed the first array's address. The callee then
read twelve floats through that pointer, depending on the compiler placing
the other arrays immediately afterward. That is not a valid C array contract.

The retail caller passes `r1 + 184`. Its endpoint stores, normalized direction,
radius setup and edge-length store establish this complete layout:

| Packet offset | Recovered member | Evidence |
| --- | --- | --- |
| 0x00 | `start[3]` | First triangle vertex, and the pointer passed to the callee. |
| 0x0c | `end[3]` | Next triangle vertex; the caller subtracts `start` from it. |
| 0x18 | `direction[3]` | Normalized endpoint difference, read by the callee. |
| 0x24 | `radius` | Input sphere radius; used to form the output plane. |
| 0x28 | `radiusSquared` | Radius squared; used by the line-distance rejection. |
| 0x2c | `length` | Return from normalizing the edge direction; limits the contact to the segment. |

`TrackSphereSweepEdge` now owns the packet in `track_dolphin.h`, with size and
member-offset assertions beside its definition. The caller creates one record;
the callee has a typed parameter and a canonical header declaration. The later
endpoint-sphere pass reuses `end` as its vertex scratch, just as it reused `vb`.
No triangle, global, TU, compiler or allocation boundaries change.

The helper intersects the moving sphere center with the finite cylinder side
around the edge. It rejects parallel rays, excessive line separation, entry
outside the supplied movement interval, and entry beyond either endpoint.
Successful calls return 3, the sphere-center position, distance along the ray,
and a unit normal with plane constant `radius - dot(center, normal)`. Endpoint
spheres and triangle faces are separate coordinator paths. The clearance and
epsilon arguments are unused in this helper and remain in its ABI.

Caller names now distinguish collision-space start/contact coordinates from
world positions. Its old `maxStep` is `clearance`: the actual expression is
`radius + gTrackCollisionEpsilon`. The signed distance passed to surface
resolution is named `radiusDistance`, reflecting subtraction of the radius.

Two source spellings remain intentional. Byte views with canonical `offsetof`
keep the caller's endpoint/direction scratch pointers independent; direct member
addresses add a register-copy instruction. In the already-exact edge helper,
replacing the final byte-view output copies with array indexing removes retail
stack stores and changes its 188-instruction body to 181 instructions. Those
copies remain unchanged apart from their recovered names.

## Validation and remaining match cost

- The 752-byte edge helper remains 100% exact. The 4,460-byte coordinator retains
  all 1,115 retail instruction mnemonics, but its register/stack assignment
  changes: fuzzy match moves from 99.76233% to 99.698654%. This small regression
  is accepted to replace the invalid cross-array packet with owned storage.
- The TU retains 23/30 exact target functions and 100% matched data. Every other
  compiled function body, all named symbol layouts, non-text section bytes and
  resolved relocation destinations are unchanged. All 1,001 other source
  objects are byte-identical. No unit matching status changes.
- `python3 tools/test_track_sphere_edge.py` compiles the production helper,
  vector operations and packet definition at O0/O2. An independent quadratic
  cylinder oracle checks 508 cases per build, including 216 contacts, rotated
  edges, parallel motion, tangency, interior starts, finite endpoint rejection,
  range limits, untouched miss outputs and unchanged inputs. A deliberate
  edge-length/radius substitution fails the oracle. This is host arithmetic
  coverage, not Gekko rounding or full coordinator execution.
- The existing ground-query harness passes. `ninja all_source` and the strict
  retail checksum pass after `python3 configure.py --matching`, with each Ninja
  invocation limited to 30 seconds. The TU remains `NonMatching`; the checksum
  therefore verifies integration with its retail object, while objdiff checks
  the reconstructed source directly.

## Coordinator edge-plane array and stack placement

The coordinator's three edge planes are now `f32 edgePlanes[3][4]` instead of
three independent four-float arrays. Each record receives the corresponding
`TrackTriangle.edgeNormals` vector and a fourth plane constant. The three
tested constants produce edge-mask bits 1, 2, and 4. These parallel consumers
establish the element count and four-component shape independently of stack
spacing. The owned 48-byte `TrackSphereSweepEdge` packet remains intact.

This places the packet at retail SP+184 and the three planes at SP+232, +248,
and +264. Ordinary array-to-pointer assignments introduce two extra register
copies; byte views using `sizeof(edgePlanes[0])` preserve the independent
scratch-pointer setup, as the packet's existing `offsetof` views already do.
Moving the packet declaration alone does not correct the stack allocation.

All five hash-verified retail versions improve from **99.698654% to 99.76233%**
for the 4,460-byte coordinator. The TU improves from 99.689735% to **99.699844%**
and preserves all **24/30 exact functions**. This is a stack-layout improvement,
not another exact function. Fifty retail instruction differences remain,
including pointer setup/addressing and endpoint-sphere floating-point registers.

The before/after instruction audit finds exactly 75 changed instructions. Every
change is solely the 16-bit displacement of an SP-based `addi`, `lfs`, or
`stfs`: old offsets 184..231 move up 48 bytes, and 232..279 move down 48 bytes.
Every opcode, register field, branch, arithmetic instruction, and other bit is
unchanged. This verifies a complete permutation of the two disjoint scratch
areas; it does not claim a host geometry test of the entire coordinator.

Full source and strict retail builds pass for all five versions. Every other
function, allocated data section, named-symbol layout and resolved relocation
is unchanged, and no other source object changes. All five track objects have
SHA-256 `36ee73d5fe750e70e284b9db81b3f20fc18cbfe6104d093987d655819a1cc0de`.
The unit remains `NonMatching` until its remaining six functions are exact.

## Shared endpoint-sphere sweep

The two endpoint tests now call one inline `trackSweepEndpointSphere` helper.
They perform the same ray/sphere calculation: project the center offset onto
an already normalized movement direction, reject a miss, choose the entry
root for an exterior start or exit root for an interior/surface start, and
accept only a distance in `[0, maxDistance]`. On success the helper writes the
moving center, contact normal, offset plane constant, and distance. Rejection
leaves those outputs untouched. Its scratch vector is local to the helper.
The spelling and helper name are reconstructed, not recovered source names.

This source boundary reproduces all 24 previously different floating-point
instructions in the two endpoint paths. Merely sharing or splitting scalar
locals in the coordinator did not reproduce their retail register allocation.
The coordinator remains 1,115 instructions / 4,460 bytes and improves from
99.76233% to **99.86996%** in all five versions. The TU reaches **99.71693%**,
still with **24/30 exact functions**. Twenty-six coordinator differences remain:
endpoint scratch-pointer setup/addressing, the output-slot register, and two
instructions computing the final plane distance.

The before/after audit changes exactly 24 instructions, all in the endpoint
paths (indices 695 through 853); their opcodes and instruction count are
unchanged. All other 29 functions, allocated data sections, named-symbol
layout, and resolved relocations are unchanged. The inline helper has no
out-of-line emitted body. All five original DOL hashes are rechecked, and
`ninja all_source` plus the strict retail checksum pass in each version.
The resulting raw object SHA-256 is
`1761c9673147b23f0ea0216cbd3a3f6fb62bf24c5b3d6fb9895876f67a57dba7`.

`python3 tools/test_track_endpoint_sphere.py` checks 1,211 cases at both `-O0`
and `-O2` against independently computed quadratic roots: 621 accepted sweeps
and 590 rejections. Cases include tangent contact, interior/surface starts,
backward motion, movement-limit rejection and exact endpoints, plus random
oriented rays. Inputs and rejected outputs must remain unchanged. Host vector
adapters validate geometry and branches, not Gekko rounding or execution of
the complete coordinator.

An ordinary LLDB instruction capture reproduces the unmodified object's hash
and all 1,115 instructions. Requesting its GPR graph exposed an unsupported
allocation retry (`unpaired initial GPR graph`); no graph replay is claimed.
Explicit scratch-pointer, declaration-order, and transform-helper experiments
did not recover the remaining retail setup and are not retained.

## Endpoint scratch-pointer allocation

Explicit `startY`, `startZ`, `endY`, and `endZ` pointers now express the shared
coordinate addresses used by matrix output arguments and scalar copies. They
use ordinary typed array addresses; no integer or byte-pointer cast is needed.
Their position among the existing pointer declarations and initialization order
are codegen-significant. This recovers all retail pointer setup instructions,
matrix argument registers, edge scratch registers, and the output-slot register.

The coordinator improves to **99.98027%** in all five versions, leaving only
four of its 1,115 instructions different: stores at indices 150/153 use direct
stack addressing instead of the existing endpoint pointers, and 974/975 use
FPR1 instead of FPR0 for the intermediate plane distance. Constant propagation
is the first captured stage that folds the two stores' pointer operands into
stack addresses. Address casts and separate plane-distance temporaries did not
fix these differences and are not retained.

The TU reaches **99.73444%**, with **24/30 functions exact**. Exactly 22
coordinator instructions change. All other functions, named-symbol layout,
allocated data sections, and resolved relocations remain unchanged; all five
source builds and strict checksum gates pass against hash-verified originals.
The new object SHA-256 is
`eb029dd1cdcbda02cd31262db562b3e40f567e640bbdb300126b59cfd9cdc123`.

The preceding source's allocator capture shows an initial 309-node GPR graph,
then a 364-node retry. `tricky_backend_trace.py --final-allocation-attempt`
now permits inspection of the final complete pair while explicitly recording
the earlier attempt as unreplayed. It retains all raw snapshots, requires the
retry graph to grow, and still rejects missing final pairs and incorrect
simplification/coloring. The strict default is unchanged. The observed final
attempt replays 332 simplification steps and physical color choices, including
one high-degree removal (virtual register 47, degree 29, weight 368). Spill
selection in the earlier attempt is not verified. LLDB and ordinary compilation
produce identical objects. This trace exposed the pointer-register ordering
that guided the retained source change.

## Final plane-distance temporary

The assignment is now `radiusDistance = (f32)radiusDistance - radius`.
Although both operands already have type `f32`, the explicit cast prevents
MWCC from coalescing the preceding plane sum into the call-argument register.
LLDB captures before and after reproduce their ordinary objects exactly.
Before the cast, both instructions define virtual FPR32, which coalesces into
physical FPR1. With the cast, the sum retains virtual FPR32 / physical FPR0,
while the subtraction defines virtual FPR41 and coalesces into physical FPR1.
Both final FPR graph replays pass (344 nodes / 310 choices before, 345 / 311
after), with no high-degree removals.

Exactly two instruction words change in all five versions: index 974 changes
`ec26002a` to `ec06002a`, and index 975 changes `ec21e828` to `ec20e828`.
The coordinator reaches **99.989235%**, with only the indirect-store differences
at indices 150 and 153 remaining. The TU reaches **99.73587%** and still has
**24/30 exact functions**. No other function, allocated data section, named-symbol
layout, resolved relocation or source object changes. Full source and strict
retail builds pass for all five hash-verified originals. The new track object
SHA-256 is `60852af4d1624f3f1854c1b9adbec74c181811a2f62d38b517aefc7f7aca75da`.

Ordinary `Vec` records for the transformed endpoints, register declarations,
address/value casts and a scalar store helper do not fix the remaining stores.
Volatile experiments alter other stores and are not retained. Double-precision
locals and arithmetic regress code generation; the retained cast is `f32` only.
