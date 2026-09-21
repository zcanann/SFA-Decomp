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

## Store-fold watchpoint and compiler selector

A hardware watchpoint on the first remaining store's base-register operand
catches the write at compiler PC `0x005747f7`, after the second word copy at
`0x005747f6`. The instrumented and ordinary objects both retain SHA-256
`60852af4d1624f3f1854c1b9adbec74c181811a2f62d38b517aefc7f7aca75da`.
The before/after IR shows virtual GPR65 with immediate offset zero becoming
frame GPR1 with a kind-3 symbolic operand and displacement 4; the adjacent
GPR66 store similarly acquires displacement 8. This locates the actual fold,
not merely the first dump that exposes its result.

The caller invokes a 122-byte selector at `0x00574a10` from `0x005747df`.
The selector reads the current definition table at `0x005dfc38`, checks ADDI
opcode `0x3f`, symbolic operand kind 3, either configured frame base
(`0x005e70e0` / `0x005e6cfa`), local-object kind 1, and the offset predicate
at `0x004f5c90`. The observed definition uses frame base 1; the second allowed
base is -1. On success the caller copies the defining address operands into
the store. The definition lookup and local-frame eligibility are therefore
the relevant next source-model boundary, rather than physical register choice.

The sibling compiler project now has a local `ConstantAddress.c` model of the
complete selector, registered with host tests and its GC/1.3 manifest. All
8,140 original/native cases agree, covering all 47 reachable x86 instructions,
signed offset truncation, alternate frame bases, rejected definitions and
unchanged failure output. Its offset-predicate call is an explicit stub
boundary, and no Win32 binary match is claimed. `ninja check` passes there.

Moving scratch-pointer setup into query loops, constructing component addresses
through named base pointers, or extracting scalar/vector translation helpers
does not improve the coordinator. Those experiments remain outside production
source. The TU is unchanged at 99.73587%, with the coordinator at 99.989235%.

## Two-store diagnostic control (2026-09-20)

A fresh GC/1.3 LLDB capture confirms that the current coordinator still differs
at only instruction indices 150 and 153. These are the static-world endpoint
copies, not the earlier bounce initialization or the start-point copies:

```c
*endY = cur[1];
*endZ = cur[2] - offZ;
```

Retail writes through r27/r28; current source emits SP+164/SP+168. The complete
ordinary and instrumented baseline objects have SHA-256
`7ecb728fb409bab9e079347ce5da067fb4c8bf96e396072b31f25d5c3f1c0daa`.
The captured function has 19 stages and 1,115 final instructions.

The sibling `../mwcc` model in
`src/versions/GC_1_3/ConstantAddress.c` explains the frame-address selector.
Further static inspection of the hash-verified GC/1.3 binary establishes two
relevant parts of its caller:

- At `0x00573866..0x00573871`, the instruction walker tests bit `0x80` of the
  instruction flags at `+0x14`. A set bit branches directly to the next
  instruction at `0x00574978`, bypassing constant folding.
- `0x00574a90..0x00574c1a` initializes the GPR, FPR and special-register
  definition tables for a block. It intersects each register's definition list
  with that block's incoming definition bitset. Exactly one incoming definition
  yields a PCode pointer; zero or multiple definitions yield null. The driver
  at `0x00573820..0x00573828` calls this initializer before the block walker.
  These roles are inferred from the instructions, not recovered source names;
  this investigation does not claim a differential test of the initializer.

As a **diagnostic only**, changing the two accesses to
`*(volatile f32*)endY` and `*(volatile f32*)endZ` reproduces **100% objdiff** for
the function. LLDB shows their flags changing from `0x4` to `0x84`. Their
virtual bases remain GPR65/GPR66 across constant propagation, whereas baseline
changes both bases to frame GPR1 and symbolic offsets 4/8. The diagnostic's
ordinary and instrumented objects both hash to
`11777ad64940b5717740ff6ff6d75db649fdc6db20e93c74fbf6d1d95aff0893`.

The raw object comparison changes exactly four bytes in two instruction words:
`d00100a4` becomes `d01b0000`, and `d00100a8` becomes `d01c0000`.
All other function bodies, allocated data, section layouts, named symbols and
relocations are unchanged. This isolates the optimizer gate without requiring
an allocator change. It does **not** establish that these ordinary stack writes
were volatile in the original source. The casts are not installed in `src/`,
and neither the function nor TU is promoted to matching.

Focused ordinary-source controls give the following results:

| Source experiment | Instructions | Objdiff |
| --- | ---: | ---: |
| Baseline | 1,115 | 99.989235% |
| Explicit same-type pointer casts | 1,115 | 99.989235% |
| Block-local aliases for the two pointers | 1,115 | 99.989235% |
| Direct `we[1]` / `we[2]` accesses at these two sites | 1,117 | 99.779370% |
| Volatile-pointee diagnostic | 1,115 | 100% |

Additional scratch controls with void/byte pointer casts, same-type value
casts, scalar inline stores, inline pointer identity helpers, and cursor-based
translation helpers leave both differences intact. Splitting the Z copy and
subtraction adds a store. Reassigning the endpoint pointers inside the branch
changes allocation extensively. None is retained as game source.

Reproduce the focused controls and independently hash-gated captures with:

```sh
python3 tools/track_intersect_store_probe.py --capture
```

The tool writes complete scratch sources/objects and `report.json` under
`build/track_intersect_store_probe/`. It uses fresh compilation directories,
the actual configured TU flags, objdiff, full object comparisons, and the
existing LLDB capture equivalence gate. Its report records both stores' flags
and operands immediately before and after constant propagation. Without
`--capture`, the same source/object controls run without a debugger.

All five originals were checked against their configured SHA-1 values. The
EN-built diagnostic object also scores 100% for this function against each
regional retail object. This is a cross-region comparison of one experimental
object, not five regional source builds or source-link completion. The current
EN `ninja all_source` and strict retail checksum pass. Production source remains
at 99.989235%; the unresolved task is recovering a justified source shape that
retains the two indirect stores.

## Retained volatile exception (2026-09-20)

The user authorized the two volatile accesses as a narrow matching exception
if another non-volatile investigation did not succeed, with a TODO to revisit
them. A second round tested 12 ordinary C variants on the fresh staging tip:
deriving either coordinate pointer from the other, incrementing the pointers
during setup, byte-based initializers, four sequential vector-copy cursors,
point/bounce-scoped initialization, and an inline translation helper with scalar
inputs and separate output pointers. None reached 100%. Byte initializers and
the four cursors retained the original two differences; the other variants
regressed instruction count or operands. Local results are retained under
`build/track_intersect_lldb/second_round/`.

The two casts are now retained in `trackGetIntersect2`, immediately below:

```c
/* TODO: Recover a non-volatile source shape that preserves retail's indirect stores. */
```

This supersedes the preceding investigation's decision to keep them outside
production. It is an explicitly authorized code-generation workaround, not
evidence that the original stack accesses were volatile. The rest of the
function, compiler flags and TU boundaries are unchanged. The entire TU remains
`NonMatching`, since five other functions still differ.

The retained function reaches **100%**, with **25/30 exact functions** and
**99.74327%** overall for the TU. Its object hash is the diagnostic hash above:
only the two store words change relative to baseline, with no other function,
data, symbol-layout or relocation differences. `clang-format -i` makes no
additional edits to the TU or its canonical header; both pass the dry-run check
and formatting preserves the complete object. The probe accepts both the
ordinary and retained source forms and continues to recreate the non-volatile
baseline before comparing controls.

The retained source was then rebuilt separately for all five configured retail
versions. Each has the same object hash, 100% for this function, and passing
`ninja all_source` and strict checksum gates against independently hash-verified
original DOLs. Each Ninja invocation was limited to 30 seconds. The matching
link still uses the retail object for this incomplete TU; objdiff verifies the
new source function directly. The regional results and build logs are under
`build/track_intersect_lldb/retained_regions/`, and the active build configuration
is restored to EN v1.0. A fresh LLDB run of the retained-source probe also
reproduces the baseline and exact exception objects without instrumentation
changes to either output.
