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
