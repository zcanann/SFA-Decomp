# Block-triangle vector storage

`trackBuildBlockTriangles` stages three decoded vertices and three edge vectors
while preparing collision planes. Retail EN stores the vertices at stack offsets
0x38, 0x44, and 0x50, and the edge vectors at 0x5C, 0x68, and 0x74. The vertex
decoder writes the last two vertices through a cursor advancing twelve bytes;
the edge-plane loop visits all three edges with the same stride. The loop limits
establish three elements independently of the stack gaps.

The imported source declared six separate `f32[3]` locals in reverse order.
Its cursors crossed those independent C objects, relying on their accidental
stack adjacency. These are now `Vec triangleVertices[3]` and
`Vec edgeVectors[3]`, with `Vec*` cursors. The SDK vector calls use their native
types, and the second-vertex alias no longer passes through an integer cast.
The edge normal, edge index, degeneracy flag, and output component index also
have names describing their roles. The model-triangle collector uses a separate
scalar path and does not need this array recovery.

## Stack-array verification

- Input DOL checksums pass for EN, EN rev1, JP, and PAL rev1. Their normalized
  retail collector bodies are identical.
- Before/after compilation preserves every function's bytes, every allocated
  section, and every named symbol's layout in all four versions. One anonymous
  literal label changes from `@1964` to `@1974`; its relocation type, offset,
  addend, and resolved destination are unchanged.
- All four rebuilt objects have SHA256
  `73e2f58dbc5a4313a8ff80bccdc44fee48a82f994007007f9a9cd71544cebfc6`.
- The collector remains **98.475815%**, at **765 instructions / 3,060 bytes**.
  This recovers real source structure without changing matching scores or
  promoting a nonmatching unit.

No compiler settings, section ownership, or regional matching manifests change.
The full source build and strict EN checksum remain the integration gates;
the per-object comparison establishes the unchanged generated behavior.

## Shared triangle edge normals

The corresponding output storage is now `TrackTriangle.edgeNormals[3]`, using
the canonical `Vec3f` type. The block collector and model collector both write
three consecutive normal components for each of three edges. The intersection
consumer reads the same three vectors, pairing each with the corresponding
vertex to form an edge plane. This establishes an array independently of the
36-byte gap in the record. Assertions retain its element offsets at 0x24, 0x30,
and 0x3C and the full triangle size of 0x4C.

Both writers keep their evidenced component index: direct vector-indexed stores
shorten each collector by 44 bytes, regressing the original instruction stream.
The retained component writes use `sizeof(f32)` and the canonical `offsetof`
instead of numeric strides and the raw 0x24 field offset. All readers use the
array's named vector components. The ground-query host fixture imports the
canonical vector definition and alias along with the triangle record.

Full before/after source builds cover EN, EN rev1, JP, and PAL rev1. Every source
object except `track_dolphin.o` is byte-identical; that object's only changes are
anonymous literal names with unchanged resolved relocations. Its function bytes,
allocated data, and named symbol layouts remain identical. The three affected
retail function bodies also have identical normalized signatures across these
checksum-verified versions. Matching scores remain unchanged.

The resulting track object is identical across all four versions, with SHA256
`7be35b6e837332b9f96085f9aa8b46be97103bdc806728798ef71ccfdcb828e6`.
Formatting preserves this raw object. The comparison covers 1,002 EN source
objects and 987 in each secondary version; the five track tests also pass.

## Grid-origin and last-cell spill slots

The collector now computes the last cell with `last = count; last--;`.
Keeping these two source operations separate recovers the retail spill-slot
order without adding an instruction: the saved grid-origin pointer occupies
SP+336 and the last-cell index occupies SP+340. Before the change they were
reversed. This is allocator-created storage, not another declared array or
an alignment gap to model in C.

LLDB captures identify the first value as the global-origin address derived
for `firstp` and the second as `count - 1`. The original source starts with a
282-node GPR graph and retries with 397 nodes. The new source starts with 283
and retries with 398. Before the change, the index spill uses the named `last` object;
afterward it uses a generated spill object following the generated origin
spill. Both final attempts replay successfully: 365 and 366 color choices,
respectively, with the same two high-degree removals (virtual GPR39, degree 29,
weight 3; GPR88, degree 29, weight 960). Earlier spill-selection attempts remain
explicitly unreplayed. Each instrumented object equals its ordinary compile.

Across all five versions, the only changed instruction words are indices
188, 207, 213, 291 and 296. Each exchanges stack displacement 336 with 340;
all upper instruction bits, including opcode and register fields, are identical.
Every changed instruction now matches retail. The collector stays 765
instructions / 3,060 bytes and improves from **98.475815% to 98.48235%**.
The whole TU reaches **99.74156%**, still with **24/30 exact functions**.

Every other function, allocated data section, named-symbol layout, resolved
relocation, and other source object is unchanged. All five original DOL hashes
are rechecked, and each version passes `ninja all_source` and the strict retail
checksum target. The new object SHA-256 is
`7ecb728fb409bab9e079347ce5da067fb4c8bf96e396072b31f25d5c3f1c0daa`.

Grid-bound declaration moves, source coordinate-load rewrites, pointer casts
and integer address storage do not recover the remaining allocation. A `s32`
grid-bound variant changes many registers and slightly raises the fuzzy score
but does not recover the target grid-bound registers, so it is not retained.
Moving mask expressions into their consumers regresses the collector. The
retained correction is limited to the evidenced pair of spill slots.
## Register allocation after spill retry (September 20)

The retained ordinary-C collector now matches **99.888885%**, up from
**98.48235%**. Its 765 instructions / 3,060 bytes are unchanged in length.
The remaining eleven differing instructions are all register operands in the
initial grid-cell loop (indices 121, 124–126, 134–138, 144 and 150); the entire
following triangle-processing path matches retail.

The source changes the second vertex decoder's addition to
`(vp[1] >> 3) + blk->collisionYOffset`, matching the first decoder's spelling
and retail's load order. Reordering ordinary local declarations recovers the
remaining triangle-processing registers. Initializer execution stays in its
original block, and locals are returned to their original scopes wherever
that preserves the generated object. No volatile accesses, cursor aggregates,
compiler settings, or new storage objects are introduced by this change.

LLDB produces an object identical to the ordinary compile and aligns all 765
instructions. The final 398-node graph replays all 366 color choices and its
two high-degree removals. Retail's remaining four colors satisfy that same
interference graph: p2 requires r14 instead of r20, q2 requires r16 instead of
r17, and the generated X/Z grid-origin values require r20/r17 instead of
r16/r14. This establishes a valid allocation target, not an exact source match.

The register-comparison and retail-projection tools now accept
`--final-allocation-attempt`. They select the final simplification/rewrite pair,
keep strict rejection as the default, and report earlier allocation attempts
as unreplayed in both console and JSON output. They do not treat a successful
final coloring replay as verification of the earlier spill selection. The
comparison, projection and graph-replay suites pass 8, 7 and 35 tests.

Scratch investigation also recorded the first attempt's simplify order and
failed coloring through GC/1.3's coordinator, simplify and coloring routines
at 0x506DAB, 0x507070 and 0x506F50. Declaration-order candidates had to preserve
that attempt's spill set and spill ordering: optimizing only the final graph
predicted gains that disappeared when the real compiler chose different
spills. Those scratch captures are diagnostic experiments; the supported tool
still explicitly leaves the first 283-node attempt unreplayed.

Reproduce the retained-source capture and projection with:

```sh
python3 tools/tricky_backend_trace.py --unit main/main/track_dolphin \
  --function trackBuildBlockTriangles --graph --final-allocation-attempt \
  --output build/track_triangle_registers
python3 tools/mwcc_retail_registers.py build/track_triangle_registers/trace.json \
  --function trackBuildBlockTriangles --final-allocation-attempt
```

All five original DOL hashes are rechecked. Each version passes `all_source`
and the strict retail checksum, and produces the same track object, SHA-256
`64245dfca3780f798bbd4aecb997e085b1fa2853e44a2b04432409fb6dd9e73b`.
Only the collector's instruction bytes change: every other function, named
symbol layout, relocation and non-text section is identical to the preceding
object. All eight track tests pass, including the existing endpoint, wrapper,
edge, ground-query and surface-response fixtures; these do not directly test
the block-triangle collector's geometry.

The TU reaches **99.896484%**, retaining **25/30 exact functions**, and remains
`NonMatching`. The strict link still substitutes its retail object. The
collector's remaining grid-register differences and the other four imperfect
functions are not claimed complete.

## Frontend origin of the remaining grid counters (September 20)

A fresh LLDB capture of `bad98ad595` confirms that all eleven differences
remain register operands. The two multiplication instructions and their
incremented counters already exist in `BEFORE GLOBAL OPTIMIZATION`; they are
not introduced by the PPC backend's later strength-reduction pass. In the
final allocation graph:

| Value | Virtual GPR | Current physical | Retail physical |
| --- | --- | --- | --- |
| `p2` | 107 | r20 | r14 |
| `q2` | 110 | r17 | r16 |
| X origin, generated `@1899` | 166 | r16 | r20 |
| Z origin, generated `@1897` | 168 | r14 | r17 |

The named-register boundary is 122. Both generated objects are created by
`0x004F4200`, observed at its return instruction `0x004F4275`, with caller
return address `0x004A6D8C`. Static inspection places that call at
`0x004A6D87` inside the frontend routine `0x004A6D60`–`0x004A7287`.
Its caller at `0x004A59EE` sits in the path labeled by the compiler's
"Found reduction in strength" diagnostic. The caller first checks existing
reduction records with `0x00469180`, and invokes the materializer on a miss.
These are observed call sites and inferred roles, not recovered original
source names or a reconstruction of either complete routine.

The capture still produces the ordinary object's exact SHA-256:
`76488b758f3e83805c526eff61d0eb627c5edf9c078244d1b1917d3f22f7a235`.
The 398-node final graph replays all 366 color choices and two high-degree
removals. The first 283-node allocation attempt remains explicitly unreplayed.
No source match is gained: the collector stays 99.888885%, and the TU stays
99.92923%, 26/30 exact.

The supported LLDB provider now exposes this diagnostic without the scratch
provider copy:

```sh
python3 tools/tricky_backend_trace.py --unit main/main/track_dolphin \
  --function trackBuildBlockTriangles --graph --final-allocation-attempt \
  --temporary-name '@1897' --temporary-name '@1899' \
  --output build/track_triangle_births
```

Temporary names depend on the current source and compiler. The tool fails
if a requested name has no observed birth in the selected graphs. It joins
factory results to graph nodes by object address and checks name/type identity;
register numbers alone are not used as identity. The return address identifies
one caller site, not an unwound stack. The new option is macOS-only; existing
capture modes and cross-platform trace reading remain available. The factory's
RET is emulated as a four-byte guest return, without changing its EAX result.
Ordinary/instrumented object equality remains mandatory.

Source probes retain no changes. Reusing scalar coordinate locals, extracting
inline store/append helpers, changing pointer-store views, and spelling the
loops as split-initialization `for` or `while` forms preserve the same residual.
Explicit coordinate induction counters regress code and spill layout. Typed
three-word origin records also do not improve the match. Volatile coordinate
stores add operand differences; qualifying only the block-pointer store does
not help. No additional volatile exception is justified. The next useful
boundary is frontend reduction-record reuse/materialization and its ordering,
rather than the backend initialization emitter.

The LLDB provider, trace inspection and graph suites pass 12, 6 and 35 tests.
The new trace also passes offline readback with the same full allocator checks.

## Exact grid collection through nested indices (September 20)

`trackBuildBlockTriangles` now matches **100%**, all **765 instructions /
3,060 bytes**, in EN, EN rev1, JP, PAL and PAL rev1. The TU reaches
**99.94134%**, with **27/30 exact functions**. It remains `NonMatching` because
`trackIntersect`, `trackGetLineIntersect` and `trackGetHeight` are not exact.

The successful source keeps each layer's starting pointers fixed and uses
`layerCount` to locate each column's start. Within a column, `columnCount`
indexes successful block lookups and their three-word origins. Both counts
advance only when a block exists. The column count advances before the layer
count, followed by the retained overall cursors. MWCC's frontend strength
reduction generates the intermediate pointer counters with retail's register
allocation and update order. No volatile access is added.

This follows reconstruction of three complete GC/1.3 routines in the sibling
MWCC project, under `src/versions/GC_1_3/`:

- `IROLoopReduction.c`: driver at 0x004a5580, 1,520 bytes; 3,001 differential cases.
- `IROReduction.c`: materializer at 0x004a6d60, 1,320 bytes; 1,920 cases.
- `IROExpressionEqual.c`: ordered equality at 0x00469180, 602 bytes; 6,294 cases.

The compiler models are checked against isolated original x86 instructions
with explicit dependency adapters; they do not claim Win32 object matching.
Their sources, partial layout assertions, native tests, reproducible offline
oracles and fixtures are recorded in that project's `docs/IRO_REDUCTION.md`.
LLDB establishes that the X/Z reductions are multiplication by 640 with unit
steps and no optional increment object. The useful source change instead makes
the pointer counters compiler-generated through nested indexing.

A final supported LLDB capture produces the ordinary object's exact SHA-256,
`5c353e528455ac0a2bbba4f84c61881d13c8fa8fa2be6b6ba3c5a2584522a677`,
with zero retail instruction differences. Its final 398-node allocation graph
replays all 366 color choices and two high-degree removals. The initial
283-node spill-selection attempt remains explicitly unreplayed.

All five verified input DOLs pass `ninja all_source` and the strict retail
checksum target. Each region produces that same source object and reports the
collector exact in objdiff. Relative to the preceding source object, only
15 bytes in this function change; other function bytes, allocated data and
named symbol offsets are preserved. One anonymous literal label is renumbered,
with its relocation destination unchanged. Formatting preserves the candidate
object. The eight existing track tests also pass; they cover endpoints,
wrappers, edges and ground/surface queries, not full block-triangle geometry.
The strict link continues to use the retail object for this incomplete TU.
