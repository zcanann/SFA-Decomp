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
