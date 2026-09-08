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

## Verification

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
