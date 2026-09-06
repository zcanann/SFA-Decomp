# Text-box texture loops

`gameTextInitBoxTextures` at EN `0x8001C794` creates two RGB5A3 textures from
linear halfword images: a 16x16 corner and a 20x20 edge. Both are stored in GX
4x4 tiles. The source arrays are independently defined in `textrender_drawbox.c`
and occupy exactly 512 and 800 bytes in retail. No texture asset bytes change.

## Recovered source shape

Replace the imported expansion of 48 halfword stores and its byte-offset
temporaries with four nested loops: tile row, tile column, texel row, texel
column. A `u16*` source-row view keeps the row origin separate from the column
index, matching retail's row-base-plus-column addressing. Each destination
advances by one halfword. Separate row counters and destination cursors describe
the two independently allocated images; the inner coordinates and row view are
reused.

The existing profile disabled both strength reduction and propagation. That
profile was fitted to the already-expanded source: removing either restriction
there did not establish the settings for the original loops. Retail's running
row offsets, derived tile coordinates, and constant-zero induction-variable
initializers give direct reasons to test those optimizations on ordinary loops.
With both enabled, GC/1.3 reproduces the 234-instruction expansion, including
the corner's two-tile unrolling and the edge's single-tile loop. Removing the
row view instead changes address factoring and produces a much shorter body.

Only this TU's existing profile changes: `nostrength` and `nopropagation` are
removed, with no compiler-version override, assembly, pragma, or TU split.
Other optimization restrictions remain provisional; this result does not prove
their original settings.

## Matching and checks

- Fuzzy code match: **96.66239% -> 98.290596%**.
- Target and current length: **234 instructions / 936 bytes**.
- Operand differences: **136 -> 59**; one structural difference remains, the
  edge loop's initial `li` versus retail's `mr`. Register allocation is not yet
  exact, so the unit remains `NonMatching`.
- All allocated data and named symbol layouts are unchanged. The resulting raw
  object SHA256 is
  `c5c87d290e941289d0e726a9019c3ac5fcfc63b02b7506a5bbc296d06e93d166`.

`python -m unittest discover -s tools -p test_gametext_box_textures.py` compiles
the production TU with host-native texture storage and controlled allocator,
asset-loader, and cache dependencies. It checks every texel against an
independent linear-coordinate-to-tile-index oracle: one coordinate pattern,
32 randomized image pairs, and the retained texture assets, totaling 22304
halfwords. Header bytes, guards on both sides, the background texture, and
source images remain untouched. The test also checks load/allocate/flush order,
all allocation parameters, published pointers, and exact flush ranges.

A negative control shifts each source column within its tile; both tests reject
it. Host halfwords test copying and addressing, not PowerPC serialization or GX
hardware behavior. The target object comparison remains the codegen evidence.
`ninja all_source` and the strict matching build pass; this nonmatching TU uses
its retail object in the latter, so the DOL gate is an integration check only.
