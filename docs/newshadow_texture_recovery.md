# Procedural shadow texture recovery

## Noise records

The generator and sampler both advance by 20 bytes per placement. The generator
caps the live prefix at 50 records; the sampler interprets offsets 0/4/8/12/16 as
frame count, normalized X/Z position, and starting/ending radius. Recover these
as `NewShadowNoisePlacement`, with field and size assertions in the owning
internal header. Position comparisons wrap around the unit square. Radius
contracts with the square root of normalized animation time.

The former `f32[274]` backing span is 1096 bytes. Only its first 1000 bytes have
proven record consumers. `NewShadowNoiseData` therefore models 50 records and an
opaque 96-byte tail, not 54 invented placements. The total span is inherited
from the current TU BSS ownership; the tail's original declaration is still
unknown. Renaming the BSS symbol and using typed record pointers changes no
instruction bytes, section sizes, or allocated data. The sampler stays exact;
the generator retains its pre-existing 98.66216% match.

The generator retains pointers to the candidate record's X/Z/end-radius fields.
Replacing those with repeated member expressions removes three retail
instructions. These pointers are meaningful live field references, not raw
state-offset accessors.

## Tiled blend

The two branches blend GX RGB565 and RGBA8 4x4 tiles. Each source contribution
is shifted by eight before adding; combining products and shifting once is not
equivalent. Weights are the wrapped low byte of `int(255 * blend)` and its
complement, not clamped interpolation weights.

Retail address chains add pixel-in-row, tile-column, row-in-tile, and tile-row
offsets in that order. Recover that order for both RGB565 sources and the
destination; put the first source's red contribution first. Remove the trivial
read/write macros and name coordinates, channels, and row offsets. Keep width
and height as dimensions instead of reusing them for unrelated tiled offsets.

RGBA8 has separate AR and GB halfword planes. The routine deliberately writes
only the blended red byte into AR, clearing alpha. Its later width reload after
that write is retained, as are in-place destinations and the final cache store.

This is an intentional source-recovery regression in fuzzy score, not a new
exact match: `blendTextures` goes from 94.48052% to 93.78788%. It retains all 231
instructions and the retail mnemonic sequence. Every other function in the TU
is byte-identical, all 38 exact functions remain exact, and all non-code section
bytes and named BSS offsets are preserved. The TU remains NonMatching.

## Checks

`python -m unittest discover -s tools -p test_shadow_texture_blend.py` compiles
the actual function body with a minimal host fixture and checks 210 randomized
format/size/weight/destination combinations plus ten rejection cases. A separate
pixel oracle covers tile crossings, RGB expansion, independent truncation,
alpha clearing, in-place operation, unchanged headers, and cache-store bounds.
Host-native halfwords avoid mistaking host byte order for the PowerPC image
format. This is behavioral evidence, not a substitute for the PPC comparison.

`ninja all_source` and the strict retail DOL checksum pass. Because this TU is
NonMatching, the DOL gate protects integration; the object comparison is the
evidence for its own generated code and data. Formatting is verified in a
separate commit by raw hashes of the affected objects.
