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

## Procedural row loops

The two 256x4 I8 ramps are nested pixel loops, not four hand-expanded writes.
MWCC 1.3 unrolls their four-row inner loops into byte-identical instructions.
The addresses follow GX's 8x4 I8 tiles; the inverse ramp stores `255 - x`.

The 4x4 reflection gradient similarly has a four-row inner loop. Each channel
encodes a coordinate using `255 * (coordinate / 3 - 0.5) + 128`, truncated to
an integer. The high byte follows X and the low byte follows Y in a 4x4 tile.
Unrolling folds the Y expressions to 0.5, 85.5, 170.5, and 255.5, while leaving
the retail float-to-integer conversions in place. Writing those values as
literal integer casts directly would fold the conversions too early.

This recovers three anonymous pool words without any named constants or section
directives. `.sdata2` grows from 244 to 256 bytes, ending with the retail words
`42ab0000 432a8000 437f8000`. The existing 0.5 literal can also replace its
external alias at every consumer. Four external declarations are removed.

The two ramp loops alone are byte-neutral. The combined change preserves all
43 other function bodies, all 38 exact functions, every named symbol offset,
and all other allocated data. `allocLotsOfTextures` retains 1487 instructions;
its final gradient store has three address instructions scheduled earlier than
retail. Its fuzzy score changes from 98.066574% to 97.93544%, and the TU from
98.7832% to 98.74698%. This is source and pool recovery, not an exact code gain.

Replacing all seven remaining external floats was also tested, not landed.
It emits a 280-byte pool but changes loop-invariant motion, including the exact
noise sampler. The remaining pool ordering difference lies in the distortion
falloff's 100.799995, 1/256, and 112 values. Computing the falloff before its
radius clamp reproduces the complete retail pool but worsens that function's
code. These experiments identify adjacent source-shape questions; they do not
establish the original compiler settings or justify forced data declarations.

## Normalization and complete literal pool

The reciprocal words are generated from coordinate divisions by 8, 16, 32,
and 64. Spelling them as divisions matters: MWCC lowers these operations late,
after transformations which move or combine literal multiplications. For
example, `frame / 16.0f` preserves the exact noise sampler; replacing the old
external reciprocal with `frame * 0.0625f` hoists its contribution out of the
placement loop. The final output scale remains `0.125f * shift`, which emits
the evidenced multiply-add operand order.

Distortion strength is a radius-limited conditional expression:

```c
strength = radius <= 112.0f
               ? (2.0f * (0.9f * 112.0f - 0.9f * radius)) / 256.0f
               : 0.0f;
```

This produces both the exact 116-instruction function and the retail pool
order: the folded 100.799995 intercept, the generated 1/256 reciprocal, then
112. The center is (127.5, 127.5); normalized direction is scaled by the
falloff and encoded with a gain of 127 and a bias of 128. Tiled addressing
establishes that the outer coordinate is X, not the old decompiler's Y;
the high byte encodes X and the low byte Y. Local names now follow that view.

Together with the literal disk scales 1.1 and 1.2, these expressions eliminate
the last seven external float declarations. The complete 280-byte `.sdata2`
section is byte-identical to retail, with no named literal definitions or
section placement directives. All other allocated data and named data symbol
offsets are unchanged. The earlier before-the-clamp experiment is superseded
by the exact conditional expression above.

Relative to the row-loop checkpoint, distortion improves from 96.206894% to
100%, adding 464 matched code bytes. Noise generation improves from 98.66216%
to 98.75676%. Allocation changes from 97.93544% to 97.24613%: literal disk
scales allow loop-invariant motion, leaving 1485 instructions against retail's
1487. The other 41 function bodies are byte-identical, including all 38
previously exact functions. The TU now has 39/44 exact functions, 5160 matched
code bytes, and all 16668 data bytes matched; its fuzzy score is 98.644806%.

A separate BSS experiment removes the synthetic `NewShadowData` overlay in
favor of the existing arrays. MWCC then forms its own `...bss.0` base, but
reorders the arrays. Definitions placed before all functions allocate in
first-use order; changing declaration order alone does not restore retail.
That experiment is not landed. Retaining zero-filled section equality without
checking the named offsets would conceal a real layout regression.

## Noise and caustic channels

Noise and caustic texels use the same 4x4 halfword tiling, but do not share an
XY record layout. Noise writes intensity in the high byte and shift in the
low byte; caustics write the modulated product and the wave respectively.
Replace the one-field `NewShadowVectorTexel` wrapper with ordinary halfword
stores and name those channel values. Distortion's independent X/Y encoding
keeps its exact instruction bytes after the same wrapper removal.

Recover real byte pointers for both generated texture address chains. Their
successive values identify pixel-in-row, tile-column, row-in-tile, and tile-row
contributions. The old noise expression added the column offset first and
carried its address in an integer. Both generated images now use texture X/Y
coordinates consistently, with texture Y supplied as the noise field's Z.
Use `sizeof(Texture)` at the payload boundary instead of literal 0x60.

The caustic phase steps factor as `6.284f / 64.0f` and `6.284f / 16.0f`.
These preserve the exact pool words while exposing the intended approximately
one-cycle and four-cycle phase ranges across the image. Keep the evidenced
6.284 approximation rather than substituting a more accurate pi constant.
The overlap check also keeps X/Z distances separate from the radial distance.

These changes improve noise generation from 98.75676% to 98.9054%, retaining
370 instructions and the complete retail mnemonic sequence. Its operand
differences decrease from 74 to 70. Every other function and all allocated
data are byte-identical; all 39 exact functions and 100% data matching remain.

Fixed-count inner loops were tested for the blur's explicit tile copies, but
change MWCC's outer unrolling substantially. Those experiments are not landed.

## Native texture contracts

All eleven remaining integer-backed texture globals are `Texture*`: their
values come directly from `textureAlloc` or `textureLoadAsset`, and consumers
use the canonical texture header, GX object, or inline payload. The bump fill
now carries its tiled pixel address as `u8*` instead of truncating it through
an integer. Global declaration order and storage widths remain unchanged.

The five pointer-returning getters and five formerly `u32*` output getters
now expose `Texture*` and `Texture**` in their owning headers. Their seven
direct consumer TUs no longer cast texture pointers through these integer
contracts. The pause-menu disk texture and projected-shadow comparison local
also use `Texture*`; no unrelated consumer formatting or type cleanup is mixed
into this change.

All seven edited consumer objects remain byte-for-byte identical, including
all 48 shader functions and all 65 intersection-render functions. In
`newshadows`, the other 43 function bodies remain byte-identical and all 39
exact functions remain exact. Allocation retains 1485 instructions against
retail's 1487 and 16 structural differences; operand differences increase from
330 to 342. Its fuzzy score changes from 97.24613% to 97.19906%, and the TU from
98.65502% to 98.64202%. This is source-contract recovery, not a matching gain.

All 16668 allocated data bytes and every named symbol's section, offset, size,
and linkage remain unchanged. Relocations have identical targets and addends;
only generated anonymous pool symbol names change. No compiler flags, sections,
constant definitions, or inline assembly are introduced. Natural single-address
and halfword-indexed bump expressions were also tested but add structural
differences, so the existing byte-address sequence is retained.

## Checks

`python -m unittest discover -s tools -p test_shadow_texture_blend.py` compiles
the actual function body with a minimal host fixture and checks 210 randomized
format/size/weight/destination combinations plus ten rejection cases. A separate
pixel oracle covers tile crossings, RGB expansion, independent truncation,
alpha clearing, in-place operation, unchanged headers, and cache-store bounds.
Host-native halfwords avoid mistaking host byte order for the PowerPC image
format. This is behavioral evidence, not a substitute for the PPC comparison.

The same harness compiles the three recovered fill bodies and checks every
texel: 2048 I8 ramp pixels and 16 gradient halfwords, plus unchanged headers
and trailing canaries. The fixture widens texture storage to host pointers;
PowerPC object comparisons separately check the actual target representation.

The distortion test compiles the actual recovered function and checks all
65536 texels against an independent radial-field oracle with single-precision
rounding. It also checks allocation arguments, the returned texture, exactly
one cache flush over the payload, unchanged header bytes, and trailing canaries.
The host uses a native square root and non-fused arithmetic; the separate exact
PowerPC comparison establishes the retail square-root and fused instruction
sequence, rather than assuming host execution emulates those instructions.

`python -m unittest discover -s tools -p test_shadow_noise_generation.py`
compiles the actual generator with controlled sampler, trigonometry, allocator,
random, cache, and heap dependencies. It checks all 69632 halfwords across the
16 noise frames and caustic image, headers and canaries, phase arguments,
allocation/flush order, texture publication, scroll resets, and heap restoration.
Identical candidate centers exercise the 10000-attempt retry boundary: retail
still counts the final overlapping placement, yielding two sampled records.
Unused placement records and the opaque BSS tail must remain untouched.
The controlled numerical dependencies isolate addressing and lifecycle; this
test does not claim to validate the real noise sampler or trig approximation.

`ninja all_source` and the strict retail DOL checksum pass. Because this TU is
NonMatching, the DOL gate protects integration; the object comparison is the
evidence for its own generated code and data. Formatting is verified in a
separate commit by raw hashes of the affected objects.

## Native shadow storage (2026-09-07)

The earlier BSS experiment is resolved with deferred emission and reverse
ordinary-function definition order. The common GC/1.3 compiler, optimization
profile including `nodead`, disabled automatic inlining, and TU boundaries
remain. Every native array is defined before the function bodies, in the order
that preserves the existing physical allocations. MWCC generates its own shared
BSS base. The synthetic `NewShadowData` view is removed from the internal header.
Rendering and allocation now name the caster, cast-slot, cast-texture, and frame-
texture arrays directly, including the cast-slot index's evidenced byte narrowing.

| BSS offset | Native storage | Bytes |
| --- | --- | ---: |
| `0000` | 33 entry records | 660 |
| `0294` | Three frame-texture pointers | 12 |
| `02A0` | 8 by 4 texture-pointer table | 128 |
| `0320` | Sixteen noise-frame pointers | 64 |
| `0360` | 300 queued casters | 3600 |
| `1170` | 100 cast slots | 10400 |
| `3A10` | Eight cast-texture pointers | 32 |
| `3A30` | Existing noise records and opaque tail | 1096 |

The combined view previously obscured the texture and noise-frame tables inside
a padding span. The native definitions, the retail common-base instructions,
and initialization following consumers in text support this emission model.
All pre-existing named symbol offsets, sizes, linkage, and every allocated
non-text section's bytes, extent, and alignment are unchanged. The compiler adds
only its internal zero-size `...bss.0` base symbol.

The allocation routine initializes 33 records, which independently confirms the
660-byte array extent. Its manually expanded sixteen-record writes and tail loop
are now one loop in a private inline helper setting each entry's `isActive`
and `state` bytes. The helper keeps the loop index local to initialization and
preserves all 5,940 instruction bytes of the allocation routine. Layout
assertions cover the 20-byte record, both byte offsets, and complete array size.
The release routine deliberately retains the retail 37-record byte scan. Its
last four `isActive` accesses reach texture-table bytes at offsets 0x04, 0x18,
0x2c, and 0x40 within `gNewShadowTextureTable`; initialization does not own or
clear those as extra entries. The proven byte-field loads/stores and complete
release-function code are retained, with the overrun documented at the source.
The allocation is not enlarged to conceal it.

All 39 previously exact functions remain exact. Rendering improves slightly
from 99.730354% to 99.745766%; only two instruction bytes in `renderShadows`
change. Every other function's instruction bytes are unchanged, including
`allocLotsOfTextures` at 97.19906%. The whole-unit fuzzy score improves from
98.64202% to 98.643875%, while all 16,668 data bytes remain exact. This is
native-storage and source-structure recovery, with no additional exact function.
The unit remains `NonMatching`.

The four blend/fill/distortion tests and the noise-generation test pass. Their
scope remains the generated images and lifecycle described above; the entry
loop is validated by the byte-identical allocation routine rather than claimed
as covered by those image tests.

Both `ninja all_source` and the strict retail DOL checksum pass after integration
with current staging. All resolved relocation destinations are unchanged.

## Exact shadow renderer (2026-09-07)

`renderShadows` now matches all 2,596 retail code bytes. Three source details
close its remaining differences:

- The projection scale has its own `shadowScale` local instead of reusing the
  light direction's Z component. MWCC can reuse the dead direction register for
  the scale, matching the projection calls without extending an unrelated local.
- The viewport extent is `u32`, consistent with its nonnegative texture-width
  sources, GX scissor arguments, and the retail unsigned float conversion for
  `GXSetViewport`. This also preserves the retail scissor argument evaluation.
- A private inline `shadowSquare` helper expresses the two separately rounded
  products used for horizontal length. Its calls retain the two `fmuls` and
  produce the retail addition operand order before the inline square root.
  Combining the products into one expression would permit a fused operation.

Only 16 instruction bytes in the renderer change. Every other function body,
all named symbol layouts, every allocated non-text section, and resolved
relocation destinations are unchanged. The unit advances from 39 to 40 exact
functions out of 44, with 2,596 additional matched code bytes and all 16,668 data
bytes still exact. Its fuzzy score rises from 98.643875% to 98.67453%.
The common compiler and complete TU profile remain unchanged.

`ninja all_source` and the strict retail DOL checksum both pass. The TU remains
`NonMatching` because four other bodies are incomplete, so its new exact-function
credit comes from objdiff; the checksum separately validates integration.
