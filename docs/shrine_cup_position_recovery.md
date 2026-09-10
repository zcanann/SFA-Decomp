# Shrine cup-position initializer

Slot 399's `ecshShrine_update` uses one eight-byte `(x, z)` position while
rotating cup locations in shuffle patterns six and seven. The temporary now
uses the existing `ECSHShrineCupPosition` type and named fields, replacing a
float array initialized through a fabricated pair of integer words. Its native
`{0.0f, 0.0f}` initializer emits the missing `.sbss2` template.

The recovered position definition and its field/size assertions live in the
canonical shrine header. The existing `ECSHShrinePuzzleScratch` definition and
assertions also move there without changing its fields or uses. That scratch
view still spans the two adjacent position and slot-map globals; their separate
definitions, declaration order and packed offsets are preserved. The descriptor
retains its already-exact earlier position in the TU's data.

Initialization order matters. The original code first obtains the scratch
pointer and state, then calls `Obj_GetPlayerObject`, then copies the zero
position. Giving those existing locals initializers and declaring the position
immediately afterward preserves that sequence without a large nested block.
Initializing the position at the very start instead changes instructions and
was discarded. The unnecessary `ECSHShrineWordPair` type and external zero
placeholder are removed.

## Retail ownership

Two word loads at `ecshShrine_update+0x34` and `+0x38` select the position's
first and second words. They are the only direct r2 load/store accesses to the
last eight bytes of the BSS tail in each verified retail DOL. The active EN
extracted-object relocation scan likewise finds only these two references,
both in the shrine TU. Header-derived BSS ends independently confirm the end
of the record. No file-backed payload is assumed for zero-initialized storage.

| Version | Retail loads | Claimed `.sbss2` range |
| --- | --- | --- |
| EN | `801C60EC`, `801C60F0` | `803E8470..803E8478` |
| EN rev1 | `801C66A0`, `801C66A4` | `803E90F0..803E90F8` |
| JP | `801C61DC`, `801C61E0` | `803E8590..803E8598` |
| PAL rev1 | `801C68F0`, `801C68F4` | `803E9E50..803E9E58` |

The old two four-byte symbols become one eight-byte
`sECSHShrineCupPositionInit` record in each config. The regional projector
independently reproduces all three new claims. Its unrelated symbol metadata
normalization is not included in this recovery.

## Completed zero-tail ownership

This accounts for the final initializer in the 56-byte `.sbss2` tail. Source
objects naturally emit 39 bytes across six TUs:

| Owner | Initializer payload |
| --- | ---: |
| Shader: glow, material and lightmap fog colors | 12 |
| Renderer: channel and depth-fade fog colors | 8 |
| Sky backdrop color | 4 |
| Sky selected direction indices | 3 |
| Explosion additive color | 4 |
| Shrine cup position | 8 |

The other 17 bytes are alignment. DTK counts one of those bytes inside the
word-ended sky index split, so objdiff reports 40 assigned and matched bytes
for these sections and omits the other 16 alignment bytes. No automatic
`.sbss2` units remain in any of the four reports. This establishes data
ownership, not completion of all code in those TUs: shader still contains
nonmatching functions.

## Validation

All four versions retain 16 exact functions and 5,244 code bytes. All previous
allocated sections and all 21 named symbol layouts are unchanged. The source
adds only an eight-byte, eight-aligned `SHT_NOBITS` `.sbss2` section. Both new
relocations select its offsets zero and four at the exact retail instructions;
all other relocation sites, kinds, addends and destination layouts are unchanged.

Each version gains eight matched and completed data bytes, bringing the shrine
to 400 exact data bytes. The data denominator decreases by four bytes when DTK
recognizes the preceding explosion alignment gap. Every other compiled source
object, including header consumers, is byte-identical in all four builds.
The generated-path audit, full-source builds and strict EN checksum pass; EN
links the shrine's compiled source. Formatting is checked separately for
unchanged object bytes.
