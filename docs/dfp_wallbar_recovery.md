# DFP wall-bar placement and display state

Slot 560 displays the safe-floor solution using model banks and Z rotation.
Its state, placement prefix, public API and real descriptor declaration now
belong to `include/dlls/objects/560_DFP_wallbar.h`. The old `ChukaState` and
`ChukaPlacement` headers and the unsupported baddie-state-machine description
are removed. Existing public callback and descriptor symbols remain unchanged.

## Retail-backed layouts

EN's extra-size callback at `80205F48` returns 0x0C. Initialization stores the
object's initial local Y at state offset zero; no later function in this TU
reads it. The controller pointer occupies offset four, followed by the row
index and selected safe tile at offsets eight and nine. The final two bytes
remain opaque. State size and all recovered field offsets are asserted.

The common placement prefix is followed by a signed rotation byte at 0x18,
unsigned row byte at 0x19, signed initial Z rotation at 0x1A and signed
motion-scale divisor at 0x1C. The divisor drives the original expression
`1.0f / (divisor / 1000.0f)` in initialization and each model-selection path.
It is not used as a movement height.

The previous declaration extended through 0x2F with unaccessed imported fields.
Those fields have no established EN contract and are removed. The replacement
is explicitly a prefix, with no complete placement-size assertion. Nine
available EN rev1 placements are each 0x24 bytes, independently contradicting
the old 0x30 size; those secondary records do not establish EN v1.0's full size.

## Solution display and symbol ownership

The wall bar finds the same controller object, ID 0x431, as the floor bar.
Its controller export writes nine safe-tile bytes. When the show-solution bit
is clear, the wall bar selects zero instead of the row's copied tile.

| Safe tile | Model bank | Z-rotation behavior |
| --- | --- | --- |
| 0 | 0 | Unchanged |
| 1 | 1 | Reset to zero |
| 2 | 2 | Reset to zero |
| 3 | 2 | Store 0x7FFF unless the current value is 0x3FFF |
| 4 | 1 | Store 0x7FFF unless the current value is 0x3FFF |
| Other | 0 | Reset to zero |

The unequal compare/store constants in cases three and four are directly
present at EN `80206270`/`80206278` and `802062E0`/`802062E8`. They remain
unchanged. Controller invalidation likewise retains the mask 0x40 read from
`anim.flags`, rather than substituting the flag in unrelated object storage.

The receiving array already contains nine entries followed by three natural
alignment bytes. Its old config name, `gChukaModeTable`, is corrected to the
existing source definition `gDFPWallbarSafeFloorTiles` in all four verified
versions. The complete extracted EN relocation scan finds only this owner's
references. The registry now includes the canonical header and casts the
actual 60-byte descriptor at its generic resource boundary.

## Validation

EN text remains `80205F40..80206474`, its 72-byte data section remains
`803299D8..80329A20`, and its 16-byte constant pool remains
`803E63F8..803E6408`. The descriptor starts at `803299E4`; its existing wrapper
and final zero word are preserved. The neighboring torch and floor-bar units
retain their boundaries and generated source paths.

All source objects remain byte-identical in EN, EN rev1, JP and PAL rev1,
including the owner and registry. Fresh objdiff reports retain ten exact
functions, 1332 code bytes and 88 data bytes in this unit. All four full source
builds and the strict EN checksum pass. Formatting is committed separately and
verified to preserve generated output. This is layout and ownership recovery;
no new matching bytes are claimed.
