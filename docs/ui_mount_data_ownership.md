# UI state and mounted-creature tuning storage

Target: EN v1.0, GC/1.3 game compiler with existing per-unit flags.

## Pause-menu map cell

All references to `gPauseMenuPlayerMapCell` belong to engine slot 0. The map
page writes the player cell, applies map-act/group remaps, and compares or
indexes the resulting cell while displaying the current task and player marker.
The retail word at `803DD8E0` immediately follows this unit's saved text-directory
word. Define the cell alongside those native UI globals and correct its symbol
size from eight to four bytes. The existing `.sbss` grows from 440 to 444 bytes;
eight-byte section alignment supplies the remaining four bytes before engine 59.
Existing symbol offsets, function bodies, and other data are unchanged. This
adds eight matched data bytes; engine 0 remains nonmatching and uses retail code
and data in the strict link.

## EarthWarrior exhausted speed

When the mounted warrior's energy reaches zero, its idle handler sets `maxSpeed`
from the float at `803DC76C`, then starts camera shake and damages the player.
Define `gDREarthWarriorExhaustedSpeed = 3.0f` after the tail-chain data. The native
`.sdata` extends from twelve to sixteen bytes with unchanged existing symbols
and function bodies. All 32 functions remain exact, and four new data bytes
match and link from C.

## CloudRunner radii and camera settings

The following block, `803DC770..803DC79E`, is owned entirely by object slot 600.
It follows EarthWarrior in both text and small data. Native initializers reproduce
all 46 bytes without padding objects or section-placement overrides.

| Address | Definition / use | Value |
| --- | --- | --- |
| `803DC770` | Mode 1 segment radius | 40.0 |
| `803DC774` | Mode 1 local-point radius | 40.0 |
| `803DC778` | Mode 2 segment radius | 20.0 |
| `803DC77C` | Mode 2 local-point radii, two floats | 20.0, 0.0 |
| `803DC784` | Mode 0 local-point radii, two floats | 15.0, 15.0 |
| `803DC78C` | Camera local Y offset | 16.0 |
| `803DC790` | Camera local Z offset | -16.0 |
| `803DC794` | Three roll limits | 0x071c, 0x0e38, 0x38e3 |
| `803DC79A` | Default X rotation | 0x4000 |
| `803DC79C` | Heading offset | -0x8000 |

The first two entries were misclassified as three-byte strings by the old symbol
carve. `curves_setSegmentCollision` reads float radii; the local-point setter
stores float-radius pointers and point counts consumed by the collision walker.
Mode 2 supplies two local points, proving the eight-byte radius span starting at
`803DC77C`. Mode 0's segment setup uses the zero second element at `803DC780`;
remove that interior standalone symbol and express the shared element directly.
The former integer extern declarations did not describe these floating values.

The flight handler bounds its move index to 0..5 (unrecognized moves use index 4),
then selects one roll limit per pair of moves. Use a three-element `s16` array
indexed by `idx / 2`, replacing byte-offset arithmetic from a scalar declaration.
That expression preserves the exact original function body. Shifting first and
then indexing instead generated an extra shift; it is not retained.

The path setup's address of the shared zero entry introduces one `addi` under
the existing compiler settings. Setup grows from 508 to 512 bytes; the other 35
functions retain their exact bodies, and the other data allocations are unchanged.
The unit is now `NonMatching`: exact code falls by 508 bytes and all 10,164 retail
code bytes stop linking from C, while 46 new data bytes match. Its 597 previously
linked data bytes also fall back to retail. This is the explicit cost of recovering
the complete native radius storage instead of unresolved interior aliases.
A separate zero-valued float was tested and emitted `.sbss`, contradicting the
retail placement; scalar definitions do not establish the correct layout.

## Verification

Strict matching checksum and `ninja all_source` both pass with 30-second timeouts.
The strict DOL remains byte-identical, using the retail CloudRunner object after
the matching-status change. Object comparison verifies every unaffected function,
existing allocated data section, and named storage offset. Total matched data
increases by 58 bytes, including UI alignment. Formatting is committed separately
and checked to preserve the complete generated objects.
