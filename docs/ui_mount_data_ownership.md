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
| `803DC77C` | Mode 2 local-point radius | 20.0 |
| `803DC780` | Mode 0 segment radius | 0.0 |
| `803DC784` | Mode 0 local-point radii, two floats | 15.0, 15.0 |
| `803DC78C` | Camera local Y offset | 16.0 |
| `803DC790` | Camera local Z offset | -16.0 |
| `803DC794` | Three roll limits | 0x071c, 0x0e38, 0x38e3 |
| `803DC79A` | Default X rotation | 0x4000 |
| `803DC79C` | Heading offset | -0x8000 |

The first two entries were misclassified as three-byte strings by the old symbol
carve. `curves_setSegmentCollision` reads float radii; the local-point setter
stores float-radius pointers and point counts consumed by the collision walker.
Mode 2 supplies two local points but only one radius scalar. The second radius
read crosses into the following mode-0 segment-radius word. The earlier eight-byte
array reconstruction concealed this overread and made mode 0 address an interior
array element, adding an instruction that retail does not contain.

The Dinosaur Planet counterpart, object DLL 714's `dll_714_func_3574`, supplies
independent evidence for these scalar boundaries. Its mode-2 radius is at data
`0x5C`; the next word at `0x60` is also the first component of mode 0's position
vector. Mode 0's segment radius is a separate word at `0x6C`. The same two-radius
request is present there, but the second read crosses into that position vector.
EN's small-data separation places the independent mode-0 radius next to the mode-2
radius instead. Preserve the two-count request and this retail adjacency.

Define `gDRCloudRunnerMode2LocalRadius = 20.0f` and
`gDRCloudRunnerMode0SegmentRadius = 0.0f` separately. The direct EN references at
`802BF1C4` and `802BF270`, the separate donor roles, and the initialized zero at
`803DC780` support these definitions. The TU's `explicit_zero_data on` setting
keeps the explicitly initialized zero in `.sdata`; its genuinely uninitialized
globals remain in their existing `.sbss` slots. GC/1.3 and all optimization and
inlining options are unchanged. No new padding or interior alias is needed.

The flight handler bounds its move index to 0..5 (unrecognized moves use index 4),
then selects one roll limit per pair of moves. Use a three-element `s16` array
indexed by `idx / 2`, replacing byte-offset arithmetic from a scalar declaration.
That expression preserves the exact original function body. Shifting first and
then indexing instead generated an extra shift; it is not retained.

The restored direct scalar address reduces path setup from 512 to the retail
508 bytes. All 36 functions (10,164 bytes) and all 643 assigned data bytes now
match. Every allocated non-code section remains byte-identical, including the
46-byte `.sdata` and twelve-byte `.sbss`; all other named data offsets are
unchanged. Slot 600 is `MatchingFor("GSAE01")` and links from C again.

## Verification

Strict matching checksum and `ninja all_source` both pass with 30-second timeouts.
The strict DOL remains byte-identical with the native CloudRunner object selected.
Objdiff confirms all code and data exact; the linked object inputs independently
confirm the matching-status change. The TU and its owning header pass the formatting
check; running `clang-format -i` produces no source changes.
