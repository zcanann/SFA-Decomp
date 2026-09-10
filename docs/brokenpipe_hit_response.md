# DLL 688 hit response

The generated `688_BrokenPipe/BrokenPipe.c` path is preserved. Its three EN
functions occupy `80236154..80236298`. The sole data object is the terminal
56-byte descriptor at `8032BCC8`; the 32-byte constant pool is
`803E7338..803E7358`. These boundaries meet the neighboring tree and CmbSrc
units without claiming new gaps.

The TU implements hit responses for a hidden object, not a breaking transition.
Initialization sets `OBJECT_OBJFLAG_HIDDEN`, and the descriptor has no render
callback. `brokenpipe_getExtraSize` returns four bytes, used exclusively as the
priority-hit effect cooldown. The shared helper decrements that cooldown and
resets it to 45 on an eligible hit. Its arguments request eight light-blue
particles (RGB 180, 240, 255) and sound trigger `0x6F`; the sound requires a staff
hit. No independently established trigger name replaces that number.

Initialization reads placement rotation bytes at `0x18..0x1A` and scale at
`0x1B`. The source preserves the nonzero-scale branch, subsequent zero check,
signed hit-sphere radius conversion and model-base-scale multiplication order.
The canonical header exposes `BrokenPipePlacementPrefix`, with offsets asserted
but no invented full EN placement extent or unused trailing array.

EN rev1 and JP each contain 77 DLL 688 placements, all eight words: 40
SnowBoulder, one BrokenPipe, 24 BoulderOne, eight RedBoulder and four Cactus.
These counts come from walking decompressed romlists by their encoded size and
resolving IDs through OBJINDEX and object definitions. They establish secondary
record widths and DLL reuse; local EN placement assets remain unavailable.

All three retail functions have equal normalized instruction signatures across
the four verified EN, EN rev1, JP and PAL rev1 DOLs. Their complete constant
pools are byte-identical. Source recovery and formatting retain exact code,
data and linkage; full source builds and reports are checked for all four
versions, with the strict EN retail checksum as the link gate.
