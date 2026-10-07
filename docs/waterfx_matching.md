# Water effects (engine DLL 19)

Updated 2026-10-06. All five retail versions match with the existing common
game compiler and TU boundaries. EN's 15 retail functions (6,680 text bytes)
and all 304 assigned data bytes match; the complete source object also retains
the unused helper described below.

## Storage and public contract

The service owns typed circular-ripple, movement-ripple, splash-burst and
splash-drop pools. `WaterfxStorage` accounts for the complete `0x22B0`-byte
allocation: two 60-triangle arrays, two 120-vertex arrays, 30 circular ripples,
10 splash bursts, 30 drops and 30 movement ripples. Capacities come from the
runtime loops; size and offset assertions verify every allocation partition.
The allocation cursor remains byte-addressed, while all persistent pool
pointers and their consumers use the recovered element types.

The old `WaterVtxDesc` was a triangle record, and `WaterVtx` duplicated the
renderer vertex layout. Both now use the canonical `LightmapTriangle` and
`LightmapVertex`. Splash positions are `Vec` records, texture coordinates are
two-float arrays, and each splash owns eight packed RGBA color words. The
color loop directly indexes those words and derives the matrix index from
the band number. The display-list writer likewise derives its matrix index
directly, removing a fake one-element byte array.

Ripple `active` is alpha, `rot`/`sourceId` is yaw, and the movement ripple's
`f18` controls visibility. `spawnCircularRipple` and `spawnMovementRipple`
now distinguish the two effects. Their stored but unread float at `0x0C`
remains unidentified. Dinosaur Planet's `24_waterfx` at
`c4340802dc9f62e1181d00cc34c3175fca6ca4be` corroborates both `0x1C` ripple
records and the allocation scheme; its different splash and particle layouts
are not substituted for SFA's retail-backed layouts.

Object-impact and splash calls use `GameObject*`, impact positions use `Vec*`,
and the resource descriptor embeds the same checked interface used by all
callers. The renderer's two unused legacy display/matrix-list arguments are
no longer misleadingly named as an object or render mode. Shared caller edits
are limited to this contract and the recovered ripple names.

## Splash bands

`waterfx_drawSplashBurst` previously differed in seven floating-point register
operands. Grouping the particle lifetime and derived band phase in a local
record preserves the existing equations and recovers all 166 instructions.
This is transient calculation state, not a claim about an allocated game
object or an original type name. The alpha calculation still reads the
unmodified lifetime after computing the phase and fade.

## Particle traversal

The renderer indexes each pool through its recovered element type. One `void*`
pointer carries the current particle through all four rendering phases;
casts at the accesses identify the ripple, splash, drop, or wake record.
The ripple scan has its own index. Splash, drop, and wake scans share the
second index, including its initialization before splash render-state setup.

Ripple and wake geometry use one triangle index: two triangle descriptors
and four vertices per particle. Typed array expressions replace the explicit
28-, 60-, 32-, and 64-byte induction counters. MWCC generates the retail
walkers, update order, and initial register copies from those expressions.

These lifetimes matter together. Separate typed particle locals leave the
wake pointer and counter swapped; a separate drop counter can reproduce all
register colors but replace a retail copy with a zero load. Splitting the
shared pointer or counter again therefore requires a code-generation check.
All 215 renderer instructions now match. The earlier comma-order experiment
was an incomplete reconstruction, not evidence of an unreachable allocation.

## Validation

- Objdiff: 15/15 functions, 100% code and data.
- Every retail function body is byte-identical; `.sdata2` bytes also agree.
- Common named data symbols retain their retail sections, offsets, and sizes.
  The linker supplies the final one-byte `.data` alignment gap.
- The existing unused `waterfxBandEnvelope` helper remains in the object and
  is discarded by the linker. Its 92 bytes explain the source object's larger
  raw `.text` section; it is not part of the retail function set.
- EN, EN rev1, JP, PAL and PAL rev1 pass `ninja all_source`, strict retail DOL
  equality and complete objdiff inventories with completion metadata removed.
  Every affected TU and every active game TU is exact. The existing TRK vector
  carving and MusyX discarded-data report artifacts are unchanged.
- Across every source object in all five versions, section contents, symbol
  locations and resolved relocations are unchanged after the seven deliberate
  symbol renames. EN retains retail SHA1
  `e750e8e894707a52446118a4b84f1b58b677b269`.
- Formatting is committed separately and checked against the complete object.
