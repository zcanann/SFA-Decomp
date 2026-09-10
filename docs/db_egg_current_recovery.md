# DB egg and river-current recovery

The helper at EN `801FE774` (612 bytes), formerly named
`dbegg_computeFlocking`, consumes object group `0x14`. The identified producer
of that group is slot 372, `CCriverflow`; eggs register in group `0x24`.
The helper is therefore named `dbegg_computeWaterCurrent`.

The current-source placement byte at `+0x19` supplies the planar radius to the
egg, player and WaterFlowWe. Slot 372 also adds that byte divided by 512 to
`rootMotionScale`. Byte `+0x1A` holds flags: initialization expands zero to
`0xFF`, and player/WaterFlowWe test bit `0x02`. The egg deliberately has no such
test. These fields, the group and the shared flag now have one definition in
`372_CCriverflow.h`; the obsolete `FoliageCurrentSetup` overlay is removed.

The egg still uses a seven-unit vertical band, a radius of 1.5 times the source
byte, linear distance attenuation, and direction from the source rotation.
Its existing averaging, damping and clamps are preserved. No common helper
was extracted from consumers with different behavior.

Egg state flags now describe their observed pickup, curve activation, landing
and group-membership effects. The pickup message `0x7000A` passes an eight-byte
payload beginning at state `+0x11C`. The player interprets its first halfword
as a game-bit gate; `-1` bypasses it. The following halfword and float retain
cautious names because their downstream meanings remain unresolved.

The state allocation establishes `sizeof(DbEggState) == 0x124`. In contrast,
the old placement `sizeof == 0x30` assertion came from an imported layout,
without a proven EN allocation or serialized extent. `DbEggPlacementPrefix`
now describes only evidenced readers through the halfword at `+0x2C` and must
not determine allocation or copy sizes. The falsely attributed current radius
is removed from this egg view. Unaccessed imported fields become opaque spans.

The egg group definition is shared with slots 578 and 579. Their edits, and
those in the player and WaterFlowWe, are limited to the relevant includes,
types, constants and comments. DLL paths, split boundaries, compiler profiles,
descriptor position and constant-pool ownership are unchanged.

## Validation

All 15 egg functions occupy EN `801FE118..801FF884`; its data occupies
`803292B8..8032933C`, with the 172-byte constant pool at
`803E61C0..803E626C`. The descriptor retains its proven earlier position,
followed by the diagnostic and jump-table data.

The 15 egg functions and five current-source/consumer functions have equal
normalized instruction signatures across the checksum-verified EN, EN rev1,
JP and PAL rev1 DOLs. The egg's 172-byte constant pool is byte-identical across
those versions. This supports the shared recovery; normalized signatures alone
do not establish byte identity or original source names.

Direct compilation preserves every allocated section, function body, named
symbol offset and relocation in all six affected EN objects, allowing only the
helper rename. The five shared objects are raw-identical. Restoring the old
helper name in a scratch control restores the entire egg object byte-for-byte
(SHA-256 `5c6f3abe21e5f67e826c7524e84916ce6c54d0b46bc4185e553d30a935a13cc9`).

The helper name is synchronized in all five symbol configs. PAL rev0 receives
only symbol consistency: the local artifact does not satisfy that version's
configured checksum and is not used to claim validation.

Full `all_source` builds pass for EN, EN rev1, JP and PAL rev1. Complete objdiff
reports remain identical after normalizing only the helper rename: all 15 egg
functions, 5,996 code bytes and 304 data bytes remain exact in each version.
Every other source object is raw-identical (990 EN objects and 987 in each
secondary version). The strict EN matching link also passes its retail checksum.
