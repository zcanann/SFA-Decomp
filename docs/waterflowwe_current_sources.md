# WaterFlowWe current sources

Slot 686's current sampler at EN `8023503C` reads two distinct object groups.
Group `0x14` is the CCRiverFlow source recovered with DB egg. Group `0x50`
is registered by `iceBaddie_enterWhirlpoolGroup`, reached through the
`ENEMY_WHIRLPOOL_OBJ` (`0x851`) cases in slot 201's enemy state machine.
The matching leave helper and the enemy's free path remove that registration.
The helper lives in slot 202's existing support source; this does not transfer
ownership of the enemy placement to slot 202 or 686.

Both the player and WaterFlowWe read enemy placement byte `+0x29` as a
whirlpool radius in eight-unit cells, and byte `+0x32` as current strength in
tenths. Generic enemy consumers use those same unsigned bytes as aggro radius
and hit points. Explicit union views in `EnemyPlacement` preserve both roles
without a second padded `ObjectCurrentSourceSetup` overlay. The group ID is
shared through the enemy's canonical header.

WaterFlowWe applies the existing vertical band, planar falloff and angle offset
independently for each source family. Its `hasCurrent` local is a boolean set
to one, not a count: division by that value does not average multiple sources.
The source contributions are summed, then filtered and clamped. If no source
is enabled, the function outputs zero without clearing its persistent filter
state.

The retail update at `802354CC` advances two shared phase accumulators. Both
animation branches load `gWaterFlowIdlePhase` (`803DDDB0`), despite advancing
`gWaterFlowFlowPhase` (`803DDDAC`) at a different rate. The latter has no
recovered animation consumer. Preserve this behavior and declaration order;
using the faster phase for the moving animation would change the game.

The ten WaterFlowWe functions and four current owner/consumer functions have
equal normalized instruction signatures across checksum-verified EN, EN rev1,
JP and PAL rev1 DOLs. WaterFlowWe's 72-byte constant pool is byte-identical in
those versions. No new split, filename, compiler-profile or constant-pool
ownership claim is needed for this recovery.

## Owning layouts and validation

`waterflowwe_getExtraSize` establishes an eight-byte state: two filtered current
components at offsets zero and four. `686_WaterFlowWe.h` now owns that state,
the placement reader, public API and `ObjectDescriptor` declaration. The
registry uses that declaration and casts only at its generic resource boundary.
The descriptor remains at the end of the TU; callbacks with exact matching
prototypes use function designators directly.

EN rev1 and JP each map WaterFlowWe object `0x868` to definition `0x28E`,
DLL 686, class `0x7F`. Their 100 placements across five romlists each have eight
words. Whirlpool object `0x851` maps to definition `0x37`, DLL 201, class `0x1C`;
their 22 placements each have fourteen words. These are secondary-version
cross-checks. Without EN placement assets, `WaterFlowWePlacementPrefix` keeps
only reader-backed offsets through `+0x1F`, without asserting a complete EN
serialized size. EnemyPlacement retains its independently allocation-backed
`0x38` size.

Direct EN compilation preserves all 37 affected objects byte-for-byte, covering
all compiled consumers of the shared enemy header, WaterFlowWe and the registry.
WaterFlowWe retains ten functions, 1,680 code bytes, the 56-byte descriptor,
three four-byte small-BSS globals and the complete 72-byte constant pool.

Full source builds pass for EN, EN rev1, JP and PAL rev1. All source objects
remain raw-identical (991 in EN, 988 in each secondary version), and complete
objdiff reports remain unchanged. WaterFlowWe remains 100% matched for code
and data. The strict EN matching link passes the retail checksum. This is
shared source and layout recovery, with no increase in match scores.
