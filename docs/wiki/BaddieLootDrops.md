# Baddie Loot Drops

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/BaddieLootDrops). Reverse-engineering notes; not independently verified here.

When enemies are defeated, they have a chance to drop a useful item.

There are six tiers of drop, but only three appear to be used:

| Tier | Contents | Notes |
|------|----------|-------|
| 1 | MagicDustSm, MagicDustMi, MagicDustLa, MagicDustHu | used |
| 2 | *(not used)* MagicDustLa, MagicDustHu | second half of the Tier 1 table, also referenced separately |
| 3 | Apple, EnergyEgg | used |
| 4 | *(not used)* Apple, MagicDustSm | |
| 5 | *(not used)* EnergyEgg | |
| 6 | MagicDustMi, ?, EnergyEgg, MagicDustMi, special | used |

Item names:
- **MagicDustSm**: small mana crystal
- **MagicDustMi**: medium mana crystal
- **MagicDustLa**: large mana crystal
- **MagicDustHu**: huge mana crystal
- **Apple**: small health refill (TODO: actual name)
- **EnergyEgg**: large health refill

"Special" is a case where instead of dropping an item, a previous drop is moved? Possibly used
for magic plants to drop their gems?

Each individual enemy has a drop assigned for tiers 1, 3 and 6. In theory this means they can
drop 3 items at once, but there doesn't appear to be any enemy that actually has more than one.

When defeated, the enemy has a 50% chance to drop whatever item is assigned to it. (Note that
this can be, and often is, nothing.)

There's also an unknown condition that overrides the drop type, which seems to be used often.
TODO research this.

## In this codebase

Cross-references verified by reading the source at the paths below. The generic, engine-wide
"per-enemy tier 1/3/6 table + 50% roll" system the wiki describes was **not found** as named
code in this pass — see the dedicated subsection below. What *is* verified is the identity and
mechanics of the individual drop items themselves, plus one concrete per-enemy drop-table
instance (Snowclaw) that implements the same *shape* of mechanic on a smaller scale.

### Tier 1 items — mana dust (MagicDustSm/Mi/La/Hu)

- `src/main/dll/dll_00FF_magicgem.c` is DLL 0x00FF, "magic-gem / collectible objects"
  (`0x80173224`–`0x801732A4` per its header comment; confirmed against
  `config/GSAE01/symbols.txt`: `MagicDust_getExtraSize`/`_free`/`_render`/`_update`/`_init`).
  Its functions are literally named `MagicDust_init`/`_update`/`_render`/`_free`/`_getExtraSize`
  — this is the dust pickup the wiki calls MagicDustSm/Mi/La/Hu.
- State struct: `MagicGemState` in `include/main/dll/magicgemstate_struct.h`. Its `mode` field
  is commented "particle color row" and is set in `MagicDust_init`'s `switch (obj->anim.seqId)`:
  `seqId 0x2c4 -> mode 4`, `0x2cd -> mode 1`, `0x2ce -> mode 2`, default (incl. `0x2cf`) ->
  `mode 6` — each branch also picks its own `ambientEffectId`/`burstEffectId`/`sfxId`. This is
  almost certainly the 4-way Sm/Mi/La/Hu split, but **which seqId is which size is not
  confirmed** (no size-labelled sfx/effect names were found to anchor it) — flagged as an
  opportunity below, not asserted as fact.
- The burst/despawn/pickup state machine (`MAGICGEM_FLAG_BURST1/2`, `_SETTLED`, `_COLLECTED`,
  `_CLAIMED`, `_COLLECT_LATCH` in the same header) is the physical toss-bounce-settle-collect
  animation of a dropped dust crystal.

### Tier 3 items — Apple / EnergyEgg (health refills)

- `src/main/dll/dll_00ED_collectible.c` is DLL 0x00ED, the generic "collectible / genprops"
  pickup handler (`0x80171D14`–`0x801723DC`). Its header comment already documents: "health
  items add health, dust items bump counters" — i.e. this one DLL hosts *both* the Tier 1 dust
  counters and the Tier 3 health pickups, distinguished by `obj->anim.seqId`.
- In `collectible_applyPickup`, the health branch (`switch` on a category read from the
  object's model resource, case `4`) has exactly two cases:
  - `seqId 11` (`0xB`) -> `playerAddHealth(player, 4)` — **the large refill, i.e. EnergyEgg**.
  - `seqId 973` (`0x3CD`) -> `playerAddHealth(player, 2)` — **the small refill, i.e. Apple**.
  This is a live-verified mapping: `include/main/dll/collectible_state.h`'s header comment
  records a Dolphin session that broke a crate, traced object type `0xB`/seqId `11` through
  proximity-detect -> pickup-message -> collect, and watched player health rise 4 -> 8.
- These exact two ids are **independently confirmed** by `src/main/dll/dll_0105_largecrate.c`:
  `largecrate_spawnDropContents`'s `dropType == 5` spawns object id `0xb`, and
  `dropType == 6` spawns object id `0x3cd` — the same two numbers, same two items, from a
  completely different call site (a crate breaking, not an enemy dying), which is why the
  identification is treated as solid here despite `seqId`/"object id" not being formally typed
  anywhere in the codebase yet.
- State/setup structs: `CollectibleState` / `CollectibleSetup` in
  `include/main/dll/collectible_state.h` (per-instance despawn timer, hide/visibility/collect
  gamebits, bounce/path-follow physics).
- Not the same thing: `src/main/dll/dll_0117_appleontree.c` (`AppleOnTree_*`, DLL 0x0117) is a
  *tree-fruit-harvesting* object (an apple you knock down/pick off a tree), a different game
  mechanic from the loose "Apple" collectible dropped as enemy/crate loot. Worth not conflating
  the two despite the shared name.

### Container/enemy "break -> spawn a drop item" pattern

- `src/main/dll/dll_0105_largecrate.c`: `LargeCrateState.dropType`
  (`include/main/dll/largecrate_state.h`) selects between crate debris (`dropType` 1-3),
  the two collectible items above (`dropType` 5/6, via DLL 0x00ED object ids `0xb`/`0x3cd`), a
  no-op break (7/8), and a third pickup kind (`dropType` 9, object id `0x259`, unidentified
  against the wiki's item list). This isn't the *baddie* system the wiki page is about, but it's
  the same "container takes damage -> on death, look up an item id from a small per-instance
  table -> spawn it" shape, and a good model for whoever finds the baddie-side equivalent.
- `src/main/snowclaw.c`: `SnowclawState.dropIndex` (an `init[0x27]` placement byte) indexes a
  small per-species table, `extern SnowClawAnimTbl gSnowClawDropObjectTable;` (this codebase
  types `SnowClawAnimTbl` as `{ s16 v[5]; }`, i.e. 10 bytes; `config/GSAE01/symbols.txt` records
  the retail symbol itself as `.rodata:0x802C2540 size:0x10` — the 6-byte discrepancy against
  the current typing wasn't resolved in this pass), to pick a spawn-object id for a child object
  attached to the Snowclaw (see `dropTable.v[dropIndex]` in the update function, and the
  mirrored lookup against `gSnowClawDropObjectTable` a second time later in the same file). The
  table's actual byte contents aren't defined in source yet (only `extern`-declared), so its
  item ids are unread here. This is the closest concrete in-repo analogue to "each enemy has a
  drop assigned," scoped to one enemy species rather than the generic engine table the wiki
  describes.

### "Special" (moving a previous drop)

- `src/main/dll/dll_00FE_magicplant.c` (`MagicPlant_*`) + `src/main/dll/dll_00FD.c`
  (`magicPlantDropGem`): a magic plant already owns a child gem object
  (`state->childObj`, in `MagicPlantBridgeState`) attached at spawn time. On being hit
  (`MAGICPLANT_MODE_HIT_REACT`), `magicPlantDropGem` **detaches and launches the existing child**
  rather than allocating a new object — exactly the "instead of dropping an item, a previous
  drop is moved" mechanic the wiki speculates about for tier 6's "special" entry. This is a
  magic plant, not a generic baddie, so it's supporting evidence for the *mechanism*, not
  confirmation that this is literally what tier 6 does.

### The generic per-baddie tier-table + 50%-roll system — not found

- `include/main/dll/baddie_state.h` (`BaddieState`/`GroundBaddieState`) is this codebase's
  matched engine-wide actor-control record for baddies (shared with the player). It has no
  named fields resembling a 3-slot drop-item table or a drop-chance roll; its documented
  per-baddie config tail (`triggerId`, `soundIdA`/`soundIdB`, `aggroRange`, `aggression`) is all
  audio/AI config, not loot.
- `include/main/dll/baddieControl.h` — the `gBaddieControlInterface` vtable's ~90 entries
  (`0x8010dedc`-`0x801127c4`) are still raw `FUN_8010xxxx` prototypes, undecompiled. Given that
  `BaddieState`/`GroundBaddieState`'s own comments say "the engine-side writers (the interface
  implementations) own most of the unobserved head," this is the most likely home for the
  generic tier1/3/6-drop-assignment + 50%-chance-on-defeat logic the wiki describes. No hex
  literal `50` (or `randomGetRange(0, 1)`/`randomGetRange(0, 100)`) tied to a defeat/hitPoints
  check was found anywhere in the already-matched `src/main/dll/*.c` baddie files searched.
- `include/main/dll/enemy_state.h` (`EnemyState`, the `enemy_*`/`projswitch.c` family's extra
  record) likewise has `health`/`current`/`max` fields but nothing resembling a drop table.

## Ready-to-adopt code

The wiki page itself gives no numeric ids/offsets to lift (it's design-level prose, not a data
table). The candidates below come from **this pass's own code reading**, not from the wiki, and
are offered so a maintainer can turn magic numbers already in the tree into named constants
where the identification is solid.

```c
/* dll_00ED_collectible.c / dll_0105_largecrate.c — pickup "object id" (obj->anim.seqId),
 * live-verified (collectible_state.h) and cross-confirmed by largecrate_spawnDropContents
 * dropType 5/6 spawning the same two ids. Wiki: BaddieLootDrops tier 3. */
#define COLLECTIBLE_ITEM_ENERGY_EGG 0xB   /* +4 health (large refill) */
#define COLLECTIBLE_ITEM_APPLE      0x3CD /* +2 health (small refill) */
```

```c
/* largecrate_state.h LargeCrateState.dropType values, from largecrate_spawnDropContents'
 * switch (src/main/dll/dll_0105_largecrate.c). Not a wiki table -- named here for reference
 * since the switch itself has no symbolic constants yet. */
#define LARGECRATE_DROP_FRAGMENT_A   1   /* obj id 0x3d3, launched crate debris */
#define LARGECRATE_DROP_FRAGMENT_B   2   /* obj id 0x3d4 */
#define LARGECRATE_DROP_FRAGMENT_C   3   /* obj id 0x3d5 */
#define LARGECRATE_DROP_GAS_A        5   /* obj id 0xb   == COLLECTIBLE_ITEM_ENERGY_EGG */
#define LARGECRATE_DROP_GAS_B        6   /* obj id 0x3cd == COLLECTIBLE_ITEM_APPLE */
#define LARGECRATE_DROP_NONE_A       7
#define LARGECRATE_DROP_NONE_B       8
#define LARGECRATE_DROP_PICKUP       9   /* obj id 0x259, unidentified against the wiki's list */
```

Not proposed: a Sm/Mi/La/Hu enum for `MagicDust_init`'s four `seqId` branches (`0x2c4`/`0x2cd`/
`0x2ce`/`0x2cf`) — the branches are clearly four distinct dust variants (confirmed structurally),
but which seqId is Small vs. Huge isn't pinned down by anything read in this pass, so naming them
now would risk asserting a wrong size order into a header.
