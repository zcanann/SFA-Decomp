# Shop

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Shop). Reverse-engineering notes; not independently verified here.

The ThornTail Shop has several items for sale, including a few unused ones and many deleted entries.

* `No`: List index
* `P$`: Normal price
* `D1`, `D2`, `D3`: Discounted price
* `aval`: GameBit (see `include/main/gamebits.h`'s `enum GameBitId`) that must be set for the item to be available
    * `0x0095` is always set; `0x0096` is never set.
* `bght`: GameBit that tells whether you've already bought the item. This is `0xFFFF` for
  consumable items that can be bought more than once.
* `text`: Which text shows when you stand near the item. Add `0x2710` to get the
  [GameText](Gametext.md) ID.

Omitted entries all have `P$,D1,D2,D3=0` and `aval,bght,text=FFFF`.

| No | P$  | D1  | D2  | D3  | aval | bght | text | item |
|----|-----|-----|-----|-----|------|------|------|------|
| 00 |   3 |   2 |   2 |   3 | 0095 | ffff | 003f | DumbleDang Pod (1/2 heart) |
| 01 |  10 |   7 |   8 |  10 | 0095 | ffff | 0040 | 4x DumbleDang Pod (2 hearts) |
| 02 |   6 |   4 |   5 |   6 | 0095 | ffff | 0041 | PukPuk Egg (1 heart) |
| 03 |  15 |  10 |  12 |  15 | 0095 | ffff | 0042 | 7x PukPuk Eggs (7 hearts) |
| 04 |   5 |   3 |   4 |   5 | 0095 | ffff | 0043 | Bomb Spore |
| 05 |  30 |  25 |  27 |  30 | 0095 | ffff | 0044 | Moon Seed |
| 06 |  12 |  11 |  11 |  12 | 0095 | ffff | 0045 | GrubTub Fungus |
| 07 |  10 |   7 |   8 |  10 | 0095 | ffff | 0046 | Firefly |
| 08 |  10 |   7 |   8 |  10 | 0095 | ffff | 0047 | Fuel Cell |
| 14 |  15 |  10 |  12 |  15 | 0095 | 0025 | 0053 | Tricky's Ball |
| 15 |  20 |  15 |  18 |  20 | 0095 | 013e | 0048 | Firefly Lantern |
| 16 | 130 | 110 | 120 | 130 | 0095 | 01a2 | 0049 | SnowHorn Artifact |
| 17 |  20 |  15 |  17 |  20 | 0095 | 0eb2 | 004b | Bafomdad Holder |
| 18 |  50 |  45 |  47 |  50 | 0096 | 0eb0 | 004c | Bad Guy Alert (unused) |
| 19 |  10 |   8 |   9 |  10 | 0095 | 0c7c | 0052 | Rock Candy |
| 1A |  22 |  18 |  20 |  22 | 0095 | 0c8d | 004c | PDA (unused) |
| 1B |  20 |  17 |  18 |  20 | 0095 | 0c64 | 000f | Viewfinder |
| 28 |   5 |   3 |   4 |   5 | 0095 | 059e | 004d | DarkIce Mines Map |
| 29 |   5 |   3 |   4 |   5 | 0095 | 082f | 004e | Cape Claw Map |
| 2A |   5 |   3 |   4 |   5 | 0095 | 05a3 | 0050 | ThornTail Hollow Map |
| 2B |   5 |   3 |   4 |   5 | 0095 | 0835 | 004f | Moon Pass Map |
| 2C |   5 |   3 |   4 |   5 | 0095 | 082e | 0051 | Walled City Map |
| 2D |   5 |   3 |   4 |   5 | 0095 | 05a1 | 0054 | CloudRunner Fortress Map |
| 2E |   5 |   3 |   4 |   5 | 0095 | 05a2 | 0055 | LightFoot Village Map |
| 2F |   5 |   3 |   4 |   5 | 0095 | 07dd | 013b | Dragon Rock Map |
| 30 |   5 |   3 |   4 |   5 | 0095 | 07e5 | 013c | Krazoa Palace Map |
| 31 |  10 |   7 |   8 |  10 | 0095 | 07e9 | 013d | Ocean Force Point Map |
| 32 |   5 |   3 |   4 |   5 | 0095 | 05a0 | 013e | SnowHorn Wastes Map |
| 33 |  10 |   7 |   8 |  10 | 0095 | 059d | 013f | Volcano Force Point Map |

The last entry is `0x3B`.

## Discounts

When you enter the shop, the ShopKeeper decides on a minimum price for each item by randomly
choosing either D1, D2 or D3 (which is always the same as the normal price).

## Unused Items

* Item `0x18` is labelled "Bad Guy Alert", and is set to never be available (GameBit `0x0096` is
  always zero). A description in the unused `GAMETEXT.bin` suggests this would make the staff glow
  red when enemies are nearby. (The code responsible for making the staff glow does not appear to
  have red as one of the available colors.)
* Item `0x1A` is Fox's PDA (the map/fuel cell scanner/info box on the HUD). This is set to be
  available if you don't have the PDA, which is normally impossible as Fox starts with it and
  never loses it. (This also raises the question of how you'd see the item name without it.) It
  has the same text ID as Bad Guy Alert.
* Even if you set the appropriate GameBits to make these items available, they're nowhere to be
  found inside the shop.
* The PDA does have an object, `SPPda`, but it just appears as a placeholder cube, with no
  interaction.
* The fuel cell is called `SPReplayDis`. Unused `GAMETEXT.bin` suggests there was once a way to
  replay boss fights; this could be related?

## In this codebase

The shop is implemented by three DLLs (per this repo's own [DLLs](DLLs.md) /
[Objects](Objects.md) id lists, which independently name the same three: `0x284 ShopItem`,
`0x285 Shop`/`SPShop`, `0x286 ShopKeeper`/`SPShopKeeper`):

| DLL id | wiki role | this repo |
|--------|-----------|-----------|
| `0x284` | shop item pickup/model | `src/main/dll/dll_0284_shopitem.c`, `include/main/dll/dll_0284_shopitem.h` — `shopitem_*` symbols |
| `0x285` | the shop stall / item-table manager | `src/main/dll/SP/dll_0285_spshop.c` — `shop_*` symbols |
| `0x286` | the ShopKeeper NPC | `src/main/dll/SP/dll_0286_spshopkeeper.c`, `include/main/dll/shopkeeperstate_struct.h` — `ShopKeeper_*` symbols |
| `0x287` | scarab coins the ShopKeeper scatters on purchase (`OBJTYPE_SPSCARAB` = 1151) | `src/main/dll/SP/dll_0287_spscarab.c` |

`docs/wiki/DLLs.md` (`| 284 | ShopItem |`, `| 285 | Shop |`, `| 286 | ShopKeeper |`, `| 287 |
SPScarab |`) and `docs/wiki/Objects.md`'s DLL-name table (`006E|SPShop`, `006F|SPShopKeeper`,
`0070|ShopItem`) independently name the same four objects, confirming the id/name pairing above.

### The item table itself — verified 1:1 with the wiki's columns

`0x285`'s `shop_*` functions read a flat data table, `lbl_80327FD0` (`config/GSAE01/symbols.txt`:
`.data:0x80327FD0`, size `0x2D0`), typed in this repo as:

```c
typedef struct ShopItemRow
{
    u8 price;      /* 0x0  == wiki "P$" */
    u8 pad1[0x4 - 0x1]; /* 0x1..0x3 == wiki "D1","D2","D3" (currently unnamed padding) */
    u8 field4;     /* 0x4  -- not one of the wiki's columns, see note below */
    u8 minPrice;   /* 0x5  -- the runtime-computed discount, not a static wiki column */
    s16 availBit;  /* 0x6  == wiki "aval" */
    s16 boughtBit; /* 0x8  == wiki "bght" */
    s16 textId;    /* 0xa  == wiki "text" */
} ShopItemRow; /* sizeof 0xc */

#define SHOP_ITEM_ROW_COUNT 0x3c   /* 0x2D0 / sizeof(ShopItemRow) == 60 == matches wiki "last entry is 0x3B" */
```

- `0x2D0 / 0xc == 0x3C` (60) rows, index range `0x00..0x3B` — **exactly** matches the wiki's "the
  last entry is `0x3B`" and its list of omitted/all-zero entries.
- `shop_isItemAvailable`/`shop_isItemBought` treat `availBit`/`boughtBit == -1` as "always
  available" / "no bought-bit, i.e. repeatable consumable" — independently arrived at in this
  repo's own field comments, and it exactly matches the wiki's "Omitted entries ... aval,bght,text
  = FFFF" and "bght is 0xFFFF for consumable items that can be bought more than once."
- **Discounts, confirmed live in code**: `shop_init`'s body (`shop_initBody`) does
  `item[5] = item[randomGetRange(0, 2) + 1]` for every row on shop entry — i.e. `minPrice` (offset
  `0x5`) is set to a random pick of `item[1]`/`item[2]`/`item[3]` (D1/D2/D3). This is the wiki's
  "Discounts" section verbatim: "the ShopKeeper decides on a minimum price for each item by
  randomly choosing either D1, D2 or D3."
- **Not accounted for by the wiki's column list**: `field4` at offset `0x4`. The wiki's row schema
  (`P$,D1,D2,D3,aval,bght,text`) only explains 10 of the row's 12 bytes; this repo's struct layout
  (forced by the accessor functions' concrete byte offsets) leaves one byte, `field4`, with no wiki
  counterpart. `shop_getItemField4` reads it but nothing in this pass traces what consumes its
  return value — left unnamed/undetermined here rather than guessed.

### `shop_buyItem`'s switch cases are literally the wiki's "No" column

`shop_buyItem` (`src/main/dll/SP/dll_0285_spshop.c`) switches on `itemIndex` (the row's `No`) to
apply each item's purchase effect, and the case values match the wiki table row-for-row:

| `itemIndex` (switch case) | effect in this repo | wiki row `No` / item |
|---|---|---|
| `0` | `playerAddHealth(player, 2)` | `00` DumbleDang Pod (1/2 heart) |
| `1` | `playerAddHealth(player, 8)` | `01` 4x DumbleDang Pod (2 hearts) |
| `2` | `playerAddHealth(player, 4)` | `02` PukPuk Egg (1 heart) |
| `3` | `playerAddHealth(player, 0x1c)` (28) | `03` 7x PukPuk Eggs (7 hearts) |
| `4` | `gameBitIncrement(0x66c)` | `04` Bomb Spore |
| `5` | `gameBitIncrement(0x86a)` | `05` Moon Seed |
| `6` | `gameBitIncrement(0xc1)` | `06` GrubTub Fungus |
| `7` | `gameBitIncrement(0x13d)`, `gameBitIncrement(0x5d6)` | `07` Firefly |
| `8` | `gameBitIncrement(0x3f5)` | `08` Fuel Cell |
| `0x17` | `*(u8*)(mapEventState + 0xa) = 10` | `17` Bafomdad Holder |

The health values line up with the wiki's parenthetical heart counts (2 health units == 1/2 heart
in this engine's scale, so `2`/`8`/`4`/`28` == 1/2, 2, 1, 7 hearts for rows `00`-`03`). The
`gameBitIncrement` targets (`0x66c`, `0x86a`, `0xc1`, `0x13d`/`0x5d6`, `0x3f5`) are almost certainly
the consumable-count GameBits for Bomb Spore/Moon Seed/GrubTub Fungus/Firefly/Fuel Cell, but none
of them are traced to a confirmed consumer in this pass, so they are **not** added to
`include/main/gamebits.h` yet (its own header policy is to only name a bit once its meaning is
established, not just guessed from row order).

### `aval`/`bght` GameBits — already named in this codebase, independently, and they match

`include/main/gamebits.h` already carries symbolic names for essentially every `aval`/`bght` id in
the wiki's table, added independently of this wiki page and cross-checked here by raw value:

| wiki id | wiki column/row | `include/main/gamebits.h` |
|---|---|---|
| `0x0095` | `aval` (always set) | `GAMEBIT_Always1` — comment: *"table 0; used for always-available shop items"* |
| `0x0096` | `aval` (never set, row `18`) | `GAMEBIT_Always0` — comment: *"table 0; used for never-available (unused) shop items"* |
| `0x0025` | `bght` row `14` Tricky's Ball | `GAMEBIT_ITEM_TrickyBall_Bought` |
| `0x013E` | `bght` row `15` Firefly Lantern | `GAMEBIT_ITEM_FireflyLantern_Got` |
| `0x01A2` | `bght` row `16` SnowHorn Artifact | `GAMEBIT_ITEM_NWSnowHornArtifact_Got` |
| `0x0EB2` | `bght` row `17` Bafomdad Holder | `GAMEBIT_ITEM_BafomdadHolder_Got` |
| `0x0EB0` | `bght` row `18` Bad Guy Alert (unused) | `GAMEBIT_ITEM_BadGuyAlert_Got` — comment: *"unused shop item"* |
| `0x0C7C` | `bght` row `19` Rock Candy | `GAMEBIT_ITEM_RockCandy_Got` |
| `0x0C8D` | `bght` row `1A` PDA (unused) | `GAMEBIT_ITEM_PDA_Got` — comment: *"Set when landing at TTH"* |
| `0x0C64` | `bght` row `1B` Viewfinder | `GAMEBIT_ITEM_Viewfinder_Got` |
| `0x059E` | `bght` row `28` DarkIce Mines Map | `GAMEBIT_ITEM_MapDIM_Got` — comment: *"Have DarkIce Mines Map"* |
| `0x082F` | `bght` row `29` Cape Claw Map | `GAMEBIT_ITEM_MapCC_Got` |
| `0x05A3` | `bght` row `2A` ThornTail Hollow Map | `GAMEBIT_ITEM_MapSH_Got` — comment: *"Have ThornTail Hollow Map"* |
| `0x0835` | `bght` row `2B` Moon Pass Map | `GAMEBIT_ITEM_MapMMP_Got` |
| `0x082E` | `bght` row `2C` Walled City Map | `GAMEBIT_ITEM_MapWC_Got` |
| `0x05A1` | `bght` row `2D` CloudRunner Fortress Map | `GAMEBIT_ITEM_MapCF_Got` — comment: *"Have CloudRunner Fortress Map"* |
| `0x05A2` | `bght` row `2E` LightFoot Village Map | `GAMEBIT_ITEM_MapLV_Got` — comment: *"Have LightFoot Village Map"* |
| `0x07DD` | `bght` row `2F` Dragon Rock Map | `GAMEBIT_ITEM_MapDR_Got` |
| `0x07E5` | `bght` row `30` Krazoa Palace Map | `GAMEBIT_ITEM_MapWM_Got` |
| `0x07E9` | `bght` row `31` Ocean Force Point Map | `GAMEBIT_ITEM_MapOFP_Got` |
| `0x05A0` | `bght` row `32` SnowHorn Wastes Map | `GAMEBIT_ITEM_MapNW_Got` — comment: *"Have SnowHorn Wastes Map"* |
| `0x059D` | `bght` row `33` Volcano Force Point Map | `GAMEBIT_ITEM_MapVFP_Got` — comment: *"Have Volcano Force Point Map"* |

(The internal `Map*` abbreviations resolve against this repo's own [Objects](Objects.md)
"Object Names" prefix legend: `SH` = ThornTail Hollow, `MMP` = Moon Mountain Pass, `WC` = Walled
City, `CF` = CloudRunner Fortress, `DR` = DragonRock, `OFP` = Ocean Force Point, `NW` = SnowHorn
Wastes, `WM` = Krazoa Palace ("internally 'Warlock', was once called Warlock Mountain" — resolving
the wiki's own "Krazoa Palace Map" text label to a GameBit name that doesn't look like it at first
glance), `CC` = Cape Claw, `DIM` = DarkIce Mines, `VFP` = Volcano Force Point. One exception:
`GAMEBIT_ITEM_MapLV_Got` uses `LV`, but the same legend gives Lightfoot Village's prefix as `LF` —
that one mismatch is called out here rather than papered over.)

Other shop-related GameBits used directly in `dll_0285_spshop.c` and already named in
`gamebits.h`, confirmed by literal id:

- `mainSetBits(0xefe, 1)` in `shop_initBody` / `mainSetBits(3838, 0)` (`0xefe` in decimal) in
  `shop_free` -> `GAMEBIT_PlayerInShop = 0xEFE`.
- `mainGetBit(0xd21)` in `shop_update` (gates an env-fx toggle) -> `GAMEBIT_SHOP_Unk0D21`, already
  commented *"set when entering shop"*.
- `mainSetBits(0x617, 1)` in `shop_update` -> `GAMEBIT_SHOP_Unk0617`, already commented *"set when
  entering shop"*.
- `mainGetBit(0x18b)` in `shop_update` (staff-glow toggle gate) -> `GAMEBIT_STAFF_ACQUIRED`,
  documented as the Krazoa Staff pickup latch (unrelated to the shop item table, just a shared
  precondition check in the same function).

### GameText id offset

The wiki's "Add `0x2710` to get the GameText ID" matches this repo's own [Gametext](Gametext.md)
notes independently: GameText ids `10000-19999` (`0x2710-0x4E1F`) are documented there as
"Descriptions shown in pause menu or PDA" — the shop's per-item hover text falls in exactly that
range once the `0x2710` offset is added (e.g. row `00`'s `text = 0x003f` -> GameText id
`0x274F` = 10063).

### Unused items — partially found, mostly not

- **`SPPda` / `SPReplayDis` (the wiki's names for the unused PDA/fuel-cell placeholder objects):
  not found.** A case-insensitive search of `src/`, `include/`, and `config/GSAE01/symbols.txt`
  turns up no `SPPda` or `SPReplayDis` symbol; these were apparently stripped from (or never
  reached) the retail symbol table this repo's tooling recovers from.
- The **world pickup objects that give the shop items their names** are present under unrelated
  DLL numbers (separate systems from the `0x284/0x285/0x286` shop trio above — noted here only as
  a bonus cross-reference, not as part of the shop item-table system):
  - "Firefly Lantern" (row `15`): `FireFlyLantern_spawnFireFly` symbol exists
    (`.text:0x801871C8`) and is implemented at `src/main/dll/dll_010B_fireflylantern.c` (DLL
    `0x10B`) — a different object from the shop stall's `ShopItem`/`0x284`.
  - "Fuel Cell": `gFuelCellObjDescriptor` (`.data:0x80321DE8`) is defined in
    `src/main/dll/CC/dll_0122_cctestinfot.c` as a raw `u32[14]` descriptor array (not yet given a
    typed `ObjectDescriptor*` cast) referencing `FuelCell_init/_update/_render/_free/_getExtraSize`
    — those four/five function bodies were not located as decompiled source in this pass (symbol
    table only, per `config/GSAE01/symbols.txt`).
  - "DumbleDang"/"PukPuk"/"GrubTub"/"Bomb Spore"/"Moon Seed"/"Bafomdad"/"Rock Candy" as *named
    objects*: not found as such; the closest is `MoonSeedBush`/`MoonSeedPlantingSpot`
    (`config/GSAE01/symbols.txt`, `.text:0x801A6C28` on) which look like the growable-plant system
    the seed item plants, not the shop pickup itself — flagged as a plausible but unconfirmed link.
- The "make the staff glow red" unused-feature claim and the "GAMETEXT.bin suggests a boss-replay
  feature" claim are both about *deleted content* the wiki infers from unused string/id data; this
  pass did not attempt to re-derive those from `GAMETEXT.bin` — see [Gametext](Gametext.md) for
  what this repo has recovered from that file generally.

## Ready-to-adopt code

`shop_buyItem`'s switch (see table above) and the `ShopItemRow` accessors currently index by raw
row number. The wiki's `No`/`item` columns give a complete, verified id-to-name list for the rows
that matter to that switch (and to any future work reading the same table), so a maintainer could
lift this directly:

```c
/* Shop item-table row indices ("No" column) into lbl_80327FD0 / ShopItemRow.
 * Only the rows referenced by shop_buyItem's switch and the wiki's non-omitted
 * rows are named; unlisted indices in [0, SHOP_ITEM_ROW_COUNT) are omitted/unused
 * rows (P$,D1,D2,D3 == 0, aval,bght,text == FFFF). */
enum ShopItemIndex
{
    SHOP_ITEM_DUMBLEDANG_POD        = 0x00, /* 1/2 heart */
    SHOP_ITEM_DUMBLEDANG_POD_4X     = 0x01, /* 2 hearts */
    SHOP_ITEM_PUKPUK_EGG            = 0x02, /* 1 heart */
    SHOP_ITEM_PUKPUK_EGGS_7X        = 0x03, /* 7 hearts */
    SHOP_ITEM_BOMB_SPORE            = 0x04,
    SHOP_ITEM_MOON_SEED             = 0x05,
    SHOP_ITEM_GRUBTUB_FUNGUS        = 0x06,
    SHOP_ITEM_FIREFLY               = 0x07,
    SHOP_ITEM_FUEL_CELL             = 0x08,
    SHOP_ITEM_TRICKYS_BALL          = 0x14,
    SHOP_ITEM_FIREFLY_LANTERN       = 0x15,
    SHOP_ITEM_SNOWHORN_ARTIFACT     = 0x16,
    SHOP_ITEM_BAFOMDAD_HOLDER       = 0x17,
    SHOP_ITEM_BAD_GUY_ALERT_UNUSED  = 0x18, /* unused, GAMEBIT_Always0-gated */
    SHOP_ITEM_ROCK_CANDY            = 0x19,
    SHOP_ITEM_PDA_UNUSED            = 0x1A, /* unused, Fox always has the real PDA */
    SHOP_ITEM_VIEWFINDER            = 0x1B,
    SHOP_ITEM_MAP_DARKICE_MINES     = 0x28,
    SHOP_ITEM_MAP_CAPE_CLAW         = 0x29,
    SHOP_ITEM_MAP_THORNTAIL_HOLLOW  = 0x2A,
    SHOP_ITEM_MAP_MOON_PASS         = 0x2B,
    SHOP_ITEM_MAP_WALLED_CITY       = 0x2C,
    SHOP_ITEM_MAP_CLOUDRUNNER_FORT  = 0x2D,
    SHOP_ITEM_MAP_LIGHTFOOT_VILLAGE = 0x2E,
    SHOP_ITEM_MAP_DRAGON_ROCK       = 0x2F,
    SHOP_ITEM_MAP_KRAZOA_PALACE     = 0x30,
    SHOP_ITEM_MAP_OCEAN_FORCE_POINT = 0x31,
    SHOP_ITEM_MAP_SNOWHORN_WASTES   = 0x32,
    SHOP_ITEM_MAP_VOLCANO_FORCE_PT  = 0x33,

    SHOP_ITEM_LAST = 0x3B /* highest valid row, per lbl_80327FD0's 0x2D0-byte size */
};
```

`ShopItemRow`'s currently-anonymous `pad1[0x4 - 0x1]` (offsets `0x1`-`0x3`) is verified above to be
the wiki's D1/D2/D3 fields, one byte each, and could be split out the same way `field4`/`minPrice`
already are:

```c
typedef struct ShopItemRow
{
    u8 price;       /* 0x0: normal price ("P$") */
    u8 discount1;   /* 0x1: "D1" */
    u8 discount2;   /* 0x2: "D2" */
    u8 discount3;   /* 0x3: "D3" (observed always == price) */
    u8 field4;      /* 0x4: unidentified, not one of the wiki's columns */
    u8 minPrice;    /* 0x5: runtime pick of discount1/discount2/discount3 */
    s16 availBit;   /* 0x6: "available" GameBit slot (-1 = always available) */
    s16 boughtBit;  /* 0x8: "bought" GameBit slot (-1 = none / repeatable consumable) */
    s16 textId;     /* 0xa: "text"; add 0x2710 for the GameText id */
} ShopItemRow;
```
