# Warptab (`WARPTAB.bin`)

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Warptab). Reverse-engineering notes; not independently verified here.

`WARPTAB.bin` is a disc-root asset holding a flat, indexed list of warp destinations — the
positions the `warpToMap`/warp-point/warp-pad machinery jumps the player to. Each entry gives:

- `Xpos`, `Ypos`, `Zpos`: world-space coordinates to warp to.
- `Ly`: the destination map "layer".
- `Ang`: the angle the player faces on arrival — the high byte of an s16 angle, converted to
  approximate degrees in the table below.

About half the id range is unused (all-zero entries): these send you to an empty map where
Krystal is stuck in a climbing animation (Fox crashes outright). Omitted rows below have zeros in
every field.

## Warp destination table

ID|Xpos     |Ypos    |ZPos     |Ly|Ang|Destination
--|---------|--------|---------|--|---|------------
00|  +744.47|+1309.00|-16341.25| 0|  0|clouddungeon
02| +3583.79|+6397.00| +4374.05| 0|290|Ice Mountain, main entrance
03| -5517.87| -636.25|  -800.18| 0|  0|ThornTail Hollow, egg stealer cave
05|+11104.35| -289.00| +3593.05| 0|  0|Empty
06|+12264.56| +211.00|  +451.46| 0|  0|Krazoa Palace, near where Krystal lands
0C|  +744.47|+1309.00|-16341.25| 0|  0|same as 00
0F| -5222.53| -634.53| -1733.20| 0|331|WarpStone platform
10|-12406.05| -255.00|  -892.95| 0|  0|Moon Mountain Pass, magic cave entrance
12|-18780.69|  +31.71|+28498.75| 0|  0|Title Screen
13|-16321.92| -778.00|-13280.20| 0|  0|Walled City in front of pyramid
15|-16321.63| -844.00|-15650.99| 0|  0|Walled City magic cave entrance
1A| +3339.32|+6545.63| +4197.86| 0|  0|Ice Mountain after re-race
1D| -9273.60|-2958.66|+20698.02|-2|  0|Boss Galdon
1E| -7950.00|-2959.70|+20201.84|-2|  0|Boss Galdon (crashes)
20|+11840.23| -246.02| +5864.17| 0|  0|Krazoa Palace, WarpStone entrance
22|+13154.08|  -84.02| +2880.27| 0|  0|Krazoa Palace, interior warp
24|+14079.91| -204.01|-17072.95| 0|180|dfshrine (crashes)
25| +7039.94|  +57.95|-13887.78| 0|  0|nwshrine (crashes)
26|+17920.00| -204.02|-10672.93| 0|179|dbshrine (crashes)
27|+13927.60|  +56.34| -4632.16| 0|  0|empty
28|+10688.02|  -84.00| +1495.12| 0|271|Krazoa Palace, interior warp 2
2A|+17919.77| -204.03|-14514.45| 0|179|Walled City (crashes)
2B|+10240.04| -204.02|-18354.30| 0|179|mmshrine (crashes)
32|-11682.48| -956.37|-16806.23| 2|  0|Andross
33| +8269.23| +134.00|+31105.61| 0| 83|MazeCave
34| -5840.06| -569.00| -1711.77| 0|  0|ThornTail bomb spore cave
35| +2053.46|-1638.77| -2064.91| 0|  0|Cape Claw magic cave entrance
36| -9260.67|-2959.83|+20803.75|-2|  0|Boss Galdon (crashes)
40|-11839.86|  +52.99| -4799.99| 0|183|Moon Mountain Pass warp at end
41|+13201.71|+1278.00| +2239.03| 0|  0|Krazoa Palace warp to final boss
42| -4159.92| -522.02| +4159.72| 0|  0|SnowHorn Wastes shrine warp
44|+13440.05| -204.00|-13234.06| 0|179|ecshrine (crashes)
46|-16320.60| -474.00|-13759.80| 0|180|Walled City top of pyramid
47| -1601.05|-1217.00|  -960.92| 0|  0|LightFoot Village shrine warp
48|-18713.44| +389.00|  -307.88| 0|  0|Volcano
49|  -170.03|+1284.00|-14400.68| 0| 88|CloudRunner bike race
4A|  +463.57|+1845.00|-16899.71| 0|180|CloudRunner Fortress
4B| +1534.03|-2536.00| -8577.08|-1|  0|desert (crashes)
4C| +4225.95|-2536.01| -8576.80|-1|  0|desert (crashes)
4E|+12637.58|+1278.70| +2597.78| 0|  0|Krazoa Palace Arwing landing spot
50| -1299.30| -817.00| -1932.53| 0|  0|Lightfoot Village plateau
51|-18626.93|  -60.00|  +513.72| 0|  0|Volcano spellstone seal
53|-12767.98|-2364.00|+12376.13|-1|  0|hard crash that fucks up Dolphin (dragrockbot)
54| +7608.21| -281.00|+25924.80| 1|  0|Boss Drakor
55| -3401.70|-1029.90| -1769.50| 0|  0|LightFoot Village out of bounds next to cheat well
57|+10146.28| +120.00|-14819.20| 0| 45|magiccave (crashes)
5A|-10133.06|   +0.00|-12942.76| 0|  0|bosstrex (crashes)
5B|-16322.49|-1210.00|-13518.57| 0|  0|Walled City exiting from boss
5C| -9100.96|-2957.00|+20768.95|-2|  0|Boss Galdon (crashes)
5D|+13440.99| +973.00|+30397.73| 0|  0|old Krazoa Palace (empty)
5E|+19373.80|  +23.00|+30080.00| 0|  0|old Krazoa Palace (empty)
5F| -6661.47|-1092.00| -2257.07|-1|189|swapholbot (crashes)
60| +9467.04|  +24.71| -9098.43| 0|  0|World Map
63| +4125.24|+1470.00|-18232.93| 0|  0|CloudRunner Fortress, you fall through the ground
66| -6710.58| -716.00|  -956.86| 0|  0|ThornTail Hollow outside magic cave entrance
67| -2634.34| -131.00| +2167.80| 0|  0|SnowHorn Wastes magic cave entrance
68| +2878.27|-1533.02| -9251.86| 0|  0|Ocean Force Point Top warp
69| +2879.12|-2718.03| -9281.40|-1|179|desert (crashes)
6C| -5541.41| -775.00| -3385.49| 0|  0|ThornTail Hollow under the Arwing
6D|-10109.05|  +15.81|-12860.19| 0|  0|bosstrex (crashes)
6E| +6676.22| +270.01|-16653.10| 2|  0|Arwing shmup section flying to CloudRunner Fortress
6F|-17231.65| +274.55|-16641.20| 2|  0|Arwing to Dino Planet
71| +3198.86|-2543.00| -7986.54|-1|  0|desert (crashes)
72| +2894.08|-2543.00| -7679.65|-1| 90|desert (crashes)
73| +3357.74|-1601.00| -7428.49| 0|179|Ocean Force Point
74| -4843.78| +270.01|-16653.10| 2|  0|Arwing to DarkIce Mines
75|+14356.22| +270.01|-16653.10| 2|  0|Arwing to dragon
76|+10516.22| +270.01|-16653.10| 2|  0|Arwing to city
77| -7343.81|-1557.00| +8830.43| 0|  0|DarkIce Mines Arwing landing scene
78|-16802.63| -799.00|-11984.50| 0|  0|Walled City Arwing landing spot
79|-13753.41|-1715.00|+11227.98| 0|  0|Dragon Rock Arwing landing spot
7A|-18560.25| +293.00|  +639.91| 0|  0|Volcano central warp
7B|-17919.03| +198.00|  -975.60| 0|179|Volcano spellstone pillar thingy
7C|-16060.39|  +57.37|  -320.44| 0|271|VolcanoForcePoint
7E| -6068.69| +170.75|+20816.42| 0|  0|LinkA (crashes)
7F|  -860.69|  +31.71|+24658.75| 0|  0|GreatFox

## In this codebase

### The record format is confirmed, byte for byte, by `warpToMap`

`src/main/rcp_dolphin.c`'s `warpToMap(int idx, s8 transType)` is the function that consumes
`WARPTAB.bin`:

```c
typedef struct WarpDestination {
    f32 x;
    f32 y;
    f32 z;
    s16 angle0;
    s16 angle1;
} WarpDestination;

void warpToMap(int idx, s8 transType)
{
    u8* p = lbl_803DCE78;
    getTabEntry(p, 28, idx << 4, 16);
    ((WarpDestination*)gRcpPendingWarpDest)->x = *(f32*)(p + 0);
    ((WarpDestination*)gRcpPendingWarpDest)->y = *(f32*)(p + 4);
    ((WarpDestination*)gRcpPendingWarpDest)->z = *(f32*)(p + 8);
    ((WarpDestination*)gRcpPendingWarpDest)->angle0 = *(s16*)(p + 12);
    ((WarpDestination*)gRcpPendingWarpDest)->angle1 = *(s16*)(p + 14);
    ...
}
```

This is a **byte-exact** match for the wiki's schema:

- `getTabEntry(p, 28, idx << 4, 16)` reads a **16-byte** record at byte offset `idx * 16` — exactly
  `Xpos`/`Ypos`/`Zpos` (3×`f32`, 12 bytes) + `Ly`/`Ang` (2×`s16`, 4 bytes) = 16 bytes. Highest id in
  the wiki table is `0x7F` (127), so `WARPTAB.bin` is inferred to be `0x80 * 16 = 0x800` bytes total
  (not independently re-verified against this repo's `orig/` ISO in this pass).
- The literal `28` is the **file id**, and it independently matches: `src/main/pi_dolphin.c`'s
  `sResourceFileNameTable[90]` lists resource files in a fixed order, and index `28` (0-based) is
  `sResourceFileNameWarptabBin` = `"WARPTAB.bin"` (`config/GSAE01/symbols.txt`:
  `sResourceFileNameWarptabBin = .data:0x802CB09C`). So the `28` in `warpToMap` and the position of
  `WARPTAB.bin` in the resource table are the same number, cross-checked two different ways.

### `angle0`/`angle1` resolved: they are `Ly` and `Ang`, in that order

The struct's current field names (`angle0`, `angle1`) are a placeholder — tracing where the
pending-warp record actually lands proves what each one is. `loadNextMap` (same file) copies the
record, each half truncated to `s8`, into the current character's save-slot position record:

```c
*(s8*)(pos + 0xd) = (s8)((WarpDestination*)gRcpPendingWarpDest)->angle0;
*(s8*)(pos + 0xc) = (s8)((WarpDestination*)gRcpPendingWarpDest)->angle1;
```

`pos` here is `SaveGame_getCurCharPos()`, a `SaveGameCharacterPosition` (`src/main/dll/dll_0017_savegame.c`):

```c
typedef struct SaveGameCharacterPosition
{
    f32 x;
    f32 y;
    f32 z;
    s8 angle;   /* offset 0xc */
    s8 map;     /* offset 0xd */
    u8 padE[2];
} SaveGameCharacterPosition;
```

So `angle0` is written to `.map` (offset `0xd`) and `angle1` is written to `.angle` (offset `0xc`).
That means, in wiki terms:

- **`WarpDestination.angle0` is `Ly`** (the destination map layer) — matches the wiki's column
  order too (`Ly` is read right after `Zpos`, i.e. at file offset `0xc`, same as `angle0`).
- **`WarpDestination.angle1` is `Ang`** (the facing angle) — lands in the position record's
  already-named `angle` field, and the `s8` truncation matches the wiki's own description of `Ang`
  as effectively a coarse byte-angle (0-255 over 360°).

The struct's doc comment above `warpToMap` ("two orientation s16s") is imprecise for `angle0` — see
[Ready-to-adopt code](#ready-to-adopt-code) for the corrected field names.

### `warpToMap` call sites, cross-checked against the table above

Every literal id below was checked against the destination table and is consistent with it —
strong independent confirmation that the wiki's table is accurate:

| id | wiki destination | called from |
|----|-------------------|-------------|
| `0x00` | clouddungeon | `dll_0038_weirdunusedmenu.c`: `warpToMap(0, 1)` |
| `0x02` | Ice Mountain, main entrance | `dll_0238_linkalevco.c`: `LINKA_LEVCONTROL_WARP_ID_SHRINE` |
| `0x0E` | *(unused/all-zero entry)* | `SP/dll_0286_spshopkeeper.c`: `warpToMap(0xE, 0)` |
| `0x0F` | WarpStone platform | `dll_0238_linkalevco.c`: `LINKA_LEVCONTROL_WARP_ID_MODE3`; `SP/dll_0286_spshopkeeper.c`: `warpToMap(0xF, 0)` |
| `0x12` | Title Screen | `dll_0032_titlescreeninit.c`, `dll_0000_gameui.c`, `dll_02BB_gflevelcon.c` |
| `0x1A` | Ice Mountain after re-race | `IM/dll_0169_imicemountain.c` (a shared `warpCountdown` field/comment is also templated, unreached, in `dll_016C_dll16c.c` and `DIM/dll_01BE_dimlava.c`/`dll_01BF_dimlavaball.c`) |
| `0x20` | Krazoa Palace, WarpStone entrance | `dll_0238_linkalevco.c`: `LINKA_LEVCONTROL_WARP_ID_MODE2_ROUTE_A` |
| `0x22` | Krazoa Palace, interior warp | `dll_0238_linkalevco.c`: `LINKA_LEVCONTROL_WARP_ID_MODE2_ROUTE_B`; `ARW/dll_029A_arwarwing.c` |
| `0x32` | Andross | `dll_02BC_andross.c`, `dll_011B_landedarwing.c`, `ARW/dll_029A_arwarwing.c` |
| `0x33` | MazeCave | `SH/dll_01B0_shswapston.c` |
| `0x4E` | Krazoa Palace Arwing landing spot | `dll_02BC_andross.c`, `dll_011B_landedarwing.c` |
| `0x50` | Lightfoot Village plateau | `SC/dll_01B6_sclevelcontrol.c` |
| `0x60` | World Map | `dll_0039_dummy39.c`: `DUMMY39_WARP_MAP`; `ARW/dll_029A_arwarwing.c` (×2) |
| `0x63` | CloudRunner Fortress, fall through ground | `ARW/dll_029A_arwarwing.c`: `arwarwing_warpByCourse` |
| `0x6C` | ThornTail Hollow under the Arwing | `ARW/dll_029A_arwarwing.c`: `arwarwing_warpByCourse` |
| `0x73` | Ocean Force Point | `DF/dll_022D_dfpseqpoint.c` |
| `0x77` | DarkIce Mines Arwing landing scene | `ARW/dll_029A_arwarwing.c`; `DIM/dim2icicle.c` |
| `0x78` | Walled City Arwing landing spot | `ARW/dll_029A_arwarwing.c`: `arwarwing_warpByCourse` |
| `0x79` | Dragon Rock Arwing landing spot | `ARW/dll_029A_arwarwing.c`; `dll_024D_bossdrakor.c` |
| `0x7C` (124) | VolcanoForcePoint | `light.c`: `warpToMap(124, 0)` (×2) |
| `0x7E` | LinkA (crashes) | `WM/dll_020C_wmspiritplace.c`; `SH/dll_01B0_shswapston.c` |
| `0x7F` | GreatFox | `dll_011B_landedarwing.c` |

`arwarwing_warpByCourse`'s own `switch` reads especially cleanly against the wiki: it warps to
`0x22` (Krazoa interior) or `0x6c` (ThornTail, under the Arwing) depending on a game bit, then
`0x77`/`0x78`/`0x63`/`0x79` per `mapEventSlot` — DarkIce Mines / Walled City / CloudRunner Fortress
/ Dragon Rock landings, matching the wiki's descriptions one-for-one, including the "you fall
through the ground" CloudRunner Fortress case.

### Placement-driven warp ids (data-driven, not literals)

Several DLLs store a WARPTAB index in their placement/definition data rather than a hardcoded
literal — these are the runtime "typed pointer into WARPTAB" equivalent of the table above:

- **`dll_00F0_warppoint.c`** (DLL `0x00F0`, warppoint/save-point markers): placement field
  `def->warpMapIdx` (`s8`, offset `0x1a`) is passed straight to `warpToMap`.
- **`dll_011F_magiccavetop.c`** / **`dll_011E_magiccavebottom.c`** (DLL `0x011F`/`0x011E`, Magic
  Cave top/bottom): `MagiccavetopPlacement.warpMapId` (`s8`) is one placement field; a *second*
  field, `.gameBitValue` (`s8`), is written into game bit `0x1B8`
  (`GAMEBIT_MagicCaveExitWarp` in `include/main/gamebits.h`, commented there as "WARPTAB index that
  magic cave will exit to") by the top half, then read back by the bottom half
  (`MAGICCAVE_GAMEBIT_WARP_DEST`, `mainGetBit(...)` passed to `warpToMap`). Both files independently
  define `#define MAGICCAVE_GAMEBIT_WARP_DEST 0x1b8`, matching the gamebit enum exactly.
- **`CF/warp_pad.h`**: `WarpPadPlacement.warpId` (`s8`, offset `0x1A`) — the generic warp-pad
  object's placement-authored destination index (used by `dll_012C_transporter.c`'s
  `setup->warpId`).
- **`worldplanet.c`**: `gWorldPlanetWarpMapIndices[6]` (`extern u8[6]`) is indexed by
  `gWorldPlanetSelectionToIndex[state->selectedPlanet]` and fed to `warpToMap` when leaving the
  World Map planet-select screen. Declared `extern` only in this repo — its backing byte values
  (six WARPTAB ids, one per unlockable planet) are **not yet defined in any matched source file**.
- **`dll_0112_seqobject.c`**: `warpToMap(mapId, 0)` where `mapId` comes from a runtime object-sequence
  command — the id is data-driven from `OBJSEQ.bin`, not resolvable to a literal here.
- **`objseq.c`**: two call sites decode a WARPTAB id out of a script opcode's operand
  (`*(s16*)(cmd + 2) & 0xfff`) — likewise data-driven, not a literal.

### Not found

- No parsed/typed representation of `WARPTAB.bin` as a whole table exists in this codebase — only
  the single-record reader (`warpToMap`) and the record type (`WarpDestination`). There's no
  `WarpTabEntry[]` array or loader that reads the whole file at once.
- No enum or named-constant list of WARPTAB ids exists anywhere in `include/` — every call site
  above uses a raw hex literal (or a locally-scoped `#define` like `LINKA_LEVCONTROL_WARP_ID_*`,
  `DUMMY39_WARP_MAP`) rather than a shared, project-wide id.

## Ready-to-adopt code

```c
/* rcp_dolphin.c's WarpDestination, with angle0/angle1 renamed per the identification above
 * (traced via loadNextMap -> SaveGameCharacterPosition.map/.angle in dll_0017_savegame.c).
 * Byte layout/size (16 bytes) is unchanged -- this is a rename, not a layout change. */
typedef struct WarpDestination {
    f32 x;
    f32 y;
    f32 z;
    s16 layer; /* was angle0; == wiki "Ly" */
    s16 angle; /* was angle1; == wiki "Ang" (byte-angle, 0-255 over 360 degrees) */
} WarpDestination;
```

```c
/* WARPTAB.bin destination ids actually referenced by name in this codebase (see the call-site
 * table above). This is NOT the full 0x00-0x7F range from the wiki -- only ids this repo's own
 * code names or switches on get a symbol here, so as not to assert meaning for ids nothing in
 * the tree points at yet. */
enum WarpTabId
{
    WARPTAB_ID_CLOUDDUNGEON_START        = 0x00, /* dll_0038_weirdunusedmenu.c */
    WARPTAB_ID_ICE_MOUNTAIN_ENTRANCE     = 0x02, /* dll_0238_linkalevco.c: WARP_ID_SHRINE */
    WARPTAB_ID_WARPSTONE_PLATFORM        = 0x0F, /* dll_0238_linkalevco.c: WARP_ID_MODE3 */
    WARPTAB_ID_TITLE_SCREEN              = 0x12,
    WARPTAB_ID_ICE_MOUNTAIN_POST_RACE    = 0x1A,
    WARPTAB_ID_KRAZOA_WARPSTONE_ENTRANCE = 0x20, /* dll_0238_linkalevco.c: WARP_ID_MODE2_ROUTE_A */
    WARPTAB_ID_KRAZOA_INTERIOR_WARP      = 0x22, /* dll_0238_linkalevco.c: WARP_ID_MODE2_ROUTE_B */
    WARPTAB_ID_ANDROSS                   = 0x32,
    WARPTAB_ID_MAZECAVE                  = 0x33,
    WARPTAB_ID_KRAZOA_ARWING_LANDING     = 0x4E,
    WARPTAB_ID_LIGHTFOOT_PLATEAU         = 0x50,
    WARPTAB_ID_WORLD_MAP                 = 0x60,
    WARPTAB_ID_CRFORT_FALL_THROUGH_BUG   = 0x63, /* known-buggy destination per the wiki */
    WARPTAB_ID_THORNTAIL_UNDER_ARWING    = 0x6C,
    WARPTAB_ID_OCEAN_FORCE_POINT         = 0x73,
    WARPTAB_ID_DARKICE_ARWING_LANDING    = 0x77,
    WARPTAB_ID_WALLEDCITY_ARWING_LANDING = 0x78,
    WARPTAB_ID_DRAGONROCK_ARWING_LANDING = 0x79,
    WARPTAB_ID_VOLCANO_FORCE_POINT       = 0x7C,
    WARPTAB_ID_LINKA_CRASH               = 0x7E, /* crashes per wiki */
    WARPTAB_ID_GREATFOX                  = 0x7F,
};
```

Not proposed: a full 128-entry id enum for the whole `0x00`-`0x7F` range, since roughly half those
ids are all-zero/unused and most of the rest (`0x03`, `0x06`, `0x10`, `0x13`, ...) have no call site
anywhere in this repo to anchor a name to — inventing names for them now would just be re-copying
the wiki's `Destination` column as symbols, not adding anything this codebase itself confirms.
