# Practice warp entry groups (EN v1.0)

Practice warps enable a small, map-wide baseline of object groups at committed
reload, before destination objects are instantiated. Browsing presets has no
side effects. Ordinary/scripted warps retain retail behavior. The setter is
`SaveGame_gplaySetObjGroupStatus`, so saved bits, cached masks and aliases follow
the same path as the Flags menu.

This pass covers entry boundaries and landing setup, not individual rooms.
Unlisted groups retain their state. No whole-bank reset, act change, story bit,
cutscene, or toggle command is replayed. Unsupported maps retain all groups.
Multiple entry requirements are combined into one baseline per destination;
these are practice defaults, not a claim to reproduce every normal arrival.
They do not guarantee that every room spawn works with arbitrary story progress.

## Defaults and evidence

Group numbers and map IDs below are decimal. Placement indices are zero based.
`+` and `-` identify the positive and negative crossing legs, not a compass
direction. Trigger arguments and destination bank aliases are checked against
the verified disc by `tools/practice/arrival_catalog.py`.

| Map | Enabled groups | Source |
| --- | --- | --- |
| Dragon Rock Top (2) | 15, 16 | Arwing landing sequence event 5, course map 62 |
| Volcano Force Point (4) | 1, 2 | `linkf#171 +` |
| Thorntail Hollow (7) | 0, 2, 3, 4, 5, 10 | `gplayNewGame`; `linke#82 -` |
| Snowhorn Wastes (10) | 0 | `linkb#107 +`, shared group bank |
| CloudRunner Fortress (12) | 0 | Arwing landing sequence event 5, course map 60 |
| Walled City (13) | 0, 1, 5, 10, 11 | Arwing landing sequence event 5, course map 61 |
| LightFoot Village (14) | 1 | `linkg#52 +` |
| CloudRunner Dungeon (16) | 10, 11, 12 | `fortress#222 -` |
| Moon Mountain Pass (18) | 0, 25 | `linke#58 +`; `linkf#32 -` |
| DIM Top (19) | 0, 22 | Arwing landing sequence event 5, course map 59 |
| DIM Bottom (27) | 0 | `snowmines2#11 +`, entrance boundary |
| Cape Claw (29) | 0, 1, 4, 31 | `gplayNewGame`; `capeclaw#479 +`, entrance boundary |
| CloudRunner Race (43) | 0, 1, 2, 10 | `linki#19 +` |
| Ocean Force Point Top (50) | 20 | `linkj#25 +` |
| LinkB (56) | 0 | `linkb#107 +` |
| LinkD (68) | 1 | `snowmines#459 +` |
| LinkF (70) | 30, 31 | `linkf#32 -`; `linkf#57 +` |
| LinkG (71) | 0, 3, 5, 10, 13, 31 | `linkg#1/2/6/65 +` |
| LinkH (72) | 1, 3, 31 | `linkh#26/135 +` |
| LinkI (74) | 0 | `linki#20 -` |

Arwing flight maps 38 and 58-62 have no object-group bank in the retail
`gSaveGameMapObjGroupBits` table. Their landing setup writes the ground areas
above; it is not evidence for a flight-map mask. The generator verifies these
zero entries. The landing source is
`src/dlls/objects/666_ARWArwing/ARWArwing.c`; new-save setup is
`src/dlls/engine/23/23.c`, function `gplayNewGame`.

The trigger interpreter in `src/dlls/objects/294/294.c` uses opcode 0x13 for
the source map's group and 0x1A for an explicit destination (param2 = map,
param1 = group). LinkB and LinkG share banks with Snowhorn and Thorntail;
nearby map names alone cannot establish which bank a command affects.
Presets are indexed by the requested destination, not automatically inherited
by every map sharing that bank. Retail alias propagation still applies.

## Deliberately unresolved

- VFP group 22 has both an enabling plane (`linkf#57`) and a separate disabling
  plane (`linkf#58`) on the approach. It needs a route-specific decision and is
  excluded from this baseline.
- Dungeon interior groups and the Cape Claw gas chamber/shrine room groups are
  not inferred from proximity to a spawn.
- Magic Cave placements specify a group and map act per entrance. Combining
  all of those would activate distinct rooms; map 54 gets no generic preset.
- Selected planes have no game-bit gates, but their placement can still depend
  on map act or residency groups. The report records these fields. This pass
  extracts entry requirements rather than replaying the trigger interpreter;
  it leaves the current act intact, and retail object loading still filters
  individual objects by that act.

## Regeneration and validation

```powershell
python tools/practice/arrival_catalog.py --iso "C:/Projects/SFA-Decomp/orig/GSAE01/Star Fox Adventures (USA) (v1.00).iso"
clang-format -i include/practice/arrival_catalog.h
```

The generated header contains only map IDs and enable masks. A JSON audit is
written to `build/practice/arrival-catalog.json`, including command bytes,
crossing legs, placement restrictions and source-romlist hashes. Explicit
expected group sets make placement/index drift fail during generation.
The DOL is hash-verified by the shared ISO reader.

PPC regression coverage checks committed-only application, preservation of an
existing room group and map act, the high group bit (31), use of the setter for
shared banks, and absence of edits on ordinary/superseded warps or flight maps.
Runtime playtesting of all entry defaults remains outstanding.
