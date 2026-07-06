# Map List

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/MapList). Reverse-engineering notes; not independently verified here.

See also the map loading procedure (MapLoading, not yet mirrored here).

Each map has:
- an ID
- a `[mapname].romlist.zlb` file
- a directory containing the map's assets
- an entry in `MAPINFO.bin` which contains:
  - the map's name (used by debug builds)
  - the map's type (`T`)
  - an object ID which, in older versions, specified which object to use as the player
    (omitted from the first list below since it's always zero)
  - an unknown parameter which is always 6 (omitted here)

## Main map list

ID|Romlist        |Directory Name|Name from MAPINFO.bin       |T|Note
--|---------------|--------------|----------------------------|-|----
00|frontend       |shipbattle    |Ship Battle                 |0|Start of game, Krystal vs ship
01|frontend2      |animtest      |ZNot Used - Front End2      |3|only map where T = 3
02|dragrock       |dragrock      |Dragon Rock - Top           |0|
03|krazoapalace   |animtest      |ZNot Used - Krazoa Palace   |0|Unused maps are prefixed with Z
04|temple         |volcano       |Volcano Force Point         |0|
05|hightop        |animtest      |Rolling Demo - Just In Case |0|
06|discovery      |animtest      |ZNot Used - Discovery Falls |0|
07|hollow         |swaphol       |ThornTail Hollow            |0|Originally called SwapStone Hollow
08|hollow2        |swapholbot    |ThornTail Hollow - Undergro |0|
09|mazecave       |mazecave      |MazeTest                    |0|
0a|wastes         |nwastes       |SnowHorn Wastes             |0|
0b|warlock        |warlock       |Krazoa Palace               |0|Originally called Warlock Mountain
0c|fortress       |crfort        |CloudRunner Fortress        |0|
0d|wallcity       |wallcity      |Walled City                 |0|
0e|swapcircle     |lightfoot     |LightFoot Village           |0|
0f|cloudtreasure  |cloudtreasure |ZNot Used - CloudRunner - T |0|directory missing
10|clouddungeon   |clouddungeon  |CloudRunner - Dungeon       |0|
11|cloudtrap      |animtest      |ZNot Used - CloudRunner - T |0|
12|moonpass       |mmpass        |Moon Mountain Pass          |0|
13|snowmines      |darkicemines  |DarkIce Mines - Top         |0|
14|krashrin2      |animtest      |ZNot Used - Krazoa Shrine   |0|
15|kraztest       |desert        |Ocean Force Point - Bottom  |0|
16|krazchamber    |animtest      |krazchamber                 |0|
17|newicemount    |icemountain   |Ice Mountain                |0|
18|newicemount2   |animtest      |ZNot Used - Ice Mountain 2  |0|
19|newicemount3   |animtest      |ZNot Used - Ice Mountain 3  |0|
1a|animtest       |animtest      |Animtest                    |0|
1b|snowmines2     |darkicemines2 |DarkIce Mines - Bottom      |0|
1c|snowmines3     |bossgaldon    |BOSS DarkIce                |0|
1d|capeclaw       |capeclaw      |Cape Claw                   |0|
1e|insidegal      |insidegal     |ZNot Used - Inside Galleon  |0|directory missing
1f|dfshrine       |dfshrine      |Test Of Combat              |0|
20|mmshrine       |mmshrine      |Test Of Fear                |0|
21|ecshrine       |ecshrine      |Test Of Skill               |0|
22|gpshrine       |gpshrine      |Test Of Knowledge           |0|
23|diamondbay     |dbay          |ZNot Used - Diamond Bay     |0|directory missing
24|earthwalker    |animtest      |ZNot Used - EarthWalker Tem |0|
25|willow         |animtest      |ZNot Used - Willow Grove    |0|
26|arwing         |arwing        |ArWing Level - Andross      |4|
27|dbshrine       |dbshrine      |Test Of Strength            |0|
28|nwshrine       |nwshrine      |BOSS Scales                 |0|
29|ccshrine       |worldmap      |World Map                   |4|choosing where to fly to
2a|wgshrine       |animtest      |ZNot Used - WGShrine        |0|
2b|cloudrace      |cloudrace     |CloudRunner - Race          |0|
2c|finalboss      |bossdrakor    |BOSS Drakor                 |0|
2d|wminsert       |animtest      |ZNot Used - WMinsert        |0|
2e|snowmines4     |animtest      |ZNot Used - DarkIce Mines - |0|
2f|snowmines5     |animtest      |ZNot Used - DarkIce Mines - |0|
30|trexboss       |bosstrex      |BOSS TRex                   |0|
31|mikelava       |animtest      |ZNot Used - MikesLava       |0|
32|dfptop         |dfptop        |Ocean Force Point - Top     |0|
33|swapstore      |shop          |Shop                        |0|ThornTail store
34|dragbot        |dragrockbot   |Dragon Rock - Bottom        |0|
35|kamdrag        |animtest      |ZNot Used - BOSS Kamerian D |0|
36|magicave       |magiccave     |Magic Cave - Small\Big      |0|caves where staff upgrades are found - has backslash
37|duster         |cloudjoin     |ZNot Used - Duster Cave     |0|directory missing
38|linkb          |linkb         |LinkB - Ice2Wastes          |0|
39|cloudjoin      |animtest      |ZNot Used - CloudRunner2Rac |0|
3a|arwingtoplanet |arwingtoplanet|Arwing to Planet            |4|flying to Dino Planet
3b|arwingdarkice  |arwingdarkice |Arwing Darkice              |4|
3c|arwingcloud    |arwingcloud   |Arwing Cloud                |4|
3d|arwingcity     |arwingcity    |Arwing City                 |4|
3e|arwingdragon   |arwingdragon  |Arwing Dragon               |4|
3f|gamefront      |gamefront     |Game Front                  |4|title screen
40|linklevel      |linklevel     |LinkK - Nik Test            |0|directory missing
41|greatfox       |greatfox      |Great Fox                   |0|probably first scene where Fox receives mission
42|linka          |linka         |LinkA - Warpstone to Others |0|
43|linkc          |linkc         |LinkC - Wastes to Hollow    |0|
44|linkd          |linkd         |LinkD - Darkmines top 2 bot |0|
45|linke          |linke         |LinkE - hollow to moon pass |0|
46|linkf          |linkf         |LinkF - moonpass to volcano |0|
47|linkg          |linkg         |LinkG - hollow to lightfoot |0|
48|linkh          |linkh         |LinkH - lightfoot to capecl |0|
49|linkj          |linkj         |LinkJ - capeclaw 2 ocean fo |0|
4a|linki          |linki         |LinkI - CloudRunner2Race    |0|

From here on, there appears to be no corresponding directory (the directory table only goes up to
entry 0x4A). The different naming convention also suggests they may be from later in development.

These are the only ones to use the `ObjType` field. Although this function was removed at some
point during development, the object IDs still seem to match up with the final version. Also, all
maps in this list have T (Map Type) 1.

ID|Romlist        |Name from MAPINFO.bin       |ObjType         |Note
--|---------------|----------------------------|----------------|----
4b|dfpodium       |dfpodium                    |0000            |
4c|dfcradle       |dfcradle                    |0000            |
4d|dfcavehatch1   |dfcavehatch1                |0000            |
4e|dfcavehatch2   |dfcavehatch2                |0000            |
4f|scstatue       |scstatue                    |0000            |
50|galleonship    |galleonship                 |008E SB_Galleon |
51|cfgalleon      |cfgalleon                   |00CE CFScalesGal|
52|cfgangplank    |cfgangplank                 |0000            |
53|nwtreebridge   |nwtreebridge                |0000            |
54|cfdungeonblock |cfdungeonblock              |00B3 CFDungeonBl|
55|cloudrunnermap |cloudrunnermap              |008C SB_Cloudrun|
56|ccbridge       |ccBridge                    |0099 CCBridge   |
57|cfcolumn       |cfcolumn                    |0782 CF_BobbingC|
58|nwboulder      |nwboulder                   |0000            |
59|cfprisondoor   |cfprisondoor                |00C1 CFPrisonDoo|
5a|cfprisoncage   |cfprisoncage                |0127 CFPrisonCag|
5b|nwtreebridge2  |nwtreebridge2               |01DB NW_treebrid|
5c|dim2iceblock1  |dim2 ice block1             |07C7 DIM2IcePlat|
5d|dimpushblock   |dimpushblock                |01CB DIMWoodDoor|
5e|dim2iceblock2  |dim2 ice block2             |07C9 DIM2IcePlat|
5f|dimhornplinth  |dimhornplinth               |0000            |
60|nwshcolpush    |nwshcolpush                 |0000            |
61|dim2lift       |dim2lift                    |0000            |
62|dim2icefloe    |dim2icefloe                 |0111 DIM2IceFloe|
63|dim2icefloe1   |dim2icefloe1                |0109 DIM2IceFloe|
64|dim2icefloe2   |dim2icefloe2                |010D DIM2IceFloe|
65|cfliftplat     |cfliftplat                  |0000            |
66|imspacecraft   |imspacecraft                |0168 IMAnimSpace|
67|dimbossgut     |dimbossgut                  |0155 DIM_BossGut|
68|wmcolrise      |wmcolrise                   |015D WM_colrise |
69|vfpslide1      |vfpslide1                   |03BA VFP_Platfor|
6a|vfpslide2      |vfpslide2                   |03C0 VFPLavaBloc|
6b|drpushcart     |drpushcart                  |0418 DR_PushCart|
6c|drliftplat     |drliftplat                  |03B1 DR_Platform|
6d|dim2stonepillar|dim2stonepillar             |00F2 DIM2StonePi|
6e|bossdrakorflatr|bossdrakorrock              |07DF WCPushBlock|
6f|wcbouncycrate  |wcbouncycrate               |04FE WCBouncyCra|
70|wcpushblock    |wcpushblock                 |0515 WCPushBlock|
71|wctemplelift   |wctemplelift                |0528 WCMoonTempl|
72|KamColumn      |kameriancolumn              |0000            |
73|dbstepstone    |dbstepstone                 |0000            |
74|vfppushblock   |vfppushblock                |0857 VFP_Bobbing|

Although `animtest` is unused (and contains only one object, a `setuppoint`), the game does look at
its files sometimes, notably at the title screen. This might have to do with `frontend2`?

`T` is the map type:
* 00: Normal map
* 01: Normal submap
* 02: Special map - unloads all objects immediately upon loading (unused)
* 03: Special submap (same as 02) - only used by map 1 which is itself unused
* 04: Special map - hides PDA HUD. Used for title screen and Arwing maps. If applied to a normal
  map, the game will crash looking for an object that isn't there.

## Changed Names

The names, as well as prerelease articles about the game, hint at some maps whose names have been
changed:

Final Name       | Original Name  |Internal |Note
-----------------|----------------|---------|----
ThornTail Hollow |SwapStone Hollow|swaphol  |WarpStone was once SwapStone
Krazoa Palace    |Warlock Mountain|warlock  |
Ocean Force Point|?               |desert   |
Test Of Combat   |?               |dfshrine |presumably "dfalls"
Test Of Fear     |?               |mmshrine |presumably Moon Mountain
Test Of Skill    |?               |ecshrine |
Test Of Knowledge|?               |gpshrine |
Test Of Strength |?               |dbshrine |Diamond Bay?
BOSS Scales      |?               |nwshrine |Northern Wastes (SnowHorn Wastes)
World Map        |?               |ccshrine |Probably reused map ID
BOSS Drakor      |?               |finalboss|Probably final boss before Starfoxification

## Directory List

The table at `0x802cbbac` in RAM (v1.0) is a list of map directories with many repeats:

ID|Directory  |ID|Directory    |ID|Directory    |ID|Directory     |ID|Dir
--|-----------|--|-------------|--|-------------|--|--------------|--|-----
00|animtest   |10|shop         |20|animtest     |30|dbay          |40|linka
01|animtest   |11|animtest     |21|animtest     |31|animtest      |41|linkc
02|animtest   |12|crfort       |22|darkicemines2|32|cloudrace     |42|linkd
03|arwing     |13|swapholbot   |23|bossgaldon   |33|bossdrakor    |43|linke
04|dragrock   |14|wallcity     |24|animtest     |34|animtest      |44|linkf
05|animtest   |15|lightfoot    |25|insidegal    |35|bosstrex      |45|linkg
06|dfptop     |16|cloudtreasure|26|magiccave    |36|linkb         |46|linkh
07|volcano    |17|animtest     |27|dfshrine     |37|cloudjoin     |47|linkj
08|animtest   |18|clouddungeon |28|mmshrine     |38|arwingtoplanet|48|linki
09|mazecave   |19|mmpass       |29|ecshrine     |39|arwingdarkice |
0a|dragrockbot|1a|darkicemines |2a|gpshrine     |3a|arwingcloud   |
0b|dfalls     |1b|animtest     |2b|dbshrine     |3b|arwingcity    |
0c|swaphol    |1c|desert       |2c|nwshrine     |3c|arwingdragon  |
0d|shipbattle |1d|animtest     |2d|worldmap     |3d|gamefront     |
0e|nwastes    |1e|icemountain  |2e|animtest     |3e|linklevel     |
0f|warlock    |1f|animtest     |2f|capeclaw     |3f|greatfox      |

At `0x802cbcd0` is a lookup table that translates map IDs to indices into the above table.

Idx|Dir|Map            |Directory               |Note
---|---|---------------|------------------------|----
 00| 0D|frontend       |shipbattle              |
 01| 05|frontend2      |animtest                |frontend dir not used
 02| 04|dragrock       |dragrock                |
 03| 05|krazoapalace   |animtest                |used krazoa palace is idx 0B
 04| 07|temple         |volcano                 |
 05| 05|hightop        |animtest                |
 06| 05|discovery      |animtest                |dfalls dir not used
 07| 0C|hollow         |swaphol                 |
 08| 13|hollow2        |swapholbot              |
 09| 09|mazecave       |mazecave                |
 0a| 0E|wastes         |nwastes                 |
 0b| 0F|warlock        |warlock                 |
 0c| 12|fortress       |crfort                  |
 0d| 14|wallcity       |wallcity                |
 0e| 15|swapcircle     |lightfoot               |swapcircle dir not used
 0f| 16|cloudtreasure  |cloudtreasure           |
 10| 18|clouddungeon   |clouddungeon            |
 11| 05|cloudtrap      |animtest                |
 12| 19|moonpass       |mmpass                  |
 13| 1A|snowmines      |darkicemines            |
 14| 05|krashrin2      |animtest                |
 15| 1C|kraztest       |desert                  |
 16| 05|krazchamber    |animtest                |
 17| 1E|newicemount    |icemountain             |
 18| 1F|newicemount2   |animtest                |different animtest entry
 19| 20|newicemount3   |animtest                |different animtest entry
 1a| 05|animtest       |animtest                |
 1b| 22|snowmines2     |darkicemines2           |
 1c| 23|snowmines3     |bossgaldon              |
 1d| 2F|capeclaw       |capeclaw                |
 1e| 25|insidegal      |insidegal               |
 1f| 27|dfshrine       |dfshrine                |
 20| 28|mmshrine       |mmshrine                |
 21| 29|ecshrine       |ecshrine                |
 22| 2A|gpshrine       |gpshrine                |
 23| 30|diamondbay     |dbay                    |
 24| 05|earthwalker    |animtest                |
 25| 05|willow         |animtest                |
 26| 03|arwing         |arwing                  |
 27| 2B|dbshrine       |dbshrine                |
 28| 2C|nwshrine       |nwshrine                |
 29| 2D|ccshrine       |worldmap                |
 2a| 05|wgshrine       |animtest                |
 2b| 32|cloudrace      |cloudrace               |
 2c| 33|finalboss      |bossdrakor              |
 2d| 05|wminsert       |animtest                |
 2e| 05|snowmines4     |animtest                |
 2f| 05|snowmines5     |animtest                |
 30| 35|trexboss       |bosstrex                |
 31| 05|mikelava       |animtest                |
 32| 06|dfptop         |dfptop                  |
 33| 10|swapstore      |shop                    |
 34| 0A|dragbot        |dragrockbot             |
 35| 05|kamdrag        |animtest                |
 36| 26|magicave       |magiccave               |
 37| 37|duster         |cloudjoin               |
 38| 36|linkb          |linkb                   |
 39| 05|cloudjoin      |animtest                |cloudjoin dir used for unused duster map
 3a| 38|arwingtoplanet |arwingtoplanet          |
 3b| 39|arwingdarkice  |arwingdarkice           |
 3c| 3A|arwingcloud    |arwingcloud             |
 3d| 3B|arwingcity     |arwingcity              |
 3e| 3C|arwingdragon   |arwingdragon            |
 3f| 3D|gamefront      |gamefront               |
 40| 3E|linklevel      |linklevel               |
 41| 3F|greatfox       |greatfox                |
 42| 40|linka          |linka                   |
 43| 41|linkc          |linkc                   |
 44| 42|linkd          |linkd                   |
 45| 43|linke          |linke                   |
 46| 44|linkf          |linkf                   |
 47| 45|linkg          |linkg                   |
 48| 46|linkh          |linkh                   |
 49| 47|linkj          |linkj                   |
 4a| 48|linki          |linki                   |

## Unused/Mismatched Directories

A few directories aren't used, or don't match up with the actual map:
* Directory `frontend` is unused; map `frontend` uses directory `shipbattle`
* Directory `dfalls` is unused, probably belonged to map `discovery` or `dbay`
* Directory `swapcircle` is unused; map `swapcircle` uses directory `lightfoot`
* Maps `newicemount2` and `newicemount3` use entries 0x1F and 0x20 in the directory list (both are
  `animtest`, but most unused maps use entry 0x05 instead)
* Map `duster` uses directory `cloudjoin`
* Map `cloudjoin` uses directory `animtest`
* ID 0x05 (animtest) is also used as the default for any invalid map IDs

## Parent Maps

At `0x802cbdfc` is a table assigning some map directories a "parent". If a map has a parent listed
here, the parent is loaded at the same time as the map. (Note that `Idx` here is a directory ID, not
a map ID.)

Idx|ID|Directory   |Parent       |
---|--|------------|-------------|
 09|0C|mazecave    |swaphol      |
 0d|0F|shipbattle  |warlock      |
 10|0C|shop        |swaphol      |
 13|0C|swapholbot  |swaphol      |
 18|12|clouddungeon|crfort       |
 1c|06|desert      |dfptop       |
 23|22|bossgaldon  |darkicemines2|
 27|19|dfshrine    |mmpass       |
 28|15|mmshrine    |lightfoot    |
 29|0F|ecshrine    |warlock      |
 2a|14|gpshrine    |wallcity     |
 2b|0E|dbshrine    |nwastes      |
 2c|0F|nwshrine    |warlock      |
 30|05|dbay        |animtest     |
 35|14|bosstrex    |wallcity     |
 36|1E|linkb       |icemountain  |
 3f|0F|greatfox    |warlock      |
 41|0E|linkc       |nwastes      |
 43|0C|linke       |swaphol      |
 44|07|linkf       |volcano      |
 45|0C|linkg       |swaphol      |
 46|15|linkh       |lightfoot    |
 47|2F|linkj       |capeclaw     |

## In this codebase

This page's three RAM tables and the `MAPINFO.bin`/map-type mechanics are all present, matched, and
byte-verified in `src/main/pi_dolphin.c`. The three data-address citations in the wiki
(`0x802cbbac`, `0x802cbcd0`, `0x802cbdfc`) are exact matches for three of our symbols — same
addresses, same sizes, and (checked cell-by-cell below) the same content:

| Wiki address | Wiki table | Our symbol | Source |
|---|---|---|---|
| `0x802CBBAC` (size `0x124`, 73 entries) | Directory List | `sMapFileNameByMapIdTable` | `src/main/pi_dolphin.c:8049` |
| `0x802CBCD0` (size `0x12C`, 75 entries) | map ID → dir-list index | `sMapFileNameIndexRemapTable` | `src/main/pi_dolphin.c:8071` |
| `0x802CBDFC` (size `0x98`, 76 `s16` entries) | Parent Maps | `sMapFileNameAdjacencyTable` | `src/main/pi_dolphin.c:8079` |

Verified by direct comparison against this file's own tables:
- `sMapFileNameByMapIdTable[0x00..0x48]` reproduces the wiki's "Directory List" table entry-for-entry
  (e.g. index `0x0B`=`sMapFileNameWarlock`, `0x0C`=`sMapFileNameCrfort`, ... `0x48`=`sMapFileNameLinki`).
- `sMapFileNameIndexRemapTable[0x00..0x4a]` reproduces the wiki's "map IDs to indices" table exactly
  (e.g. `[0x00]=13`, `[0x07]=12`, `[0x1d]=47`, `[0x4a]=72` — all checked against the wiki's hex `Dir`
  column converted to decimal).
- `sMapFileNameAdjacencyTable` reproduces every row of the wiki's "Parent Maps" table: each listed
  `Idx` (a *directory* ID, matching the wiki's caveat) holds the parent's directory ID, e.g.
  `table[9]=12` (mazecave→swaphol, dir `0x0C`=12), `table[35]=34` (bossgaldon→darkicemines2, dir
  `0x22`=34), `table[71]=47` (linkj→capeclaw, dir `0x2F`=47); every other slot is `-1`.

Other concrete matches:

- **The 117-entry master name table** (both wiki tables concatenated, IDs `0x00`-`0x74`) is
  `sMapFileNameTable[117]` at `.data:0x802CB940` (`symbols.txt:10599`, `pi_dolphin.c:7824`) — used by
  `piRomLoadSection` (`.text:0x80048328`, `pi_dolphin.c:2713`) to build the
  `[mapname].romlist.zlb` path the wiki's intro describes: `sprintf(buf, sRomlistZlbPathFormat,
  sMapFileNameTable[mapIndex])`.
- **`mapGetDirIdx(int idx)`** (`.text:0x800481B0`, `pi_dolphin.c:3267`, declared in
  `include/main/gameplay_runtime.h:14`) is exactly the wiki's "map IDs to indices" lookup:
  `if (idx >= 0x4b) return 5; return sMapFileNameIndexRemapTable[idx];` — the `>= 0x4b` bound and the
  hardcoded `5` (`animtest`'s directory-list index) are a verbatim match for the wiki's "ID 0x05
  (animtest) is also used as the default for any invalid map IDs" note. It's called from dozens of
  DLLs across the tree (`grep -rn "mapGetDirIdx(" src/ | wc -l` → 122 call sites) whenever an object
  needs to lock/unlock/unload a *different* map by ID.
- **`loadMapAndParent(int mapId)`** (`.text:0x80042F78`, `src/main/objprint_dolphin.c:3782`, declared
  in `include/main/gameplay_runtime.h:11`) is the "Parent Maps" logic verbatim: resolve `mapId` to a
  dir-list index via `sMapFileNameIndexRemapTable`, look up `sMapFileNameAdjacencyTable[idx]`, and if
  a parent exists and isn't already loaded (`mapCheckCurBlocks(parent) == -1`), load the *parent*
  instead of the map itself.
- **`sResourceFileNameMapinfoBin[] = "MAPINFO.bin"`** (`pi_dolphin.c:7982`, symbol
  `.data:0x802CB0C0`, `symbols.txt:10460`) is fileId `0x1f` in `sResourceFileNameTable` — the
  archive the wiki says holds the per-map name/type/objId/unknown-param records.
- **The `T` (map type) field is `curMapType`**, exposed via `getCurMapType()`
  (`src/main/shader.c:210,215`). `mapSetup` (`shader.c:460`) and a second inline copy
  (`shader.c:2773-2786`) both read it the same way: `getDataFileSize(0x1f) >> 5` gives the record
  count (each `MAPINFO.bin` record is `0x20` bytes), then `getTabEntry(..., 0x1f, mapId << 5, 0x20)`
  fetches record `mapId`, and byte `+0x1c` of that record is `curMapType` (`shader.c:502`,
  `shader.c:2785`). This is a genuine structural finding beyond what the wiki states: it pins down
  *where* the `T` byte lives inside the (otherwise-undocumented) 0x20-byte `MAPINFO.bin` record.
  - `mapSetupPlayer` (`.text:0x8002BA2C`, `src/main/object.c:1979`) matches the wiki's whole `T`
    table in one function: `mapType == 2 || mapType == 3` resets the object system (wiki: type 2
    "unloads all objects immediately upon loading", type 3 "same as 02"); `mapType != 4` gates
    spawning the player character object (wiki: type 4 "hides PDA HUD... If applied to a normal map,
    the game will crash looking for an object that isn't there" — because with `T=4` this function
    deliberately skips creating that object).
  - `sceneRender` (`.text:0x8005C750`, `src/main/lightmap.c:437`) clears a render flag when
    `curMapType == 1 || curMapType == 3` — i.e. treats types 1 (normal submap) and 3 (special
    submap, wiki-documented as unused outside map 1) as the two "submap" flavors for this purpose.
- **The "Changed Names" section is independently corroborated by this codebase's own comments** —
  written from the disassembly with no knowledge of this wiki page, yet describing the exact same
  renames:
  - `src/main/dll/WM/dll_020E_wmsun.c:2-3`: `"(map 'warlock' = Dinosaur Planet's Warlock Mountain,
    hence the WM dll ...)"` — matches wiki's Krazoa Palace ⇐ Warlock Mountain.
  - `src/main/dll/SB/dll_01E8_sbgalleon.c:2-4`: `"SB" is the retail map name "ShipBattle"` — matches
    wiki's map `00`/dir `shipbattle`.
  - `src/main/dll/SH/shthorntail.c:2`, `src/main/dll/SH/dll_01B1_shstaff.c:4`: ThornTail Hollow
    naming, matching wiki's ThornTail Hollow ⇐ SwapStone Hollow (dir `swaphol`).
- **DLL-directory prefixes that resolve to a map in this list** (verified via in-file comment text,
  not just directory-name guessing): `SB` → `shipbattle` (map `00`/`frontend`), `WM` → `warlock` (map
  `0b`), `NW` → `nwastes` (map `0a`, comments literally gloss `"sh" = SnowHorn`,
  `src/main/dll/NW/dll_0198_nwshlevcon.c:3`), `MMP` → `mmpass` (map `12`), `IM` → `icemountain` (map
  `17`), `VF` → `volcano`/`temple` (map `04`, "Volcano Force Point Temple" in every `VF/*.c` banner),
  `CF` → `crfort` (map `0c`), `WC` → `wallcity` (map `0d`), `ARW` → `arwing` (map `26`).

### The wiki's `ObjType` column is a different ID space than this project's `dll_XXXX_*.c` numbers

Do not assume the second table's `ObjType` hex value equals a `dll_XXXX_*.c` file number in this
tree — it doesn't, in every case checked:

- ObjType `008E SB_Galleon` — `src/main/dll/dll_008E_dll8efunc0.c` is an unrelated foodbag
  particle-effect spawner; the real galleon object is `src/main/dll/SB/dll_01E8_sbgalleon.c` (DLL
  `0x1E8`).
- ObjType `008C SB_Cloudrun` — `src/main/dll/dll_008C_dll8cfunc0.c` is likewise a foodbag effect; the
  actual Cloudrunner-mount object is `src/main/dll/SB/dll_0259_sbcloudrunner.c` (DLL `0x259`).
- ObjType `0168 IMAnimSpace` — the real object is `src/main/dll/IM/dll_016E_imanimspacecraft.c` (DLL
  `0x16E`), off by 6 from the wiki's `ObjType`.
- Confirmed directly in-tree: `src/main/dll/SB/dll_01F0_sbkytecage.c:32-33` defines
  `#define SB_KYTE_OBJECT_TYPE 0x121` for a child object it looks up — that object's own DLL is
  `dll_01F2_sbcagekyte.c` (`0x1F2`). Object-type ID and DLL ID are tracked as separate fields in our
  own code, exactly as this mismatch would predict.

`ObjType` is almost certainly an index into the separate object-class table (`OBJECTS.bin`/
`OBJINDEX.bin`), not this project's DLL/file numbering. Where the wiki's object-class *name* (not
its numeric ID) could be matched to a file in this tree by content, here's the correspondence (all
manually verified by reading the file, not by name-guessing):

| Map (wiki 2nd table) | Wiki `ObjType` name | Matched in this tree |
|---|---|---|
| `galleonship` (0x50) | `SB_Galleon` | `src/main/dll/SB/dll_01E8_sbgalleon.c` |
| `cloudrunnermap` (0x55) | `SB_Cloudrun` | `src/main/dll/SB/dll_0259_sbcloudrunner.c` |
| `cfprisoncage` (0x5a) | `CFPrisonCag` | `src/main/dll/CF/dll_0154_cfprisoncage.c` |
| `nwtreebridge2` (0x5b) | `NW_treebrid` | `src/main/dll/NW/dll_019F_nwtreebrid.c` |
| `dimpushblock` (0x5d) | `DIMWoodDoor` | `src/main/dll/DIM/dll_01CB_dimwooddoor2.c`, `dimwooddoor.c` |
| `dim2icefloe*` (0x62-0x64) | `DIM2IceFloe` | `src/main/dll/DIM/dll_01DC_dim2icefloe.c` |
| `imspacecraft` (0x66) | `IMAnimSpace` | `src/main/dll/IM/dll_016E_imanimspacecraft.c` |
| `dimbossgut` (0x67) | `DIM_BossGut` | `src/main/dll/DIM/dll_01E1_dimbossgut.c`, `dll_01E3_dimbossgut2.c` |
| `wmcolrise` (0x68) | `WM_colrise` | `src/main/dll/WM/dll_0201_wmcolrise.c` |
| `bossdrakorflatr` (0x6e) / `wcpushblock` (0x70) | `WCPushBlock` | `src/main/dll/WC/dll_0290_wcpushblock.c`, `wcpushblock.c` |
| `wcbouncycrate` (0x6f) | `WCBouncyCra` | `src/main/dll/WC/dll_028C_wcbouncycra.c` |

Not found in this tree (either not yet split out as a distinct file, or bundled inside another
object's source): `CFDungeonBl`, `CCBridge`, `CF_BobbingC`, `CFPrisonDoo`, `DIM2IcePlat`,
`VFP_Platfor`, `VFPLavaBloc`, `DR_PushCart`, `DR_Platform`, `DIM2StonePi`, `WCMoonTempl`,
`VFP_Bobbing`.

### Existing per-file map-ID constants this list would replace

Nothing in the tree centralizes the map-ID space today; individual DLLs each define their own
local `#define` for the map IDs they care about, e.g.:

```c
// include/main/dll/DIM/dll_01E0_dimboss.h:109-111
#define DIMBOSS_MAP_DIR 0x1C     /* == MAP_ID_SNOWMINES3 ("BOSS DarkIce") below */
#define DIMBOSS_GUT_MAP_DIR 0x1B /* == MAP_ID_SNOWMINES2 ("DarkIce Mines - Bottom") */
#define DIMTOP_MAP_DIR 0x13      /* == MAP_ID_SNOWMINES  ("DarkIce Mines - Top") */
```

(`include/main/crcloudrace.h:9` and `include/main/worldplanet.h:9` follow the same one-off pattern.)
Most call sites (`src/main/dll/dll_012C_transporter.c`, `dll_02BC_andross.c`, `WM/dll_020C_wmspiritplace.c`,
`ARW/dll_029A_arwarwing.c`, etc.) just pass a bare hex literal to `mapGetDirIdx`/`lockLevel`/
`unlockLevel`/`mapUnload` with no name at all.

## Ready-to-adopt code

Two enums fall directly out of this page and out of tables/functions that already exist in this
tree; a maintainer could lift these into a new shared header (e.g. `include/main/mapid.h`) and start
replacing the bare hex literals at the ~80 `mapGetDirIdx(...)` call sites plus the per-file defines
shown above.

```c
/* Map ID space (index into sMapFileNameTable / MAPINFO.bin), 0x00-0x74.
   Trailing comment is the MAPINFO.bin debug name; "unused" = wiki's Z-prefixed placeholder maps. */
typedef enum MapId
{
    MAP_ID_FRONTEND        = 0x00, /* Ship Battle - start of game */
    MAP_ID_FRONTEND2       = 0x01, /* unused; only map with T=3 */
    MAP_ID_DRAGROCK        = 0x02, /* Dragon Rock - Top */
    MAP_ID_KRAZOAPALACE    = 0x03, /* unused */
    MAP_ID_TEMPLE          = 0x04, /* Volcano Force Point */
    MAP_ID_HIGHTOP         = 0x05, /* unused */
    MAP_ID_DISCOVERY       = 0x06, /* unused */
    MAP_ID_HOLLOW          = 0x07, /* ThornTail Hollow */
    MAP_ID_HOLLOW2         = 0x08, /* ThornTail Hollow - Undergro */
    MAP_ID_MAZECAVE        = 0x09,
    MAP_ID_WASTES          = 0x0A, /* SnowHorn Wastes */
    MAP_ID_WARLOCK         = 0x0B, /* Krazoa Palace */
    MAP_ID_FORTRESS        = 0x0C, /* CloudRunner Fortress */
    MAP_ID_WALLCITY        = 0x0D, /* Walled City */
    MAP_ID_SWAPCIRCLE      = 0x0E, /* LightFoot Village */
    MAP_ID_CLOUDTREASURE   = 0x0F, /* unused */
    MAP_ID_CLOUDDUNGEON    = 0x10,
    MAP_ID_CLOUDTRAP       = 0x11, /* unused */
    MAP_ID_MOONPASS        = 0x12,
    MAP_ID_SNOWMINES       = 0x13, /* DarkIce Mines - Top */
    MAP_ID_KRASHRIN2       = 0x14, /* unused */
    MAP_ID_KRAZTEST        = 0x15, /* Ocean Force Point - Bottom */
    MAP_ID_KRAZCHAMBER     = 0x16, /* unused */
    MAP_ID_NEWICEMOUNT     = 0x17, /* Ice Mountain */
    MAP_ID_NEWICEMOUNT2    = 0x18, /* unused */
    MAP_ID_NEWICEMOUNT3    = 0x19, /* unused */
    MAP_ID_ANIMTEST        = 0x1A, /* default map for invalid IDs */
    MAP_ID_SNOWMINES2      = 0x1B, /* DarkIce Mines - Bottom */
    MAP_ID_SNOWMINES3      = 0x1C, /* BOSS DarkIce */
    MAP_ID_CAPECLAW        = 0x1D,
    MAP_ID_INSIDEGAL       = 0x1E, /* unused */
    MAP_ID_DFSHRINE        = 0x1F, /* Test Of Combat */
    MAP_ID_MMSHRINE        = 0x20, /* Test Of Fear */
    MAP_ID_ECSHRINE        = 0x21, /* Test Of Skill */
    MAP_ID_GPSHRINE        = 0x22, /* Test Of Knowledge */
    MAP_ID_DIAMONDBAY      = 0x23, /* unused */
    MAP_ID_EARTHWALKER     = 0x24, /* unused */
    MAP_ID_WILLOW          = 0x25, /* unused */
    MAP_ID_ARWING          = 0x26, /* ArWing Level - Andross; T=4 */
    MAP_ID_DBSHRINE        = 0x27, /* Test Of Strength */
    MAP_ID_NWSHRINE        = 0x28, /* BOSS Scales */
    MAP_ID_CCSHRINE        = 0x29, /* World Map; T=4 */
    MAP_ID_WGSHRINE        = 0x2A, /* unused */
    MAP_ID_CLOUDRACE       = 0x2B,
    MAP_ID_FINALBOSS       = 0x2C, /* BOSS Drakor */
    MAP_ID_WMINSERT        = 0x2D, /* unused */
    MAP_ID_SNOWMINES4      = 0x2E, /* unused */
    MAP_ID_SNOWMINES5      = 0x2F, /* unused */
    MAP_ID_TREXBOSS        = 0x30, /* BOSS TRex */
    MAP_ID_MIKELAVA        = 0x31, /* unused */
    MAP_ID_DFPTOP          = 0x32, /* Ocean Force Point - Top */
    MAP_ID_SWAPSTORE       = 0x33, /* Shop */
    MAP_ID_DRAGBOT         = 0x34, /* Dragon Rock - Bottom */
    MAP_ID_KAMDRAG         = 0x35, /* unused */
    MAP_ID_MAGICAVE        = 0x36, /* Magic Cave - Small/Big */
    MAP_ID_DUSTER          = 0x37, /* unused */
    MAP_ID_LINKB           = 0x38, /* LinkB - Ice2Wastes */
    MAP_ID_CLOUDJOIN       = 0x39, /* unused */
    MAP_ID_ARWINGTOPLANET  = 0x3A, /* T=4 */
    MAP_ID_ARWINGDARKICE   = 0x3B, /* T=4 */
    MAP_ID_ARWINGCLOUD     = 0x3C, /* T=4 */
    MAP_ID_ARWINGCITY      = 0x3D, /* T=4 */
    MAP_ID_ARWINGDRAGON    = 0x3E, /* T=4 */
    MAP_ID_GAMEFRONT       = 0x3F, /* title screen; T=4 */
    MAP_ID_LINKLEVEL       = 0x40, /* unused */
    MAP_ID_GREATFOX        = 0x41,
    MAP_ID_LINKA           = 0x42, /* Warpstone to Others */
    MAP_ID_LINKC           = 0x43, /* Wastes to Hollow */
    MAP_ID_LINKD           = 0x44, /* Darkmines top to bottom */
    MAP_ID_LINKE           = 0x45, /* hollow to moon pass */
    MAP_ID_LINKF           = 0x46, /* moonpass to volcano */
    MAP_ID_LINKG           = 0x47, /* hollow to lightfoot */
    MAP_ID_LINKH           = 0x48, /* lightfoot to capeclaw */
    MAP_ID_LINKJ           = 0x49, /* capeclaw to ocean force point */
    MAP_ID_LINKI           = 0x4A, /* CloudRunner to Race */

    /* 0x4B+: no map directory - ObjType-only prefab-object slots, all T=1 */
    MAP_ID_DFPODIUM        = 0x4B,
    MAP_ID_DFCRADLE        = 0x4C,
    MAP_ID_DFCAVEHATCH1    = 0x4D,
    MAP_ID_DFCAVEHATCH2    = 0x4E,
    MAP_ID_SCSTATUE        = 0x4F,
    MAP_ID_GALLEONSHIP     = 0x50, /* ObjType SB_Galleon */
    MAP_ID_CFGALLEON       = 0x51, /* ObjType CFScalesGal */
    MAP_ID_CFGANGPLANK     = 0x52,
    MAP_ID_NWTREEBRIDGE    = 0x53,
    MAP_ID_CFDUNGEONBLOCK  = 0x54, /* ObjType CFDungeonBl */
    MAP_ID_CLOUDRUNNERMAP  = 0x55, /* ObjType SB_Cloudrun */
    MAP_ID_CCBRIDGE        = 0x56, /* ObjType CCBridge */
    MAP_ID_CFCOLUMN        = 0x57, /* ObjType CF_BobbingC */
    MAP_ID_NWBOULDER       = 0x58,
    MAP_ID_CFPRISONDOOR    = 0x59, /* ObjType CFPrisonDoo */
    MAP_ID_CFPRISONCAGE    = 0x5A, /* ObjType CFPrisonCag */
    MAP_ID_NWTREEBRIDGE2   = 0x5B, /* ObjType NW_treebrid */
    MAP_ID_DIM2ICEBLOCK1   = 0x5C, /* ObjType DIM2IcePlat */
    MAP_ID_DIMPUSHBLOCK    = 0x5D, /* ObjType DIMWoodDoor */
    MAP_ID_DIM2ICEBLOCK2   = 0x5E, /* ObjType DIM2IcePlat */
    MAP_ID_DIMHORNPLINTH   = 0x5F,
    MAP_ID_NWSHCOLPUSH     = 0x60,
    MAP_ID_DIM2LIFT        = 0x61,
    MAP_ID_DIM2ICEFLOE     = 0x62, /* ObjType DIM2IceFloe */
    MAP_ID_DIM2ICEFLOE1    = 0x63, /* ObjType DIM2IceFloe */
    MAP_ID_DIM2ICEFLOE2    = 0x64, /* ObjType DIM2IceFloe */
    MAP_ID_CFLIFTPLAT      = 0x65,
    MAP_ID_IMSPACECRAFT    = 0x66, /* ObjType IMAnimSpace */
    MAP_ID_DIMBOSSGUT      = 0x67, /* ObjType DIM_BossGut */
    MAP_ID_WMCOLRISE       = 0x68, /* ObjType WM_colrise */
    MAP_ID_VFPSLIDE1       = 0x69, /* ObjType VFP_Platfor */
    MAP_ID_VFPSLIDE2       = 0x6A, /* ObjType VFPLavaBloc */
    MAP_ID_DRPUSHCART      = 0x6B, /* ObjType DR_PushCart */
    MAP_ID_DRLIFTPLAT      = 0x6C, /* ObjType DR_Platform */
    MAP_ID_DIM2STONEPILLAR = 0x6D, /* ObjType DIM2StonePi */
    MAP_ID_BOSSDRAKORFLATR = 0x6E, /* ObjType WCPushBlock */
    MAP_ID_WCBOUNCYCRATE   = 0x6F, /* ObjType WCBouncyCra */
    MAP_ID_WCPUSHBLOCK     = 0x70, /* ObjType WCPushBlock */
    MAP_ID_WCTEMPLELIFT    = 0x71, /* ObjType WCMoonTempl */
    MAP_ID_KAMCOLUMN       = 0x72,
    MAP_ID_DBSTEPSTONE     = 0x73,
    MAP_ID_VFPPUSHBLOCK    = 0x74, /* ObjType VFP_Bobbing */
} MapId;
```

```c
/* MAPINFO.bin per-record map type (curMapType / getCurMapType(), shader.c). */
typedef enum MapType
{
    MAPTYPE_NORMAL        = 0, /* normal outdoor map */
    MAPTYPE_SUBMAP        = 1, /* normal submap (dungeon/indoor) */
    MAPTYPE_UNLOAD_UNUSED = 2, /* unused: unloads all objects immediately on load */
    MAPTYPE_SUBMAP_UNUSED = 3, /* unused: same as MAPTYPE_UNLOAD_UNUSED; only frontend2 has this */
    MAPTYPE_NO_HUD        = 4, /* hides PDA HUD; title screen + Arwing maps; no player object spawned */
} MapType;
```
