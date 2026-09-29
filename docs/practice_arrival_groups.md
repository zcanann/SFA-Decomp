# Practice warp entry groups (EN v1.0)

Practice warps enable a small, map-wide baseline of object groups at committed
reload, before destination objects are instantiated. Browsing presets has no
side effects. Ordinary/scripted warps retain retail behavior. The setter is
`SaveGame_gplaySetObjGroupStatus`, so saved bits, cached masks and aliases follow
the same path as the Flags menu.

This pass covers entry boundaries and landing setup, with explicitly audited
room defaults for Ocean Force Point Top.
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
| Ocean Force Point Top (50) | 20, 21, 23 | `linkj#25 +`; audited `dfptop` room groups below |
| Shop (51) | 0, 5, 6; also Thorntail group 11, clear Thorntail group 0 | `shop_update`; `hollow#304/858/859/862` entrance/exit corridor |
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

### Ocean Force Point Top room defaults

The link entrance only enables group 20. Direct warps bypass the interior
transitions: `dfptop#111` toggles groups 20/21 (opcode 0x22), while
`dfptop#112` enables/disables group 23. Applying only the link default leaves
the electric-floor room and fuel-cell area empty.

Practice arrivals now also enable group 21 (SharpClaw controllers, lightning,
floor bars and wall flame barriers) and group 23 (fuel cells and the adjoining
room contents). The generator verifies representative placements 204, 206,
221, 224 and 254 against the original disc's object names and group fields.
These are explicit practice room defaults for all OFP Top presets,
not a claim that all three groups are simultaneously enabled on every retail
entry. No toggle commands, puzzle-completion flags, collection flags or acts
are replayed; normal room triggers can subsequently change the groups.

The menu retains WARPTAB 115 first, inserts `Tile Puzzle` at
`(3371.50684, -1620.93994, -8013.62842)` second, and names WARPTAB 104
`Warp Pad` third. Both use the same baseline groups 20/21/23. The pad's
flame sources are `CmbSrc` placements 262/263/274/275/276 in group 23;
these are also checked against the disc. A Dolphin probe of Warp Pad found
all five sources and the tile puzzle controller (#243) instantiated. Those
decorative flames do not establish that the shootable puzzle works.
The actual shootable actor is `VFP_statueb` #257, also in group 23; it is
now included in the generator's placement audit. Its activation bit is
`OFPTOP_WarpEnabled` (0xD6C), shared with the pad's `Transporter` #117.
Its update stops accepting shots once that bit is set. The earlier memory
capture contains #257 at `(3376.734, -1499.123, -9249.774)` with bit 0xD6C
clear and its active state clear. That is about 498 units east of the pad,
outside the original screenshot. This establishes actor presence, not a
completed shooting test. Evidence is in `build/practice/ofpt-pad-check/`.

### Shop and Thorntail exit

Shop warps initialize its groups 0/5/6 before objects update, matching the
retail `shop_update` initialization. They also enable Thorntail group 11
and disable Thorntail group 0. The shop's exit is not wholly owned
by `swapstore`: `hollow#304` enables group 11 on approach, `hollow#858` in
that group loads shop directory 16, and `hollow#859` switches between map
layers in either direction. Bypassing that approach can leave the return
path without its triggers. `hollow#862`, also in group 11, clears Thorntail
group 0 on the entry leg (`0A140000`) and restores it on exit (`05130000`).
The old direct warp retained that group, including outside SharpClaws which
could fall into the shop. Thorntail and its lower map share the group bank.

The fix applies those entry group changes at committed practice arrivals. It preserves the
Thorntail act, purchase/first-visit bits, other saved groups, and normal warp
behavior. The existing retail asset loading already produced both directory
12 (Thorntail) and 16 (shop) in a fresh-boot Dolphin probe; no additional bank
override is needed. A successful room load alone does not establish that all
shop cutscenes or the exit work; keep runtime findings separate from this
static entry-path evidence.

A subsequent Dolphin probe seeded Thorntail group 0 and act 2 before the shop
warp. The arrival retained Thorntail group 11, cleared group 0, and contained
all three exit planes (#858/#859/#862) with no Thorntail group-0 actors.
The shop rendered with its shopkeeper and both directory banks loaded.
Evidence is in `build/practice/shop-entry-check/`; that probe did not walk
the full exit route.

### Magic Cave return context

Each preset records the entrance actor's placement ID and group as well as its
reward, act, source map, and return warp. Retail `MagicCaveTop_update` lets the
first loaded entrance consume `MC_IsExiting`, without checking distance or
origin. During a practice cave return, its wrapper reserves that flag for the
selected entrance. Ordinary cave trips use the original callback unchanged.
The well preset is named `TTH Well - Rocket`.

Direct exterior presets now use the same exit sequence. The catalog links all
nine exterior WARPTAB arrivals to their entrance context: TTH Fire Blast,
Mana Shrine and Egg Room (the Portal Device return point), Rocket Shrine,
Snowhorn Mana Shrine, Cape Claw Mana Shrine, VFP Freeze Blast Exit, MMP's
shrine arrival, and Walled City Mana Shrine. Negative `PracticeWarpSpawn.cave`
values identify exterior exits; positive values still select cave interiors.
Only a committed, unedited preset arms the exterior handoff. Editing the warp
position skips the animation, which would otherwise move Fox back to the shrine.

The selected entrance's update arms `MC_IsExiting` immediately before the retail
callback starts its sequence. Other entrances cannot consume the handoff, and
an interrupted warp cannot leave a synthetic exit flag in the save. Entrance
groups and the well's auxiliary bank are restored by the existing return path.
No spell, mana upgrade, or shrine-completion bit is granted. Compiled regression
coverage checks all nine destinations, one-shot consumption, wrong-actor
rejection, and edited-position cancellation.

Isolated Dolphin probes in `build/practice/shrine-{tth-mana,fire,portal,well,vfp}`
recorded the retail exit sequence (5), consumed the handoff and cleared the fade.
The well subsequently showed the normal first-discovery planting-patch dialogue
on the fresh synthetic save. These checks do not suppress unrelated story scenes.

The return hook recognizes the expected WARPTAB index, source map 54, and exit
flag. It restores destination arrival groups and the selected entrance group.
The well additionally queues directory 19 alongside Thorntail's parent bank;
loading only the parent omits the well's assets. Snowhorn, VFP, Cape Claw and
Walled City receive their existing map-wide arrival defaults on return.

MMP enables group 2 for the life-force doors without newly enabling key-door
group 1. Group 2 also contains the rolling cave door, so the practice return
omits only placement ID `0x4B3F0`, object `0x825`, in map 18. All other object
creation calls pass through unchanged. Existing group-1 progress is preserved.
An unrelated reload clears the return context and the door omission.

### Ship Battle combat arrival

The `Combat` preset selects Krystal, sets staff-acquired bit `0x75` to skip the
opening sequence, selects act 1, and disables the later on-deck group 2.
The character selected before entering is restored on the next practice warp
elsewhere; a repeated battle warp retains that original selection. Coordinates
are copied to the newly selected character because the reload hook runs after
the normal position commit.

Once the player, SB CloudRunner and Galleon exist, setup reproduces the
CloudRunner branch of `player_SeqFn` event 3: vehicle focus, riding move `0x7B`,
move-sequence 1, state `0x18`, and camera `0x4A`. It runs once, leaving retail
vehicle controls and combat updates in charge. The ship starts at its first
flight target relative to the bird, avoiding the cinematic approach delay.

Retail opening sequence 105, curves 474/478 in `shipbattle/ANIMCURV`, supplies
environment actions `0x85`, `0x83`, `0x82`, `0x94`, then `0x84`. Applying these
at arrival restores the sky, weather and moving clouds instead of inheriting
the previous map's environment. Clouds are enabled and lights retain the
Galleon initializer's disabled setting. Normal new games never arm this hook.

A private Dolphin capture in `build/practice/ship-combat-b-capture` shows the
mounted Krystal, combat camera, storm and incoming ship fire, with frames
advancing and no active sequence. This checks the combat arrival; completing
the entire fight and subsequent deck sequence remains untested.

Isolated Dolphin checks also reached the well exterior with banks 12/19 and
advanced beyond the fade. TTH magic-upgrade and portal returns selected their
own entrance actors. A serial fresh-save probe later crashed on the well
return after several TTH cutscenes; the isolated well check did not reproduce
that crash. These probes synthesize arrival state and do not establish that
every save's active story cutscenes are safe. The shop cutscene-void issue is
left aside at the user's request; its group repair is not a cutscene fix.

Additional isolated return probes reached Snowhorn, VFP, MMP and Walled City
with fades cleared and advancing frames. Saved group masks were respectively
`0x3`, `0xE`, `0x02000005` and `0xC23` after retail updates. MMP's rolling door
was absent. These checks restore entry groups without suppressing unrelated
fresh-save item-discovery or story cutscenes; their screenshots are not claims
that those cutscenes have all finished. Evidence is under
`build/practice/cave-cold-b-{5,7,8}` and `build/practice/cave-wc-final`.

### Dragon Rock practice positions

After the retained `Arwing Landing` entry, Dragon Rock Top offers these named
custom positions in the requested order, on layer 0:

| Spawn | X | Y | Z |
| --- | ---: | ---: | ---: |
| Earth Walker Barrel | -16170.6943 | -1406.93994 | 13305.6621 |
| High Top | -16116.4424 | -1632.93994 | 12628.3105 |
| Post High Top | -17069.1855 | -1632.93994 | 9946.83105 |
| CloudRunner | -16982.3438 | -1647.93994 | 8530.29395 |

Each custom preset queues `PRACTICE_WARP_SKIP_DR_ARRIVAL`. At committed arrival,
before object initialization, it sets `GAMEBIT_DR_FlewTo` (`0x9E9`) to 1.
This is the completed/open bit on `dragrock#715` LandingPad_, placement
`0x451BA`; the retail flight clears it to arm the landing sequence. The
original landing preset and ordinary scripted travel retain normal behavior.
The separate weather-initialization bit `0xE7B` is preserved. Existing
map-wide groups 15/16 are restored without clearing other saved groups.

The CloudRunner preset additionally enables groups 2 (cage and side area)
and 12 (CloudRunner). The generator validates `dragrock` placements 538,
564 and 628; a Dolphin probe confirmed all three actors instantiated after
this warp (`build/practice/dr-cloud-check/actor-audit.json`). This does not
reset cage completion or mount progress. Dragon Rock Bottom's sole arrival
is named `Entrance`, as is the Shop's arrival.

The generator validates all four positions against Dragon Rock's occupied
map cells. PPC tests check exact target-float coordinates, queued-only writes,
all four arrival flags, weather/group preservation, and ordinary travel.

### Great Fox scene presets

Great Fox has one retail arrival, WARPTAB 127, reused by two scenes. The
practice menu exposes it as `Opening Briefing` (act 1) and `Ending / Credits`
(act 2). Retail `Landed_Arwing` sequence events 7/0x66, placement `0x4CD65`,
warp to 127 and set Great Fox map 65 to act 2. The `greatfox` romlist contains
separate `GF_sequence` placements `0x46DE0` and `0x48133`, restricted to acts
1 and 2 respectively. The level controller's credits event starts the credit
roll and warps to the title sequence; this is not a second physical room.

Named spawns now optionally carry an act override. Zero keeps the current
act; a nonzero override is queued with the destination and applied only at a
committed practice arrival, before actors load. Changing the menu selection
after requesting a warp cannot change that queued scene. Ordinary scripted
travel preserves its own act selection. Both Great Fox presets retain the
existing Palace asset-bank setup.

Isolated Dolphin captures under `build/practice/greatfox-scene-{0,1}` reached
both scenes with a cleared fade and advancing frames: briefing sequence 1219
and ending sequence 1258, respectively. The ending scene's entire playback
through the subsequent credits was not timed to completion. Targeted PPC
tests check queuing, committed-only act changes, Palace-bank retention and
ordinary-warp preservation; patch-integrity and disabled-build checks pass.

### Named room arrivals (TTH, Snowhorn and VFP)

Room groups are now optional per-spawn metadata, queued together with the
destination. They are enabled at the committed practice reload, before actors
load. Existing groups, map acts and story bits are preserved; normal or
superseding scripted warps do not apply these additions. The generator checks
representative actor names and group membership against the verified disc.

| Map | Presets in menu order | Added room groups |
| --- | --- | --- |
| VFP Top | Entrance; Freeze Blast Exit; Central Room Bot; Central Room Top; Spell Stone Room | none; 3; 6/8; 6/8; none |
| TTH | Arwing; Egg Room; Warp Stone; Mana Shrine; Fire Blast | none; 7; none; 8; none |
| TTH Bottom | Rocket Shrine; Lantern Well | 31; 25 |
| Snowhorn Wastes | Mana Shrine; Krazoa 4 Shrine; Garunde; Post BribeClaw | 1; 3; 4/5/8/12; 4/7/8 |

These supplement the map-wide entry defaults. VFP's room transitions include
`temple#283` (groups 2/3), `#4` (6/8/11), and `#3/#11` (8).
Group 3 contains the Freeze Blast entrance `#510` and its corridor objects;
6 contains the central doors and 8 the central lava platforms/crates. The
Spell Stone room's transporter and principal objects are ungrouped. The link
map retains its normal automatic loading behavior.

TTH `hollow#50/#51` load/unload Egg Room group 7, containing the egg challenge
actors (`#817/#822`); `#275/#274` load/unload Mana Shrine group 8 (`#853`).
The well's `hollow2#11` switches groups 25/31; Rocket Shrine's entrance is
`#153` in 31, while Lantern Well's mushrooms/fog are in 25. Both well
presets explicitly request directory 19 alongside the Thorntail parent bank.

Snowhorn `wastes#11` enables Mana Shrine group 1; `#14/#22` enable Krazoa
area group 3. The westward approach `#13` enables 4/8/12 and `#54` adds 5,
which owns Garunde Te (`NW_mammothg`, `#588`) and the ice prison (`#664`).
The post-BribeClaw corridor uses 7 (`#3`), with the near-side 4/8 objects
retained until `#49`. Its preset also queues LinkC directory 65, the same
bank loaded by `wastes#28` command `05 27 00 41`; LinkC's parent is Snowhorn.
It does not bypass the bribe or change Garunde's quest flags.

The added positions are the user-supplied coordinates, validated against
occupied map cells. PPC tests cover all 16 named presets, their retail/custom
arrival IDs, coordinate precision, queued selection, bank selection, high
group bit 31, preservation of unrelated groups/acts, and superseded warps.

Candidate `build/practice/named-room-spawns-a.iso` has a 62,176-byte payload.
Patch verification confirms all disc bytes outside the new DOL and its header
pointer remain identical. The original ISO is unchanged. Payload regressions,
patch-integrity checks and disabled-build checks pass.

Isolated Dolphin captures in `build/practice/room-check-*` cover VFP Freeze
Blast Exit, both TTH room fixes, both well presets, and Snowhorn Mana Shrine,
Garunde and Post BribeClaw. All eight loads clear the fade and advance frames.
Actor inspection confirms the VFP cave entrance, TTH eggs and mana entrance,
both well groups, Snowhorn's mana entrance, and Garunde Te with the ice prison.
Post BribeClaw retains banks 14/65; both well presets retain banks 12/19.
Screenshots show rendered environments rather than empty voids for VFP, the
well and Snowhorn. The fresh-save TTH tests enter the existing arrival cutscene,
so their actor checks do not establish restored player control afterward.
Rocket Shrine also triggers the ordinary first-discovery planting-patch
dialogue. No route completion or all-save-state guarantee is claimed.

### Krazoa Palace named arrivals

Palace map 11 now lists `Krazoa 1`, `Krazoa 2`, `Krazoa 3`, `Krazoa 4`,
`Krazoa 5 Arwing`, `Krazoa 6`, then `Krystal`. Their retail warp IDs are
40, 32, 34, 34, 78, 65, and 6 respectively; coordinates/facing are unchanged.

`LinkALevControl_seqFn` explicitly selects act 2 and groups 5/6 for Krazoa 2,
act 3 and groups 8/9 for Krazoa 3, and act 4 with the same groups and position
for Krazoa 4. Separate presets preserve this distinction. The generator
verifies `warlock#367/#377/#384` and `#407/#408/#424/#458` as representative
actors in those groups. Only positive group additions are applied; the retail
route's whole-bank reset is deliberately omitted to retain existing progress.

Krazoa 1 uses act 1 and its local group 3, verified by the act-1 door placements
`#227/#231`. Krazoa 5 Arwing uses act 5 (the `Landed_Arwing` 0x451B9 arrival)
and roof groups 10/11 (also the Arwing course's Palace setup). Krazoa 6 uses
act 6, which `WM_spiritpl` checks for its sixth release interaction, with the
same roof groups. Krystal uses the original opening position, act 1 and local
groups 0/1. The approach planes toggle 0/2 (`warlock#60`), then 1/3/5
(`#75`). Preloading group 3 made the second crossing unload the dinosaur,
column and doors. The preset now clears far-side groups 2/3/5 before arrival,
including when revisiting from a different Palace preset.
This preset does not switch the player character. No spirits or quest
completion bits are granted. Actor-local story gates still apply.

The earlier Dolphin actor audit only established that placements 227/231,
232 and 234 existed immediately after arrival; it missed their subsequent
unloading at the approach trigger. It is not evidence of a working walk-in.
The corrected preset was checked by moving Fox through both retail boundaries
in an isolated Dolphin session: saved mask `0x3 -> 0x6 -> 0x2c` and `0x2c`
still resident at the injured dinosaur. See `palace-route-check-b/route.json`
and its screenshot under `build/practice/`. This uses Free Move to cross the
planes; it is not a complete normal-collision route playthrough.
K5's rearmed landing
started the Palace arrival cinematic without setting the carried-spirit bit.
The longer capture (`build/practice/palace-k5-long`) advanced 1,134 frames,
showed Fox after the arrival, and had `joypadDisabled` and `timeStop` clear.
The capture still showed cinematic framing; it does not establish that all
following dialogue and camera sequences finish on every save state.

The compiled queuing regression covers all seven presets, group preservation,
retail IDs and act selection, including changing the menu before the pending
warp commits. Patch-integrity and disabled-build checks pass.

Candidate `build/practice/palace-spawns-a.iso` was checked in isolated Dolphin
sessions for K2, K3 and K4. Screenshots show rendered rooms with the player at
the transporter. Runtime inspection confirms acts 2/3/4 respectively, K2's
groups 5/6 (11/23 placed actors), and K3/K4's groups 8/9 (10/44 actors each),
including the transporters, fire-hole controller and rising column. Captures
and actor audit are under `build/practice/palace-{check-1,recheck-2,recheck-3}`
and `palace-runtime-audit.json`. These checks cover arrival, not completion of
the spirit-release routes. The other four presets were checked by catalog
validation and compiled tests, not a new Dolphin playthrough.

### CloudRunner Fortress and Walled City arrivals

CRF now lists Arwing Arrival (WARPTAB 99), Race Ladder (74), Post Jail, and
Exterior. The last two use the supplied coordinates. Race Ladder adds group 1:
`fortress#483` sets the race-entry signal 0xD65 and `#484` is its sequence
actor. Post Jail adds groups 6/7 and dungeon directory 24 (map 16), matching
the nearby loading plane `#276` and the group-7 boundary `#34`. Exterior adds
only 19/27: the doorway/wind-lift corridor and adjoining exterior courtyard.
The upper back exit `#42` toggles interior group 7 and enables 27; `#309`
disables 27 on the return leg. The exterior preset clears front-arrival 0,
race-access 1, rooftop 5/8 and interior 7, including stale saved residency
from earlier practice warps. Other saved groups are retained. Representative
actors are asserted in the generator.
This restores room residency without solving the area's puzzles or freeing
prisoners. Non-Arwing presets mark the pending CF landing complete (bit 0x212,
the open bit in `CFLandingPa` placement 0x43091) before actors initialize.

Walled City's five retail positions were obscured by its unconditional pending
landing sequence. Their actual identities, in the new order, are:

| Preset | WARPTAB | Reference |
| --- | --- | --- |
| Arwing Arrival | 120 | `wallcity#438/#439`, landed Arwing and landing controller |
| King Earth Walker Top | 19 | `#498`, king's position (act-2 actor) |
| King Earth Walker Bot | custom | supplied lower position |
| Mana Shrine | 21 | `#364`, MagicCaveTo |
| Upper Shrine Pad | 70 | `#40`, Transporter |
| King Red Eye Gate | 91 | group 4, sun/moon and T-Rex statue room |
| Moon Temple | custom | supplied position; same group 4 |
| Sun Temple | custom | supplied position; same group 4 |
| Walled City 2 | custom | same position/facing as Upper Shrine Pad, act-2 override |

The ordinary presets preserve the current act; Walled City 2 selects act 2.
`DFPSpPl_update` sets this act after accepting the second water SpellStone.
The upper transporter is restricted to act 2; its map layer stays 0. At the
user's request, Walled City 2 now shares Upper Shrine Pad's position/facing
instead of the nearby setup point. This can enter the pad's normal arrival
cinematic; the updated on-pad arrival has not been Dolphin-tested. No
SpellStone inventory/completion flags are granted. The temple preset adds its
local group 4; all retain the existing City arrival baseline. Non-Arwing
presets set 0x818, `WC_LandingP` placement 0x451BA's completed/open bit, before
actors load. Weather-initialization bit 0xE05 is left alone.

Compiled tests cover the exact new coordinates, ordering, destination IDs,
group masks, dungeon bank, act override, preservation of existing groups,
and arrival suppression only at committed non-Arwing practice warps. Ordinary
and superseded warps do not consume stale landing flags. Patch integrity and
the zero-code disabled build pass.

Isolated Dolphin checks show rendered, advancing gameplay at CRF Race Ladder,
Post Jail and Exterior, and Walled City's Mana Shrine. Actor inspection confirms
the selected room groups and Post Jail's dungeon bank. Exercising the race-entry
signal 0xD65 loads race directory 50 alongside fortress directory 18. Captures
and actor counts are under `build/practice/crf-wc-{check-12-1,recheck-12-2,
recheck-12-3,recheck-13-2}` and `crf-wc-runtime-audit.json`.

The first Walled City 2 candidate landed directly on the transporter and started
its inbound sequence 98, producing an unsuitable arrival camera. Candidate
`build/practice/crf-wc-spawns-b.iso` uses the nearby setup point instead.
`build/practice/wc2-offpad-check` confirms act 2, the upper transporter present,
Fox standing at the requested position, normal HUD, rendered surroundings and
no inbound sequence 98. These are arrival checks, not full route playthroughs;
King EarthWalker and King Red Eye Gate have catalog/compiled coverage but were
not separately exercised in Dolphin during this pass. The original ISO is
unchanged; the generated image differs only in the new DOL and its header pointer.

### Moon Mountain Pass and location names

MMP lists Ground Quake Shrine (WARPTAB 16), Meteor Event (supplied position),
Krazoa 2 Shrine (64), then Scarab Well (supplied position). The meteor preset
loads group 5 (`moonpass#554` crater controller and `#557` meteor object),
without resetting the event's story flags. K2 and Scarab Well both load group 8:
this contains transporter `#679`, with no enable-gamebit gate, the shrine
effects, vines and well-side basket `#659`. Group 8 is enabled on the natural
approach by `#30`/`#388`. No shrine completion or spirit inventory is granted.
Ground Quake retains its existing exterior-cave animation and life-force door
group behavior.

CloudRunner Dungeon retains both identical-position retail IDs, named
`Entrance (0)` and `Entrance (12)`. LFV's ordinary first destination is named
`Intro Totem Area`; naming a location does not itself reset story progression.
The separate `Intro Totem Event` uses the same retail warp 80, act 2 and group
2. It reproduces `SC_levelcon`'s captured-arrival state (captured bit 0x2B5
and warp latch 0x4D0 set, entrance group 1 off), clears escaped 0x2D0 and
minigame completion 0x2BC, and rearms the ring/orb bits used by `SC_totembon`.
Tracking/strength records and completion are retained. These story edits occur
only when this event preset commits with its original position and act 2.
The ordinary area preset and edited coordinates do not reset these flags.
An isolated Dolphin prototype reached the tied-to-the-pole opening dialogue;
see `build/practice/lfv-event-check/map-014-spawn-01.png`.
The final build was also exercised with escaped/completion and all ring/orb
bits initially set. It rearmed the opening sequence and advanced 1,221 frames,
with the LightFoot/Fox conversation still playing at capture. This verifies
event startup, not completion of the interactive escape challenge. Final
captures and the CRF/MMP actor audit are in `build/practice/refinements-final-check`.
CRF has groups 19/27 and their representative actors, without race placements
483/484 or rooftop/interior 506/536/580/695/714/715. Both MMP K2 and Scarab
Well have transporter 679 and well-side basket 659; K2 plays arrival sequence
98. These are focused arrival checks, not complete dungeon playthroughs.

### DarkIce Mines Top presets

The requested twelve destinations retain the supplied order and coordinates.
Arwing Arrival keeps retail WARPTAB 119 and explicitly clears landing-complete
bit 0xA82; all eleven custom locations suppress the pending landing instead.
The custom room additions are:

| Preset | Groups | Representative placement evidence |
| --- | --- | --- |
| Gate Entrance | baseline | lava approach |
| End of Lava | 1 | bridge 555, SnowHorn 561; entry plane 61 |
| Flame Mammoth | 1/5/8 | lever 634, bridge 637, dismount 676; planes 20/402 |
| Alpine 1 | 6/8 | ground animator 644, alpine root 645; plane 21 |
| Alpine 2 | 3 | ice wall 615, alpine root 621; plane 119 |
| Post Big Gate | 7/9/18/20 | gate 683, cannon 663, CannonClaw 795, hut doors 802/803; planes 22/23/36 |
| Cannon | 7/18 | cannon 663 and CannonClaw 795 |
| Fire / Leap of Faith | 16 | wood door 764, magic bridge 769; plane 26 |
| Cog 3 / Mammoth 2 | 10 | alpine root 701, treasure chest 707; plane 15 |
| Post Blizzard | 12/21 | door 734, dismount 732, log fire 805; planes 720/721/381 |
| Bike | 12/14/21 | bike 740, crate 814; planes 24/392 |

These are curated residency additions validated against retail placements,
not a simulation of every intervening story event. Existing quest flags and
other room groups are retained. Generator assertions validate all positions
against map 19 and verify representative object/group assignments.

Warp catalog link/act/flags/bank fields now use bytes, with generator bounds
checks, saving four bytes per destination while retaining the existing 64 KiB
payload reservation and original game addresses.

OFPT Bottom's order is Entrance (105), Spell Stone 2 Warp (75), Spell Stone 4
Warp (76), Spell Stone Room (113), and Spell Stone Room (114). Both room
positions are retained with their original arrival IDs and behavior; the
numeric suffix distinguishes the version without an arrival animation.
OFPT Top's first destination (115) is named Entrance.

The final DIM runtime check visits all eleven custom positions sequentially
with ordinary physics, preserving groups from earlier warps. Each loads
rendered terrain, advances frames and remains near its supplied position.
Flame Mammoth shifts roughly 40 units during the settled capture; the other
ten remain within 0.2 units. Screenshots and positions are under
`build/practice/dim-spawns-check`. These are arrival checks, not completed
room/puzzle tests or independent clean-save tests for each destination.
The rearmed Arwing landing clears then sets 0xA82, but this test save has no
Tricky and falls into the game's respawn path. The user confirmed that this
is expected without Tricky in the party; the preset preserves party state.

Validation for this batch: 71 compiled PPC payload tests, 10 patch tests,
format checks, and clean-input/all-other-disc-bytes-identical verification.
CRF's additional stale-residency check explicitly seeds groups 0/1/5/7/8;
the saved mask after Exterior arrival is exactly `0x08080000` (19/27).

### Cape Claw act presets

`Cannon Act 3` follows Cannon at the same position and selects act 3. The
retail `capeclaw#649/#650` ExplodePlan mouth panels and `#750` HitAnimator are
present in act 3, while the `#481` CannonClawO enemy is restricted to act 2.
The cannon itself, `#575` DIMCannon (placement 0x460BD), is in baseline group 1.
The act-3 entrance plane `#26` sets 0x142 and 0x1EC (`02124142 021241ec`).
The practice act-3 preset applies these at committed reload as well: 0x1EC is
the cannon's reset bit and selects its usable WAIT_FOR_RESET state at init.
It does not reset already-destroyed panels or grant Portal Device.

`Disguise Door Act 2` follows Gas Room Switch at
`(3358.5166, -1398.93994, -4058.07812)` and selects act 2. The nearby trigger
`#48`, sideload `#435`, and disguise-era actors use that act. It does not grant
Disguise. Normal Cannon and other unqualified presets retain the current act.
Compiled queued-warp checks cover both act overrides and cannon activation,
including leaving inventory bits and unrelated saved object groups untouched.

### Pending Arwing arrivals on practice travel

Committed practice warps now suppress pending landing sequences by marking the
appropriate arrival complete before destination actors initialize. The bit must
be **set**, not cleared: `SeqObject_init` uses the placement's `openGameBit` to
select its completed state.

Non-dungeon destinations, including Ice Mountain and Thorntail itself, set
`GAMEBIT_FlewToPlanet` (0x956). Both Thorntail landing placements, `hollow#554`
SH_NT_Landi (0x44CB9) and `#555` LandingPad_ (0x43664), use this bit. This also
prevents a later normal return to Thorntail from replaying the pending arrival.

The four Arwing dungeon families finish their own arrival instead:

| Area | Arrival bit | Covered submaps | Preserved main arrival |
| --- | --- | --- | --- |
| Dragon Rock | 0x9E9 | Bottom, Drakor | Top WARPTAB 121 |
| CloudRunner Fortress | 0x212 | Dungeon, Race, LinkI | Fortress WARPTAB 99 |
| Walled City | 0x818 | T-Rex | City WARPTAB 120 |
| DarkIce Mines | 0xA82 | Bottom, Galdon, LinkD | Top WARPTAB 119 |

DIM's `snowmines#3` LandingPad_ (0x46EB6) supplies its arrival bit. The other
landing placements are recorded above. Main arrival presets preserve the current
bit value, rather than forcing an already-completed landing to replay. Edited
positions use arrival 128 and suppress the landing even when based on that preset.
Palace additionally finishes its own 0xD37 landing except at the named Krazoa 5
Arwing preset (WARPTAB 78), which explicitly clears it to replay the arrival.
Its placement is `warlock#462` KPLandingPa (0x4807C): open bit 0xD37 and
trigger bit 0x95 (`Always1`). `SeqObject_update` starts the landing while the
open bit is clear. Carrying K5 (0xC85) selects the Palace destination in
`arwarwing_warpByCourse`, but is not this landing controller's trigger; the
practice preset preserves that inventory bit.
Weather flags, destination unlocks and unrelated dungeon arrivals are unchanged.

The compiled regression covers cleared and already-complete flags, dungeon
submaps, main-arrival exceptions, and rejection of ordinary/superseded warps.
Menu browsing alone never changes these flags.

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

## Galdon gut arrival and boss ordering

Boss browsing follows Galdon, CloudRunner Race, King Red Eye, Drakor and Scales.
Galdon's preset order is WARPTAB 92 (`Entrance`), 30 (`Gut`), 29
(`Entrance (29)`) and 54 (`Entrance (54)`). King Red Eye retains arrivals 90
and 109, both labeled `Entrance` with their IDs; single boss arrivals use
`Entrance`.

The Galdon Gut preset enables only its additional object group 2. Retail
`snowmines3#46` is the cavity model, #47 its wave animator, #54 the tonsil,
and #55–57 the moving gut targets; all are in group 2. The generator validates
the cavity, wave animator and tonsil placements against the original disc.
The committed-arrival test verifies the group addition while retaining other
saved groups and the map act. A Dolphin probe rendered the interior and found
all these actors loaded; see `build/practice/galdon-gut-check/`. Full combat
and the exit sequence from this direct arrival remain untested.

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
The OFP Top regression checks both acts, restoration of groups 20/21/23,
preservation of an existing puzzle group, and absence of unrelated bit writes.
Runtime playtesting of all entry defaults remains outstanding.
