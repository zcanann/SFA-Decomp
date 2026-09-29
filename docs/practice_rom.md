# EN v1.0 practice ROM v1.15

This experiment lives on `practice-rom`, based on `main`, in its own worktree.
It builds a retail-DOL payload independently of the matching decomp link.
The first supported input is a clean US/EN v1.0 (`GSAE01`, revision 0) ISO.
V1.15 repairs Dragon Rock Bottom's stripped light-object DLL, adds LinkA route
presets, and supplies the missing Palace resource bank for Andross flight and
Great Fox. See [the recovery notes](practice_map_recovery_v1_15.md) for evidence,
screenshots and remaining limitations. V1.14's named spawns, entry groups and
Magic Cave contexts remain included.

## Controls

- **L + R + D-pad Down:** open/close the practice menu (controller 1).
  Release Down before toggling again; there is no time cooldown. A shoulder
  dropping out or a skipped controller poll cannot retrigger the same press.
  The opening/closing gesture is consumed until Down is physically released.
- **L/R inside the menu:** previous/next tab, wrapping at the ends. Draw
  is first, followed by Cheats, Warp, Flags, Log and Debug. Z is unused. Analog press and digital click count as
  one shoulder press; holding a shoulder does not repeatedly switch tabs.
  Tab edges use physical input history, so a skipped controller poll cannot
  turn the menu's cleared gameplay input into a false release/repress.
- **D-pad Up/Down:** select a row; hold to repeat.
- **A:** toggle its checkbox. Enabling a group expands it; disabling hides its
  children without resetting their values.
- **Right/Left:** expand/collapse a group. Left on a child returns to its parent.
- **Left/Right on numeric rows:** change water height, draw distance, or hover cadence.
- **B:** close. **X on the Cheats tab:** reset water to the player's Y + 40.
- **With Auto-Shield Hover enabled:** hold X + R to run the cadence; release either to stop.
- **With Auto Roll enabled:** hold X for roll, configurable blanks, shield, repeat.
- **Warp tab:** Left/Right edits category, map, spawn, position, layer, facing or step.
  Selecting a map/spawn restores its preset. Select **Warp Now** (fourth row, below Spawn) and press **A** to travel.
  **Overworld** follows TTH, Well, Shop, Ice Mountain, Snowhorn, MMP, VFPT,
  LFV, Cape Claw and OFPT exterior/interior, with connecting paths interleaved.
  **Dungeons** groups DIM, CloudRunner, Walled City, Dragon Rock Top and Krazoa Palace;
  LinkD sits between DIM Top/Bottom.
  **Bosses** follows Galdon, CloudRunner Race, King Red Eye, Drakor and Scales.
  **Outer Space** follows Orbit (World Map), DIM, CRF, Walled City, Dragon Rock
  and Andross. **Special** contains Ship Battle, Great Fox, WarpStone Maze,
  Shop (also in Overworld), Magic Cave, and LinkA - Warpstone to Others, in that order.
  **Unused** contains Dragon Rock Bottom, Animtest, and LinkI. **Unused Broken** holds
  the remaining legacy maps, including Arwing to Planet.
  Nik Test and Duster Cave stay listed but cannot be selected as warp destinations.
- With Swim Anywhere enabled: **L + D-pad Down** toggles swimming during play;
  activation resets the surface to player Y + 40. **L + C-stick Up/Down** adjusts the
  surface while swimming is active. The menu checkbox only arms the shortcut;
  swimming stays off until L+D-pad Down is pressed.
- With Free Move enabled: **L + D-pad Up** toggles movement override during play.
  The main stick moves forward/back and strafes relative to Fox's facing.
  **C-stick Left/Right** swivels Fox with or without L. **C-stick Up/Down**
  ascends/descends; **L + C-stick Up/Down** pitches instead.
  Infinite Health and Infinite Magic are first on the Cheats tab, then Free Move.
  Free Move's **Invert X** child option defaults
  on and reverses C-stick swivel. Turn it off for the V1.12 swivel direction.
  Moving forward while pitched also changes altitude. The camera
  follows directly behind Fox. The
  menu checkbox only arms the shortcut; the HUD distinguishes READY from ON.

The menu consumes controller-1 input and uses the existing `timeStop` mechanism
while open. This pauses object gameplay; it is not an emulator-wide frame pause.
The normal HUD shows a small reminder of the opening chord.

## Included

- **Collision:** loaded terrain triangles (green), object collision triangles
  (yellow), object hit volumes (orange), water triangles (cyan), and
  **Barriers / Ledges** (coral): the separate HITS.bin and model-line planes.
  These interaction planes include invisible barriers, ledges, and climb aids;
  their presence does not mean every kind blocks Fox in every movement state.
  **Barrier Fill** controls their translucent surfaces independently of triggers.
  Object hit volumes include the primary sphere / vertical-span shape used for
  object-pair collision, including the barrel's body, as well as model hit spheres.
  The vertical-span shape has flat ends, matching the pair test rather than an
  assumed rounded capsule. Inactive primary volumes are gray.
- **Triggers:** crossing planes, rotated boxes, spheres, vertical cylinders
  (pink); optional line between the trigger's previous/current target sample.
  **Translucent Fill** starts enabled, with opaque outlines. Both sides render;
  fill tests scene depth and never writes depth. Disable it for wireframes.
  Disabled triggers have gray fill, outlines, normals and target-motion lines.
  This includes the status bit, disabled hit callback, and an unmet crossing-plane
  game-bit gate. Geometry does not establish
  whether all of its game-bit/command conditions currently permit activation.
- **Fox / Player** collision filters: object body, model hit spheres, feet/floor
  contact, movement body spheres, wall probe spheres, and cached sweep lines.
  These are independent of the generic Object Hit Volumes checkbox and of the
  Collision group: Fox / Player draws with Collision disabled. Movement
  shapes read the active `CurvesCollisionState` and its live radii/counts. Segment
  points are world-space; wall points use the player parent's collision transform
  when parented. A captured Ice Mountain state had a 0.05 ground radius and 8.5
  body/wall radii. The tiny ground sphere gets a center cross; floor results get
  a cross and connecting line. These markers are not additional hit volumes.
  Cached trace endpoints can coincide after the engine copies the resolved point
  back, so this is not a history of all sweeps. Animation foot-effect positions
  are deliberately not represented as collision shapes.
- **Swim Anywhere:** uses the game's deep-water entry path and substitutes a
  player-local water surface/depth. A cyan grid shows that surface. Real map
  water geometry is unchanged. Disabling releases the swim flag and restores
  the real water query. Normal walls and collision still apply. The grid draws
  before other overlays so dense collision cannot exhaust its line budget.
- **Disable Save Integrity Checks:** off by default. During a save-slot write,
  bypasses cached card identity/checksum comparisons. Retail still tries the
  primary block first; if it falls back to a readable backup with a stale
  checksum, the practice hook normalizes that checksum in the working buffer
  so the write can proceed. The normal write routine produces fresh checksums
  and verifies read-back. Card filesystem checks and read/write errors still
  apply. The bypass does not affect loading, deleting or formatting cards, and
  restores the identity-check setting after each write attempt.
- **Auto-Shield Hover** on Cheats: while physical **X + R are held**, emits
  **R (shield), then X (roll)** on
  successive game input frames. **Blanks After Roll** and **Blanks After Shield**
  each accept 0-60 frames, edited with D-pad Left/Right. Each action lasts one
  frame; blank frames release both X and R. At 2 roll blanks and 1 shield blank,
  the repeating pattern is `R, blank, X, blank, blank`. Defaults are 3 roll blanks and
  0 shield blanks. Releasing either button stops and resets the cadence to shield; merely
  enabling the checkbox sends no inputs. Analog R and its digital click both
  count toward the R requirement. The stick and other buttons remain available. The macro stops during
  menus, paused gameplay, disabled input or DVD errors and restarts at shield.
  Turning it off returns X/R to physical input with correct release edges.
  It automates inputs only: height, velocity and animation state are not forced.
  The best cadence and resulting hover behavior still require gameplay testing.
- **Auto Roll:** hold X to send one X frame, 39 blank frames, one R frame, then
  repeat. The gap is configurable from 0 to 120; shield hover takes priority
  while X + R are held.
- **Flags / Log:** categorized state editing and optional Dolphin logging,
  described under **V1.5 changes** below.
- **Warp:** all 117 map IDs are listed in categories. 59 have selectable destinations,
  using retail WARPTAB entries, curated positions, or explicitly marked estimates.
  Estimated positions come from a central placed object plus 50 Y, or an occupied
  block center with Y=0 when no placement is available; adjust them as needed.
  They are not guaranteed safe ground or working entrances. The other 58 IDs
  are unplaced maps, object chunks, or explicitly unavailable destinations.
  The 146 presets use the retail occupied-cell lookup, including overlapping
  maps and signed layers. X/Y/Z, layer, facing byte and position step are editable.
  Warping validates that X/Z/layer still resolve to the selected map and uses
  the retail fade/reload path. Edited positions use unused arrival ID 128 to
  avoid activating an unrelated checkpoint marker. Unedited retail presets
  retain their arrival IDs and therefore their normal arrival events.
  Story flags, map acts and character selection are retained; bosses, Arwing
  stages and unused maps may require suitable progression state.
- **Heap Bars** (Debug tab, off by default): four full-width 10px bars show the game's
  `mm` regions by address, R0/R1 at the top edge and R2/R3 at the bottom. Gray is
  the region's slot table and dark is free. Allocated blocks are coloured by the
  tag passed to `mmAlloc`: a tag above 0xFF is the caller's own RGBA debug colour
  (drawn opaque); a small category id gets a stable hashed colour. Each pixel covers
  1/640 of a region; the first block to reach a pixel owns its colour, and
  allocations smaller than a pixel are widened to one pixel.
  The bars walk each region's address-ordered slot chain every frame, bounded by
  its slot count. The Debug tab lists used/size KB (the region's own counter),
  slots in use, the largest free block and a 32-bit fingerprint per region. Each
  region's fingerprint is also drawn in hex at the centre of its bar.
  The fingerprint mixes each allocated block's address, size and tag (xxHash-style
  rounds and avalanche; not cryptographic). Allocation ids and ticks are excluded,
  so an identical layout reached by a different history hashes the same. Regions
  with per-frame scratch allocations can change every frame; compare while the
  menu is open or at load screens. Opening the Debug tab previews the bars even
  while the checkbox is off. Region 0 can sit under the top TV overscan.
- **Draw Through Walls** and a **250–2500 unit Draw Distance** setting.

Collision and triggers start enabled, with every geometry filter on except
**Terrain Triangles** and **Water Triangles**. Draw Through Walls remains off.
Swimming, free move, infinite health/magic and both roll macros are opt-in.
Logging starts enabled in the current source; Player Stats and Runtime / Action
Flags remain off. Individual filters are independent.
The menu scrolls to keep the selected row visible when every group is expanded.
Rendering is capped at 12,000 lines and 6,000 fill triangles per frame; the menu
reports when a cap is reached. Map collision reserves half the wire budget and
visits the player's block first, then successive rings, across all five layers.
Object drawing visits nearby distance bands before farther objects, so spawn
order does not give distant hit spheres priority over nearby geometry. Cached
model spheres outside draw range are skipped; this is not a complete solution
to stale animation collision buffers following a chunk change.
Only loaded objects/map blocks are visible. Trigger
timers, message-only triggers, curves, and every specialized interaction volume
are not covered by this first viewer. Noclip is not included yet.

V1.2 corrects terrain ranges to use the final polygon-group sentinel and skips
triangles with an empty X or Z collision-cell mask, degenerate triangles, and
water groups that the retail query always rejects. Bounds-based distance culling
keeps large triangles crossing the draw radius even if their vertices lie outside.
Solid group bit 2 remains included: Fox's side-contact query uses mask `0x29`.
These rules follow `trackBuildBlockTriangles`; this is a view of collision
candidates, not the result of a particular live collision query. State-dependent
responses and specialized object volumes still require further coverage.
Barrier endpoint heights follow the signed-byte / signed-16-bit decoding in
`trackSweepCircleAgainstLines`; object lines use the engine's local-to-world
transform. The viewer does not invoke or overwrite the game's collision queries.

### Signpost and remaining collision reports

A read-only Dolphin snapshot captured two `DirectionSi` objects using collision
bank 1. The visible sign scales were approximately 0.4196 and 0.3804, while their
collision matrices had unit scale. Executing the original EN v1.0
`trackBuildModelTriangles` in the PPC harness against the first captured sign
produced 26 triangles with local bounds X [-60, 41], Y [0, 95], Z [-7, 7].
The large sign-shaped overlay agrees with the retail collision mesh; applying
the visible sign's scale would misrepresent that query. This does not imply
every triangle responds to every actor or movement state.

The separate blocker near the lowering Ice Mountain race fence has not yet been
identified conclusively. X-ray did not restore it in the reported playtest.
The new object-level volumes improve coverage, but are not proof that this
specific blocker is fixed. Distant-enemy volumes following chunk changes also
need further runtime investigation.

## Build and apply

The checked-in warp metadata can be regenerated from a clean EN disc:

```powershell
python tools/practice/warp_catalog.py --iso "path/to/clean-EN-v1.0.iso"
clang-format -i include/practice/warp_catalog.h
```

The generator verifies the DOL hash and derives map names, cells, layers and
warp records from the disc. Category grouping and estimated-spawn selection
are practice policy. No original asset files are included in the patch package.

Use the repository's existing GC/1.3 MWCC and PowerPC binutils. The builder finds
them in `build/compilers` and `build/binutils`, including the parent checkout of
a Git worktree. Override with `--compilers` / `--binutils` if necessary. Current
commands use Windows compiler executables; applying an existing patch only
needs Python 3.10+ and this checkout.

From the practice worktree:

```powershell
python tools/practice/build.py build --enable `
  --iso "C:/Projects/SFA-Decomp/orig/GSAE01/Star Fox Adventures (USA) (v1.00).iso" `
  --output "C:/Projects/SFA-Decomp/orig/GSAE01/Star Fox Adventures (USA) (v1.00) (Practice v1.14).iso" `
  --patch "C:/Projects/SFA-Decomp/orig/GSAE01/SFA-EN-v1.0-Practice-v1.14.sfapatch"
```

The `.sfapatch` is a ZIP containing a manifest and the new payload, not a retail
DOL or ISO. Version 2 of the package format identifies the source by the clean
DOL hash, independent of the image's padding or compression. Apply it with:

```powershell
python tools/practice/build.py apply --iso "clean.iso" `
  --patch "SFA-EN-v1.0-Practice-v1.14.sfapatch" --output "practice.iso"
```

The executable transformation is also available without a disc container:

```powershell
python tools/practice/build.py apply --dol "main.dol" `
  --patch "SFA-EN-v1.0-Practice-v1.14.sfapatch" --output "practice.dol"
```

`--dol` is also accepted by `build`. This is the interface for future image
adapters: extract the executable, identify its revision/hash, patch it, and
replace that logical executable in the image. Container format and game revision
are separate concerns. The current image writer accepts uncompressed ISO/GCM;
it does not directly read or edit RVZ, WIA, GCZ, or every Dolphin-supported format.

An RVZ workflow can use Dolphin's conversion tool around the ISO patcher:

```powershell
DolphinTool convert -i clean.rvz -o clean.iso -f iso
python tools/practice/build.py apply --iso clean.iso `
  --patch SFA-EN-v1.0-Practice-v1.14.sfapatch --output practice.iso
DolphinTool convert -i practice.iso -o practice.rvz -f rvz -b 131072 -c zstd -l 5
```

Use new output names and omit `--scrub` to preserve logical disc data. The
conversion command syntax was checked against Dolphin's converter source;
an RVZ round trip has not been tested for this release. Recompression changes
container bytes even when the decoded disc data is unchanged.

Output/patch filenames must be new; existing files are refused. The build writes
its payload ELF, linker map, manifest, and ISO verification report to
`build/practice/`. Boot the resulting ISO normally in Dolphin. Use an in-game
save to reach a practice location; a savestate from an unpatched build contains
the old executable/heap and is not an appropriate way to boot this build.

Without `--enable`, the builder does not define `SFA_PRACTICE`: the C translation
unit emits no symbols, the DOL is identical to retail, and an optional ISO output
is an exact copy. The regular `configure.py`/Ninja build is unchanged. All new
runtime code and declarations are enclosed in `#ifdef SFA_PRACTICE`.

## Memory and patch design

Original text/data/BSS addresses are preserved. The current source replaces 29
verified call instructions: the seven V1.6 calls (both OSInit arena-low setup
calls, controller polling, end-of-frame stub, warp reload, player controls,
surface response), eleven internal save/checkpoint calls, one player update, two
player collision passes, seven player-death calls and one camera load-center call.
Calls go through ordinary PPC EABI C wrappers; game/compiler/SDK routines retain retail addresses.

A new DOL section contains code, constants and explicitly initialized zero-state
at `0x803FA480`, the verified retail default `__ArenaLo`, above the startup stack
at `0x803F8478`. Both OSInit arena-low paths clamp the heap start to `0x8040B480`
before `ClearArena`, protecting a 68 KiB payload region. The retail debug-flag
path originally starts its arena 8 KiB earlier, so that path loses 76 KiB of heap
capacity overall. Arena high is unchanged. No menu/viewer allocations use the game heap.
**The enabled build changes heap capacity and allocation addresses/timing. It is
a practice build, not an SRM-neutral measurement build.** Swimming also deliberately
changes player state. The viewers read collision/trigger data and submit GX draws.

The builder verifies the original DOL SHA-1
`e750e8e894707a52446118a4b84f1b58b677b269`, the hook counts and original bytes,
section/BSS overlap, the apploader's `0x80700000` production load ceiling and
relative branch ranges. It copies the ISO to a new file and replaces the DOL at
its existing offset when space permits. Otherwise it puts the patched DOL in an
unused disc extent and updates only the disc header's four-byte DOL offset.
Apploader bytes, FST entries, assets and asset offsets remain intact. In the
relocation case the original on-disc DOL also remains intact. Read-back checks
compare every byte outside the declared edits and hash the original ISO again.
Input/output ISO hashes are recorded in the build report, not used as the
portable patch's compatibility key.

This EN disc's DOL starts at `0x1E000`, is `0x33DD40` bytes long and is followed
by the FST at `0x35BE00`: only 192 bytes of spare space are available. The payload
needs about 59 KiB. A growing DOL cannot be replaced at that offset without
moving it or other disc structures; this writer moves only the DOL.

V1 failed before game entry because its section at `0x816C0000` exceeded both
the apploader's production (`0x80700000`) and development (`0x81200000`) limits.
V1.1 fixes the placement instead of modifying or bypassing the apploader. Older
version-1 patch packages are rejected by the corrected patcher.

JP, PAL, and later EN revisions need independently verified symbol/hook adapters
and binary hashes. The current tool refuses them; it does not search for vaguely
similar instructions and patch an unknown version.

## Validation and limits

### V1.14 changes

The V1.14 ISO and patch package are in `orig/GSAE01`, alongside the original
and earlier releases. The builder verified that all bytes outside the relocated
DOL and its header pointer remain identical to the clean ISO. The payload is
57,504 bytes within the existing 64 KiB reservation.

V1.14 ISO SHA-256:
`67f071ea4bde8fcaf6c42c60e4a84df51247ed5b27041c55b9ae37c1d772e543`.
V1.14 payload SHA-256:
`6295948d879cf20a008defda7a730120145fab5b271ca717974ba79be95ed6f8`.

The 57-check PPC suite passed for the cave contexts; after the resource-bank
fix, the cave/bank/arrival regressions and all eight patch-integrity checks
passed. Formatting preserved the compiled payload byte for byte.
[The rendered warp audit](practice_warp_audit_v1_14.md) covers all 107 presets
and records remaining failures; these are not all working destinations.

Magic Cave now offers nine named entry contexts using the retail `MagicCaveTo`
placements: TTH Fire Blaster, TTH Magic Upgrade, TTH Open Portal, TTH Staff
Booster (underground), Snowhorn Wastes, Cape Claw, Volcano Force Point,
Moon Mountain Pass and Walled City. Each uses the shared retail arrival point
and sets the entrance's map act, selected cave reward group and return-warp
bit. It also retains the source area's resource bank for Fox's model.

The context is captured when the warp is requested and applied only when that
request commits. Groups 0-5 select mutually exclusive cave rewards; stale
selections from a previous practice visit are cleared without a transient
group-unload delay. Other groups and collected-reward bits are preserved.
The exit-in-progress bit is cleared on entry; Walled City's entrance also
clears its retail cave-entry state bit. Ordinary warps are unchanged.

Rendered Dolphin captures exposed a fallback Fox model when only the cave's
bank was loaded. Retaining the entrance bank fixed this in the repeated TTH
Fire Blaster and Magic Upgrade captures. The compiled-PPC regression exercises
all nine contexts, return IDs and resource banks, including changing menu
selection after a warp is queued. This validates stored return state; it does
not yet constitute an in-game interaction test of every cave exit.

### V1.14 entry-group defaults

Practice warps now enable known map-entry object groups for 20 destinations,
including link maps, CloudRunner Dungeon and the areas reached by Arwing
landings. This happens at committed reload through the normal group setter.
Other groups and the current map act are preserved. Arwing flight maps have
no group bank; room-specific additions remain for a later pass.
See [the defaults and their evidence](practice_arrival_groups.md).
All 56 PPC payload checks and eight patch-integrity checks pass, including
the disabled-build check. The entry defaults still need Dolphin playtesting.
These changes are included in V1.14.

### V1.14 named spawn changes

Spawn presets support optional friendly names, shown beside their number/count.
Unnamed presets retain their warp-ID or estimated label. Cape Claw now has:

| Spawn | Name | X | Y | Z |
| --- | --- | --- | --- | --- |
| 1 (default) | Entrance | 1413.41162 | -1206.3031 | -4200.09863 |
| 2 | Link Door | 2872.06055 | -1401.93994 | -4406.44971 |
| 3 | Mana Shrine | 2053.456298828125 | -1668 | -2064.908203125 |
| 4 | Gas Chamber | 3754.10693 | -1464.93994 | -3452.88184 |
| 5 | Cannon | 3299.2041 | -1579.93994 | -2635.34961 |

All five use layer 0. Mana Shrine retains the former default's X/Z, facing,
and arrival ID 53, with Y lowered as requested to avoid the intact rock.
The other four are custom arrivals. Selecting Cape Claw resets to Entrance.
The catalog generator preserves these names, positions, and order, and checks
each position against the retail world grid.

The compiled PPC payload was checked for all five coordinates/rendered labels,
default selection and wraparound. Three existing warp checks and all eight
patch-integrity checks pass. The payload occupies 56,512 bytes of the 64 KiB
reservation. These changes are included in V1.14;
the positions have not been visually playtested in Dolphin.

### V1.14 DIM warp changes

DIM Bottom's estimated destination is now the supplied position
`(-8974.73438, -1627.60266, 17620.2559)`, on layer -2. The catalog generator
preserves this override and verifies that its world cell resolves to DIM Bottom.

A direct practice warp into LinkD (DIM Top to Bottom, map 68) now loads DIM
Top's resource bank (directory 26) alongside the link. LinkD has no resource
parent; its retail transition triggers explicitly manage the neighboring DIM
banks. Full practice reloads previously loaded only the link's own bank.

The destination and queued-bank PPC regression checks pass, as do the eight
patch-integrity checks. An isolated Dolphin Null-backend probe reaches LinkD
and clears the black fade with this change. However, the same probe also
succeeds on V1.13: the reported black screen has not been reproduced, and this
resource-bank correction is not yet confirmed to resolve it. These changes are included in V1.14.

### V1.13 changes

Free Move is the first Cheats entry, with an expanded **Invert X** checkbox
enabled by default. It reverses C-stick horizontal swivel with or without L;
main-stick movement, vertical movement, and pitch retain their controls.
These changes are included in the V1.13 ISO.

All 55 payload checks passed for the feature change. After updating the release
label, the three menu/default/inversion checks and all eight patch-integrity
checks passed. The packaged ISO boots through map initialization in an isolated
Dolphin Null-backend profile with 45 objects, an intact payload prefix, and
retail vertex format 7 preserved. This is a boot check, not visual playtesting.
The payload is 55,872 bytes within the existing 64 KiB reservation. The builder
verified the original ISO hash and that only the output's relocated DOL and
header DOL pointer differ. The original ISO and earlier releases are untouched.

V1.13 ISO SHA-256:
`9532ee993c6806f7844b41874ad7c43ad5f9eed52b340903c3280313d0fe965a`.
V1.13 payload SHA-256:
`1afd671049195e644acdae409b17d2bab66417bb68cd9dff8fdd4fc5d09f5d33`.

### V1.12 changes

Flags > Inventory > Area Items > Snowhorn Wastes now contains **Artifact**,
using the ownership bit `ITEM_NWSnowHornArtifact_Got` (0x1A2).

Every bit-change log now includes `[REGION 0]` through `[REGION 3]`, taken from
the bit descriptor's storage-bank field. Named and unnamed bits both include
the region; area-item labels still retain their map context.

The following fixes were first supplied in the regression test ISO and are now
included in V1.12:

C-stick Left/Right again swivels Free Move without a modifier. L only changes
the vertical C-stick axis from height movement to pitch. The main stick still
moves relative to Fox's facing; L+Up toggles Free Move and L+Down toggles swimming.

The debug renderer now uses retail vertex format 2 (F32 XYZ, RGBA8) without
changing any vertex-format definitions. Previously both the viewer and HUD
changed format 7 from S16 XYZ / RGBA4 to F32 XYZ / RGBA8 and left it changed
between frames. Retail `pi_videoinit.c` initializes those formats once, and
`objRenderAttachment` still submits packed S16 vertices using format 7.
`resetSomeGxFlags` only invalidates two depth-state caches; it does not restore
vertex formats. Disabling Collision/Triggers could not repair this state, and
the HUD still ran the same setup. The running V1.11 GX cache confirmed the wrong
format-7 types. This is a proven rendering regression; whether it explains all
reported Ice Mountain torch and TTH-to-Moon-Mountain-Pass link-map platform
issues still needs an in-game check.

The swimming surface-response wrapper also contaminated an implicit retail
register dependency even when every movement cheat was disabled. At EN callsite
`0x802B6584`, `playerUpdate` supplies `dt` in both f1 and f31. Several paths in
retail `playerUpdateSurfaceResponse` read f31 as an uninitialized `velMag` before
assigning it. The wrapper had placed the saved water height there instead;
the no-water sentinel -100000 made horizontal damping amplify velocity by 5001
at dt=1. The saved water height now spills to the stack, leaving dt in f31.
The regression executes the actual retail surface-response and math instructions
and compares complete player/state snapshots against a direct retail call on
normal ground, snow, and ice at dt=1/2, with swimming disabled, armed, and active.
Only the Gekko quantized s16-to-float leaf is emulated by the harness. This
reproduced the amplification before the fix and now matches retail; wind-tunnel
gameplay still needs an in-game check.

Pre-release validation: 55 payload checks and 8 patch checks passed, including the disabled
build emitting no payload. `build/practice/regression-fixes.iso` and
`build/practice/regression-fixes.sfapatch` contain these fixes. The ISO boots
through map initialization in an isolated Dolphin profile with the Null video
backend; a read-only memory probe confirmed format 7 remains `0x54e0e407`
(S16 positions, RGBA4 colors). This does not verify the reported scenes visually.
ISO SHA-256: `1db7a5f1c22dd7280df2d69c296165a2355b48c2567d9f7747394d1790d3d825`.
The original disc hash and all bytes outside the new DOL extent and header DOL
pointer are verified unchanged; previous release images are untouched.

The packaged V1.12 release repeats all 55 payload checks and 8 patch checks and
passes an isolated Dolphin Null-backend boot through map initialization, with
45 objects, an intact payload prefix, and format 7 still `0x54e0e407`.
The payload is 55,712 bytes within the existing 64 KiB reservation. The original
ISO and previous releases remain untouched. The builder verified the original
hash and that the output changes only the relocated DOL and header DOL pointer.
This boot check does not visually verify the affected torches, platforms, or wind
tunnels.

V1.12 ISO SHA-256:
`ee6c873046c9a0af411f651d8d5e5f0c533a51c2bfa87ac662a07cafc65fa18d`.
V1.12 payload SHA-256:
`f7eb9b7a41af43eebfac8ec8eb8909a7f4831e8ac260eaa884db88619a71c454`.

### V1.11 changes

Free Move now uses unmodified C-stick Up/Down for world-vertical movement.
Holding L changes the C-stick to yaw/pitch control and suppresses direct height
movement; unmodified C-stick Left/Right does not turn Fox. Main-stick movement
still follows his facing, including pitch, and the camera follows behind him.
The HUD shows both C-stick bindings. **L+D-pad Up** now toggles Free Move;
**L+D-pad Down** toggles swimming. The menu stays **L+R+D-pad Down**.

Swimming and Free Move can both be armed in the menu, but only one runs at a
time. Activating either shortcut stops the other mode. Enabling Forced Swimming
in the menu only arms its shortcut; it leaves swimming off and any active Free
Move running. L+C-stick controls water height only in active
swimming, so Free Move look input cannot change the water plane.

Flags now has an **Item Discovery** page with separate introduction latches:
staff energy gems, energy eggs, duster eggs/apples, scarabs, bomb spores, fuel
cells, Bafomdads, moon seeds, bomb-spore plants and patches, warp pads, staff
boost pads, barrel generators and the C-menu explanation. ON means already
seen; OFF re-arms the introduction for its next qualifying pickup/trigger.
These edits do not change item ownership/counts, respawn items or immediately
launch a cutscene. Some unique-item scenes use ownership or story progression
rather than a separate introduction latch; those are not mixed into this page.
Changes to these flags log under the inventory category.

The IDs come from the existing `Saw*` gamebits and their object consumers.
Moon seed's `0x9A8` latch is confirmed by `collectible_checkProximityPickup`'s
moon-seed case. `MagicDust_update`, `FuelCell_update`, `BombPlantSp_update`,
`AppleOnTree`, `Duster`, `Transporter`, `StaffActivated` and `BarrelGener` show the
pickup/proximity-message and one-shot sequence gates. No retail source changes
are needed; the new page is inside the practice build guard.

Validation: 53 compiled PPC checks and eight patch tests pass. Coverage includes
both movement-mode transitions, arming swimming without activating it during Free Move,
L+C-stick routing, direct vertical movement, the swapped shortcuts, discovery
edits preserving inventory, loading guards, Back selection memory and screen
bounds. Reading BITTABLE.bin directly from the original ISO confirms all 14
catalog entries are persistent one-bit bank-2 flags.

The packaged V1.11 ISO passed an isolated Dolphin Null-backend boot: game state,
loop initialization and map-loaded flags reached 1, with 45 objects and the
payload prefix intact. This checks startup; in-game controls and cutscene
replays still need gameplay testing. The original ISO was rehashed unchanged,
and read-back verification confirmed all bytes outside the relocated DOL and
its four-byte disc-header pointer are identical. The payload is 55,680 bytes,
within the existing 64 KiB reservation.

V1.11 ISO SHA-256:
`e4252b39d66a8ed6277791bbe35f4a47e5751b9bca4d4bb427ea0e4734249bfb`.
Payload SHA-256:
`6b703528be50256c7b17624276650797106c0629b0f7fbee67340086e511ea33`.

### V1.10 changes

Free Move now uses Fox's facing as its movement frame. The C-stick controls yaw
and pitch instead of direct height: right turns right, up looks up, and the main
stick moves forward/back along that direction or strafes horizontally. Both
sticks use proportional input outside a 20-unit dead zone, reaching full speed
at the retail PADClamp cardinal maxima (72 for the main stick, 59 for C-stick).
Full movement speed is five world units per nominal frame;
full turning speed is about two degrees per nominal frame. Pitch is limited to
roughly +/-79 degrees so the view cannot flip over.

The main camera sits 180 units behind a point 25 units above Fox's world position,
following the same facing and pitch. A single verified call-site hook in
`camcontrol_applyState` overrides the final view and streaming center before
matrix generation and culling. The normal camera controller continues to run;
its mode, target and parent are retained, and its view resumes on exit. Alternate
views, loading, warp, cutscene/focus and disabled-input states are guarded.

Fox's applied and desired heading stay aligned with the new facing, including on
a rotated parent. His pitch/roll are owned only while Free Move is active and are
restored on exit; the selected yaw is retained. Collision histories are rebuilt
after turns/moves and after restoring tilt. A replaced player or loading/warping
state discards the saved pose without writing into the former object. Opening
the practice menu freezes movement and look input.

The shortcut bindings remain L+D-pad Up for swimming, L+D-pad Down for Free Move,
and L+C-stick Up/Down for active swim height.

Validation: 51 compiled PPC checks and eight patch tests pass, including facing
and pitch movement, turning in place, parent-relative heading, camera placement,
exit restoration and the disabled payload's zero symbols. The patch suite was
rerun with the release title. The packaged V1.10 ISO booted in an isolated
Dolphin Null profile: game state, loop initialization and map-loaded flags
reached 1, with 45 objects and the payload prefix intact. Camera feel and
appearance still need in-game testing.

The original ISO was rehashed unchanged. Read-back verification confirmed that
all bytes outside the relocated DOL and its four-byte header pointer are
identical. Payload size is 55,232 bytes, within the existing 64 KiB reservation.

V1.10 ISO SHA-256:
`00f51c3650088d2714ec0ba6bf12bdc8508fdb37cb2700a525c9055109343eaf`.
Payload SHA-256:
`6ec66fb6f4c38626bc230a4d8091233716cf60903044f336503101a1d2299ee7`.

### V1.9 changes

Maps now places **Remove All** second, directly below **Unlock All**. Press A
to clear the twelve map-ownership flags; individual map toggles follow both
actions. Progression flags are unchanged, and save loading blocks both actions.

**Map Cells / Gravity**, off by default on the Draw tab, draws the 640-unit
map grid with translucent horizontal tiles at Fox's height and vertical edge
markers. Green means at least one of the five streamed block layers is occupied;
red means all are empty inside the 16-by-16 streaming window; amber means outside
that window. The current cell outline is gold. It respects Draw Distance and
Draw Through Walls and does not require terrain triangles or the Collision
master switch. The markers show an X/Z partition, not vertical gameplay limits.

Classification calls retail `isInBounds`, the same check used by `playerUpdate`.
Only its zero result takes the ordinary unparented/unmounted player freeze path,
which clears velocity and skips movement/gravity processing. An outside-window
result is -1 and does not take that path. This is map coverage, not a claim that
gravity is active in every occupied cell regardless of player state. Loading or
unavailable layer tables suppress the viewer. The viewer does not edit map data.

**L+D-pad Up** toggles swimming and **L+D-pad Down** toggles Free Move once
armed. **L+C-stick Up/Down** adjusts the active swim surface. **L+R+Down**
retains priority for opening the menu. Active Free Move needs no modifier.

Free Move now follows the main camera's yaw on the horizontal plane, with
C-stick Up/Down for height. X/Y no longer move vertically. It also rebuilds the
retail terrain/local-point collision sweeps and object-hit positions at every
new position, and aligns previous local/world positions there. Releasing it no
longer resumes sweeps from the last ordinary gameplay position. Collision with
geometry at the destination still applies once Free Move is released.

Repeated debug geometry helpers are compiled out of line to retain the same
64 KiB payload reservation; retail compiler settings and game addresses are
unchanged. The new input and cache behavior is checked with compiled PPC, including
the retail collision-refresh routines and map-bounds check; Dolphin gameplay
verification is still pending.

Validation: all 49 compiled-PPC checks and 8 patch-integrity tests pass. The
53,888-byte payload fits the unchanged reservation; disabled practice still
emits no symbols. The original and older practice ISOs remain unchanged.

V1.9 was packaged alongside the original and passed an isolated Dolphin
Null-backend boot check: initialized/loaded state, 45 objects, intact payload
prefix, and no apploader boundary errors. Logging starts enabled with the
3,920-bit baseline. This checks startup; gameplay and visual verification of
the new viewer and movement changes remain pending. The builder verified the
original ISO hash and all bytes outside the relocated DOL/header pointer unchanged.

V1.9 ISO SHA-256:
`0b59af467888353613e50575fc2b28de399a54432be872ba2eafbce1fcc7aea3`.
Payload SHA-256:
`a536517c9de1fb6f929c44f1a85c1d5351d5980e93bf2f4673c19c5cbb4419cf`.

### V1.8 changes

Object Groups selects the streaming engine's current world map when opened.
Manual selection remains available and stays put while browsing. During save
loading, or when the active map ID is unavailable/outside the editable world-map
range, it retains the previous selection.

Back returns to the parent folder's selected row throughout Flags, including
Object Groups and Advanced. Consumables now includes editable Scarabs, sharing
the same live count and edit limits as Player Stats.

Inventory now uses **Upgrades, Staff Spells, Consumables, Area Items, Spellstones,
Krazoa Spirits, Maps**. Staff spells also remain accessible from the Flags root.
Area Items opens a list of areas; Back returns to the selected area rather than
resetting the cursor to the start. Labels within each area omit its name, while
inventory log lines retain the area in brackets.

| Area | Items |
| --- | --- |
| Galleon | Gold key |
| ThornTail Hollow | White grubtubs, fire weeds |
| DarkIce Mines | Dino horn, four cogs, shackle key, cell key, silver key |
| Moon Mountain Pass | Key |
| CloudRunner Fortress | Flute |
| Cape Claw | Fire gems, gold bars |
| LightFoot Village | Three wood blocks |
| Walled City | Silver/gold teeth, sun/moon stones |

Consumables retains fireflies, bomb spores, fuel cells and moon seeds. Upgrades
retains staff, lantern, scarab bags, Bafomdad holder, viewfinder and Tricky ball
flags. These moves preserve the existing game-bit IDs and count widths.

**Maps** has **Unlock All** first, activated with A, then twelve individual map
ownership toggles. Bulk unlocking calls the same guarded setter as individual
edits and skips unchanged bits; it makes no changes while loading or without a
player. It sets only map ownership flags.

- **Forced Swimming** stays enabled in the menu while **L+Left** toggles its
  active state. Every activation places the surface at the current player Y+40;
  L+Up/Down retains height control. The cyan plane draws only while active.
- **Free Move** arms a separate **L+Right** toggle. The stick controls world X/Z,
  X descends and Y ascends, at five world units per nominal frame per axis with
  a stick dead zone and bounded frame delta. It bypasses the player's update and
  collision passes while active, freezes its movement animation/state, and clears
  movement velocities. Parent transforms convert movement into local coordinates.
  Other objects and triggers still run. The two movement modes are mutually exclusive.
- Activation/exit input is consumed; free movement has priority over roll macros.
  Both modes return to READY on player replacement, save loading or a queued warp.
  Free move also releases for disabled input, DVD/cutscene guards and mounted/focus
  control. Opening the practice menu pauses movement without clearing activation.
- **Infinite Health** and **Infinite Magic** are independent Cheats toggles,
  off by default. They refill to the current capacity before/after player updates,
  without editing capacities or spell unlocks. Health-depleted death calls are
  intercepted while enabled; scripted/void death with positive health still follows
  the retail path. Save loading suppresses refills. This is not a revive command.
- **Logging starts enabled**. Player Stats and Runtime / Action Flags remain off.
  Dolphin still needs OSREPORT at Notice and a file/log-window destination.
- Inventory adds **Krazoa Spirits**, with six numbered possession/collected flags:
  Observation `BA8`, Combat `BFD`, Fear `0FF`, Strength `C6E`, Knowledge `C85`,
  and spirit 6 `174`. They also remain on their area pages. Editing these flags
  does not reset deposited/progression flags or run a spirit collection cutscene.

The isolated payload uses GC/1.3 size optimization (`-O4,s`) and non-inlined
movement helpers to retain the original 64 KiB reservation; the retail build's
compiler settings are unchanged. The payload is 64,864 bytes. All 47 compiled-PPC
checks and 8 patch-integrity tests pass, including actual lethal retail health
subtraction, quick-toggle latching, menu/chord separation, roll-input priority,
parented movement, load/player-change guards, the six spirit edits, area navigation
and isolated bulk map unlocks. Additional compiled checks cover current-map
selection, parent-row restoration and Scarabs edits/loading guards. Disabled
practice still emits no symbols; `ninja all_source` and the strict retail target pass.

Before the inventory reorganization, a private test ISO passed an isolated Dolphin
Null-backend startup check (initialized/loaded, 45 objects, intact payload).
OSREPORT immediately printed
logging enabled and a 3,920-bit baseline with filter mask `BF`, confirming the
new default without external RAM edits. The builder verified the original ISO
and all bytes outside the relocated DOL/header pointer unchanged. Movement and
resource behavior are compiled-PPC harness checks, not Dolphin gameplay tests.
Published V1.7 and older ISOs remain unchanged.

V1.8 was packaged alongside the original and booted with an isolated Dolphin
Null-backend profile: initialized/loaded state, 45 objects, intact payload prefix,
and no apploader boundary errors. OSREPORT confirmed logging enabled and the
3,920-bit baseline with filter mask `BF`. This verifies startup, not visual or
gameplay behavior. The builder verified the original ISO hash and that all bytes
outside the relocated DOL and its header pointer are identical.

V1.8 ISO SHA-256:
`f153de92eab008266de63603a5a8032e2eddee1084be96e99a0128450f7cf7f9`.
Payload SHA-256:
`40f6d0431c5023c954dda0027fcaba4517a3c7adddab004564b4df70e54f1e19`.

### V1.7 changes

- Inventory now orders **Gear, Staff Spells, Supplies, Key Items, Spellstones**.
  Staff Spells also remains accessible from the Flags root. Gear includes both
  Tricky ball bought/usable flags, also retained in Tricky; their logs remain in
  the Tricky category. Key Items adds the three LFV wood blocks (`C25`-`C27`),
  without resetting their separate puzzle-used flags.
- **Player Stats** and **Runtime / Action Flags** logging default off. The new
  runtime category owns spell/item availability restrictions and outdoor/effect
  context flags, including `961`, `965`, `986`, and `3B0`, regardless of their
  menu locations. Normal ability-unlock logs remain under Spells. `884` now has
  a WarpStone/transport label under Area; its transport consumers do not establish
  that it is ordinary movement noise, so it remains visible by default.
- **Save / Respawn Checkpoints** logging defaults on when the master logger is
  enabled. Entries report accepted save sets, partial save refreshes that retain
  the position, restart sets/clears, save restores, restart respawns and fallback
  to the save snapshot. Repeated identical checkpoint writes are reported.
  Logs include the snapshot's layer and whole-unit XYZ coordinates.
- Card saves made through `saveGame_save` and `gplaySaveGame` produce a **CARD
  SAVE REQUEST** entry. This reports submission, not asynchronous card completion;
  it does not trace every lower-level card operation or new-game file creation.
- Area / Map Acts also reports **LAYER old -> new** using `getCurMapLayer` each
  draw frame, including during loading. Re-enabling the filter starts a baseline;
  changes that reverse within one frame remain invisible.

Checkpoint hooks target verified calls inside the retail implementations, covering
both direct and indirect API callers. Save-point `memcpy` hooks report only accepted
writes to the work buffer; restart-set reporting runs after its position/layer are
written. Allocation failure and a blocked save point emit no accepted-set event.
The original copies, bit setter, frees, loader and card call always execute with
unchanged arguments/return values. Direct checkpoint events do not depend on the
bit logger's loading/baseline guard or its 32-net-changes-per-frame limit. The UART
still drops output when the bus/FIFO cannot accept it.

Validation: 40 compiled-PPC payload tests and 8 patch tests pass, including actual
retail checkpoint routines with the verified call-site edits applied. Tests cover
repeat/blocked/partial saves, restart allocation failure, restore/fallback/clear,
original copy effects and card return values, quiet defaults, layer changes during
loading, and the spell-page alias. `ninja all_source` and the strict retail checksum
pass; compiling without `SFA_PRACTICE` emits no symbols. The 64,192-byte payload
fits the unchanged 64 KiB reservation. A private ISO booted in an isolated Dolphin
Null-backend profile (initialized/loaded, 45 objects, intact payload); the builder
verified all non-DOL/header bytes and the original ISO unchanged. This is startup
and harness validation, not checkpoint gameplay testing.

V1.7 was packaged alongside the original and older ISOs, then booted successfully
in an isolated Dolphin Null-backend profile: initialized/loaded state, 45 objects,
intact payload and no apploader boundary errors. All bytes outside the relocated
DOL and four-byte header pointer compared equal. The original retained SHA-256
`f2efe87066555522fa99a31a9f8b7eb4f51b47d59e5a348b1fed324fcd69fc4e`.
V1.7 ISO SHA-256:
`b3aa7d2e8d180c0b015397ea4c50f26647993478cb90b2ad25ea4782da4f39fe`.
Payload SHA-256:
`716ebb7284c0e5f2c2e1b25f9d5c54adfaf5b991020fa48bcc18e96956504165`.

### V1.6 fixes

- Inventory / Key Items adds the intro Galleon gold key, all four DarkIce Mines
  cogs, and Walled City silver/gold teeth. The CloudRunner flute moves from Gear
  into Key Items. These are possession flags; their separate used/puzzle flags
  are not implicitly reset.
- Opening the menu mutes object sound effects, including an already-playing
  shield loop. Music/stream playback continues. Existing game-muted voices stay
  muted, recycled channels are identified by handle and allocation age, and
  closing restores only voices owned by the practice mute. Positional sounds
  resume through the engine's spatial-volume update. Newly started effects are
  muted while the menu remains open. A new cutscene/DVD pause keeps ownership
  of its mute. **The shortcut remains L+R+Down; swim control remains L+Up/Down.**
- V1.5's logger called the retail `OSReport`, which is an empty function in this
  game (`track/intersect_memcard.c`). The compiled harness had intercepted that
  call, so its earlier passing tests did not establish working Dolphin output.
  Practice now formats its own bounded lines and writes through the IPL debug
  UART using the SDK EXI lock/transfer functions. No retail console-type or UART
  globals are changed. A busy bus/full FIFO drops output rather than spinning
  for log space. Dolphin displays this under **OSREPORT** at **Notice** verbosity;
  **OSREPORT_HLE alone is insufficient**. Enable Log to File or the Log window.
  Toggling logging emits an immediate enabled/disabled acknowledgement, and
  baseline changes report the number of watched game bits and category mask.

Validation: 36 compiled-payload tests and 8 patch tests pass. The sound checks
cover pre-muted voices, restored spatial volume, recycled handles and independent
pause owners. An isolated Dolphin test booted a private test image and verified
real OSREPORT output: enabled, watching 3,920 bits, Galleon gold key 0-to-1 and
1-to-0, then disabled. The probe changed and restored that bit only in its own
test emulator. No active object voices existed at that startup point, so this
does not claim an audible shield-loop playtest.


V1.6 was packaged alongside the original and previous releases, then booted in
Dolphin with an isolated profile and Null video backend: initialized/loaded
state, 45 objects, intact payload, and no apploader boundary errors. This checks
startup, not visual or audible gameplay. The 62,368-byte payload fits the
existing 64 KiB reservation. Every byte outside the relocated DOL and four-byte
header pointer compared equal, and the original ISO retained SHA-256
`f2efe87066555522fa99a31a9f8b7eb4f51b47d59e5a348b1fed324fcd69fc4e`.
The V1.6 ISO SHA-256 is
`9e1aa1c3fcad2a85211c0b819dbdeb318cb93951a9522a037b8f35d1dd7c24ae`;
the payload SHA-256 is
`4e6814997d6895ae6073018c7e9cdc86a5da05b54b2fd4878912a1d81f13f93e`.

### V1.5 changes

Reported V1.4 failures: warping to Galdon hangs on black, Andross flight
shows a broken cube-like Arwing, and all five Krazoa test maps fail to warp.
The practice coordinate warp omitted the
destination-bank setup performed by normal entry paths. A new practice-only
hook at `loadNextMap`'s `mapReload` call queues `mapLoadByCoords` after the fade
and character-position commit, clears source resource locks, and discards the
source auxiliary-bank selection. The existing queued loader unloads old
objects before synchronously loading destination/parent resource banks.
Ordinary and superseding scripted warps retain their retail reload path.

Shrine transporters likewise call `loadMapAndParent` on entry. The loader
test covers all five test destinations as well as Galdon and Andross. This
addresses a verified loading-path omission; the reported gameplay failures have
not yet been confirmed fixed through Dolphin gameplay testing.

Menu and cheat changes:

- L/R cycles Collision, Cheats, Warp, Flags, Log. **Warp Now is the fourth row**,
  immediately after Category, Map, Spawn; it still requires an explicit A press.
- Shield hover requires **physical X + R**, with **3 blanks after roll** and
  0 after shield by default. Both gaps remain configurable from 0 to 60.
- **Auto Roll** runs while physical **X** is held: one frame of X, **39 blank
  frames**, one frame of R, then X again. The blank gap is configurable from 0
  to 120; the default cycle is 41 input frames. X and R are both released during
  blank frames. Shield hover takes priority when both cheats are enabled and
  X + R are held. Releasing the activation buttons restores physical input;
  entering the menu, loading pauses, and player changes reset the cycle.

Flags uses a curated catalog in `include/practice/state_catalog.h`, based on
the existing named game bits, rather than presenting all IDs at once:

- **Inventory:** Gear, Supplies, Key Items, Spellstones.
- **Spells:** normal ability unlocks and separately labeled disabled flags.
- **Tricky:** commands, spawning permission, rescue/goodbye progression,
  stay/find, call, flame, distract, food and ball flags; also a read-only check
  for whether the Tricky object exists. Spawn permission is not a command to
  spawn/despawn him immediately. The uncertain C11 flag is in Advanced.
- **Player Stats:** health, magic, scarabs and Bafomdads with capacity fields.
  Health is shown in raw units; edits clamp to storage bounds/current capacity.
- **Area Progress:** choose a map, edit its act and the curated flags associated
  with that area. Coverage is incomplete; maps without curated entries still
  expose their act when the retail table defines one.
- **Object Groups:** choose a world map, then individual saved group switches.
  Each row also shows the active cached mask. These are group flags, not counts
  of resident objects. Group names remain numeric where their role is unknown.
  Runtime object-chunk aliases are not exposed as independent world maps.
- **Advanced:** direct hexadecimal bit-ID access and a separate **Unused /
  Uncertain** submenu for deleted spells, unused spellstones and tentative IDs.

**A** enters a submenu or toggles a boolean, **Left/Right** changes a value or
selector, **X** cycles numeric steps 1/16/256, and **B** goes back one level.
Selected bit rows show ID, bank and width. Raw values are hexadecimal; ordinary
counts are decimal. Invalid descriptors, constant bits and unavailable state
are not editable. The descriptor bound comes from the BITTABLE asset size,
not the retail count (which is measured in halfwords). Edits use retail game-bit
setters; map acts and groups use their savegame APIs even from the raw editor,
so caches and shared masks follow normal engine behavior. Edits affect current
save state and can persist through the game's normal saves. Script-controlled
flags, especially spell availability, may be overwritten on the next update.

In V1.5-V1.7 logging was **off by default** (current source defaults on). The Log tab offers Inventory, Spells, Tricky,
Area / Map Acts, Other / Unknown Bits, Object Groups, and Player Stats filters.
The original V1.5 output path is broken; use V1.6 with the UART fix above.
With that fix, enable Dolphin's OSREPORT logging to see `[PRACTICE]` entries with a frame
counter, bit ID/name and storage region (0-3) or map/stat identity, and before/after values. Named-bit
categories cover the curated catalog; unclassified bits go to Other, including
unused items. Logging reads snapshots without modifying gameplay state.

The logger reports **net changes between draw frames**, including direct/bulk
writes, not every call to a setter. A flip that reverses within one frame is
invisible. Enabling logging, changing filters, or loading a save establishes a
fresh baseline without dumping historical state. At most 32 events per frame
are printed, followed by a suppressed-event count; snapshots still advance.

These controls are tested as compiled PPC code with stubbed game services;
their gameplay effects and layout still need Dolphin playtesting.
The V1.5 source passed 32 payload tests, 8 patch tests, `ninja all_source`,
and the strict retail checksum. A read-only check against the verified EN disc's
3,920 BITTABLE records validated all 87 ordinary catalog rows (some are aliases
shown on more than one page). Six menu previews were inspected from rasterized
GX commands, not Dolphin screenshots. The payload is 60,096 bytes and still fits
the original 64 KiB reservation.

V1.5 was packaged and booted successfully from its new ISO in Dolphin with an
isolated profile and Null video backend: initialized/loaded state, 45 objects,
intact payload, and no apploader boundary errors. This is startup validation,
not confirmation of the reported boss/shrine warp fixes during gameplay.
Every byte outside the relocated DOL and four-byte header pointer compared
equal; the original retained SHA-256
`f2efe87066555522fa99a31a9f8b7eb4f51b47d59e5a348b1fed324fcd69fc4e`.
The new ISO SHA-256 is
`902ddae941b2df122b96ee94abcad49e188964be39dfe79f15ce7d82fc73cf68`;
the payload SHA-256 is
`7500eb64ce943a548f243928da6206087f936dd42a6dccf669698e8e3d7945a3`.

### Packaged build checks

```powershell
ninja all_source
ninja
python tools/practice/test_patch.py
python -m pip install --target build/practice/python unicorn==2.1.4
python tools/practice/test_payload.py
clang-format --dry-run --Werror src/practice/practice.c include/practice/practice.h
clang-format --dry-run --Werror include/practice/warp_catalog.h
```

Patch tests cover original-section preservation, corrupt-input rejection,
disabled code elimination, in-place and relocated ISO fixtures, DOL-only
application, the old high-address boot regression, and overwrite protection.
Payload tests run the compiled PPC instructions with stubbed game/GX services:
menu debouncing/navigation/input consumption, arena bounds, swimming restoration,
trigger fills/outlines and toggles, depth-test defaults/no depth writes, menu
scrolling, hold-R hover activation/release and cadence, all three tabs, warp
defaults/overrides/explicit activation/occupied-cell validation, player movement
shapes and parent transforms, packed terrain vertices, sentinel and cell-mask filtering, large-face
culling, water filters, nearby-block priority, barrier heights, and object transforms.
Unicorn lacks Gekko paired singles, so the harness skips only the compiler's
paired-lane stack saves/restores (ordinary floating-point saves still run).

`build/practice/menu-geometry-preview.png`, when Pillow is installed, is a
rasterization of the captured menu draw commands. It is not a Dolphin screenshot.
V1.1 was also booted from its ISO in a local Dolphin instance with an isolated
profile and Null video backend. The apploader loaded the new section without
the boundary warning/error; a read-only RAM sample showed `gameState=1`,
`gGameLoopInitComplete=1`, `gGameLoopMapLoaded=1`, 45 objects and intact payload
code. The arena-low value after subsequent system allocations was `0x805364A0`.
This is startup validation, not a visual or long-session playtest.

V1.2 passed all 13 compiled-payload tests, all 8 patch tests, `ninja all_source`,
the strict retail checksum, and the same isolated Dolphin startup check (45
objects, initialized/loaded state, intact payload). Formatting preserved both
the complete object and payload bytes. The 27,456-byte payload SHA-256 is
`c331fcf30aff51fbca864b8231816d746cdce11158289a179039bfacc1caab94`.
The new ISO SHA-256 is
`3ed7a0343f381ea5128d392dcd5bd45f8d01eb295f786e990160d85ef8e7e691`;
the original retained SHA-256
`f2efe87066555522fa99a31a9f8b7eb4f51b47d59e5a348b1fed324fcd69fc4e`.
Every byte outside the relocated DOL and four-byte header pointer compared equal.
The reported problem locations have not yet been visually retested in Dolphin.

V1.4 passed 22 compiled-payload tests and 8 patch tests, `ninja all_source`, the
strict retail checksum, and an isolated Dolphin ISO boot using the Null backend
(initialized and loaded state, 45 objects, intact payload; no apploader errors).
All 95 destination presets resolved to their intended map IDs using a read-only
snapshot of retail-initialized world-map tables in the PPC harness. This verifies
map/layer association, not safe footing, arrival scripts or playable progression.
The three menu pages were reviewed from rasterized GX draw commands. Actual
hover behavior, warp arrivals and player-overlay alignment still need playtesting.
Formatting preserved complete object and payload bytes. The 46,816-byte payload
SHA-256 is `7c6aa0156541c0b748bbea549db34320c0efa09fa9363c729e9aadd321dfaebe`.
The ISO SHA-256 is
`29ba6bdc1974fd170c39945f42e95a9f981998507d520abc0c2c5cc68ff551f7`.
The original retained the SHA-256 recorded above; every byte outside the relocated
DOL and its four-byte header pointer compared equal. V1.3 remains alongside the
other earlier builds, but its hover checkbox runs continuously; use V1.4 for the
corrected hold-R activation.

These checks do not establish in-game GPU-state compatibility, visual alignment
in every map, or swimming behavior in every movement/sequence state. Those need
playtesting in Dolphin; treat this as the first experimental practice release.
