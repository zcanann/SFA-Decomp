# EN v1.0 practice ROM v1.4

This experiment lives on `practice-rom`, based on `main`, in its own worktree.
It builds a retail-DOL payload independently of the matching decomp link.
The first supported input is a clean US/EN v1.0 (`GSAE01`, revision 0) ISO.

## Controls

- **L + R + D-pad Down:** open/close the practice menu (controller 1).
- **L/R inside the menu:** previous/next tab, wrapping at the ends. Collision
  is first, Cheats second, Warp third. Z is unused. Analog press and digital click count as
  one shoulder press; holding a shoulder does not repeatedly switch tabs.
- **D-pad Up/Down:** select a row; hold to repeat.
- **A:** toggle its checkbox. Enabling a group expands it.
- **Right/Left:** expand/collapse a group. Left on a child returns to its parent.
- **Left/Right on numeric rows:** change water height, draw distance, or hover cadence.
- **B:** close. **X on the Cheats tab:** reset water to the player's Y + 40.
- **With Auto-Shield Hover enabled:** hold R to run the cadence; release R to stop.
- **Warp tab:** Left/Right edits category, map, spawn, position, layer, facing or step.
  Selecting a map/spawn restores its preset. Select **Warp Now** and press **A** to travel.
- With swimming enabled and the menu closed, **L + Up/Down** raises/lowers the water surface.

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
  These are independent of the generic Object Hit Volumes checkbox. Movement
  shapes read the active `CurvesCollisionState` and its live radii/counts. Segment
  points are world-space; wall points use the player parent's collision transform
  when parented. A captured Ice Mountain state had a 0.05 ground radius and 8.5
  body/wall radii. The tiny ground sphere gets a center cross; floor results get
  a cross and connecting line. These markers are not additional hit volumes.
  Cached trace endpoints can coincide after the engine copies the resolved point
  back, so this is not a history of all sweeps. Animation foot-effect positions
  are deliberately not represented as collision shapes.
- **Forced Swimming:** uses the game's deep-water entry path and substitutes a
  player-local water surface/depth. A cyan grid shows that surface. Real map
  water geometry is unchanged. Disabling releases the swim flag and restores
  the real water query. Normal walls and collision still apply.
- **Auto-Shield Hover** on Cheats: while physical **R is held**, emits
  **R (shield), then X (roll)** on
  successive game input frames. **Blanks After Roll** and **Blanks After Shield**
  each accept 0-60 frames, edited with D-pad Left/Right. Each action lasts one
  frame; blank frames release both X and R. At 2 roll blanks and 1 shield blank,
  the repeating pattern is `R, blank, X, blank, blank`. Both counts default to
  zero. Releasing R stops immediately and resets the cadence to shield; merely
  enabling the checkbox sends no inputs. Analog R and its digital click both
  activate it. The stick and other buttons remain available. The macro stops during
  menus, paused gameplay, disabled input or DVD errors and restarts at shield.
  Turning it off returns X/R to physical input with correct release edges.
  It automates inputs only: height, velocity and animation state are not forced.
  The best cadence and resulting hover behavior still require gameplay testing.
- **Warp:** all 117 map IDs are listed in categories. 61 have world destinations:
  41 use retail WARPTAB entries and 20 use explicitly marked estimated positions.
  Estimated positions come from a central placed object plus 50 Y, or an occupied
  block center with Y=0 when no placement is available; adjust them as needed.
  They are not guaranteed safe ground or working entrances. The other 56 IDs
  represent unplaced maps or object chunks and cannot be warped to standalone.
  The 95 presets use the retail occupied-cell lookup, including overlapping
  maps and signed layers. X/Y/Z, layer, facing byte and position step are editable.
  Warping validates that X/Z/layer still resolve to the selected map and uses
  the retail fade/reload path. Edited positions use unused arrival ID 128 to
  avoid activating an unrelated checkpoint marker. Unedited retail presets
  retain their arrival IDs and therefore their normal arrival events.
  Story flags, map acts and character selection are retained; bosses, Arwing
  stages and unused maps may require suitable progression state.
- **Draw Through Walls** and a **250–2500 unit Draw Distance** setting.

Collision and triggers start enabled, with every geometry filter on except
**Terrain Triangles** and **Water Triangles**. Draw Through Walls remains off.
Swimming and Auto-Shield Hover are opt-in. Individual filters are independent.
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
  --output "C:/Projects/SFA-Decomp/orig/GSAE01/Star Fox Adventures (USA) (v1.00) (Practice v1.4).iso" `
  --patch "C:/Projects/SFA-Decomp/orig/GSAE01/SFA-EN-v1.0-Practice-v1.4.sfapatch"
```

The `.sfapatch` is a ZIP containing a manifest and the new payload, not a retail
DOL or ISO. Version 2 of the package format identifies the source by the clean
DOL hash, independent of the image's padding or compression. Apply it with:

```powershell
python tools/practice/build.py apply --iso "clean.iso" `
  --patch "SFA-EN-v1.0-Practice-v1.4.sfapatch" --output "practice.iso"
```

The executable transformation is also available without a disc container:

```powershell
python tools/practice/build.py apply --dol "main.dol" `
  --patch "SFA-EN-v1.0-Practice-v1.4.sfapatch" --output "practice.dol"
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
  --patch SFA-EN-v1.0-Practice-v1.4.sfapatch --output practice.iso
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

Original text/data/BSS addresses are preserved. Six verified call instructions
are replaced: both OSInit arena-low setup calls, controller polling, the end-of-frame
stub, player controls, and player surface response. Calls go through ordinary
PPC EABI C wrappers; game/compiler/SDK routines remain at their retail addresses.

A new DOL section contains code, constants and explicitly initialized zero-state
at `0x803FA480`, the verified retail default `__ArenaLo`, above the startup stack
at `0x803F8478`. Both OSInit arena-low paths clamp the heap start to `0x8040A480`
before `ClearArena`, protecting a 64 KiB payload region. The retail debug-flag
path originally starts its arena 8 KiB earlier, so that path loses 72 KiB of heap
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
needs about 46 KiB. A growing DOL cannot be replaced at that offset without
moving it or other disc structures; this writer moves only the DOL.

V1 failed before game entry because its section at `0x816C0000` exceeded both
the apploader's production (`0x80700000`) and development (`0x81200000`) limits.
V1.1 fixes the placement instead of modifying or bypassing the apploader. Older
version-1 patch packages are rejected by the corrected patcher.

JP, PAL, and later EN revisions need independently verified symbol/hook adapters
and binary hashes. The current tool refuses them; it does not search for vaguely
similar instructions and patch an unknown version.

## Validation and limits

### Pending changes after V1.4 (not packaged)

Reported V1.4 failures: warping to Galdon hangs on black, and Andross flight
shows a broken cube-like Arwing. The practice coordinate warp omitted the
destination-bank setup performed by normal entry paths. A new practice-only
hook at `loadNextMap`'s `mapReload` call queues `mapLoadByCoords` after the fade
and character-position commit, clears source resource locks, and discards the
source auxiliary-bank selection. The existing queued loader unloads old
objects before synchronously loading destination/parent resource banks.
Ordinary and superseding scripted warps retain their retail reload path.

This addresses a verified loading-path omission, but neither reported gameplay
failure has yet been confirmed fixed in Dolphin. The pending source passes 23
compiled-payload tests, 8 patch tests, `ninja all_source`, and the retail build
check. No new ISO or patch has been generated, as requested during testing.

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
