# EN v1.0 practice ROM v1.1

This experiment lives on `practice-rom`, based on `main`, in its own worktree.
It builds a retail-DOL payload independently of the matching decomp link.
The first supported input is a clean US/EN v1.0 (`GSAE01`, revision 0) ISO.

## Controls

- **L + R + D-pad Down:** open/close the practice menu (controller 1).
- **D-pad Up/Down:** select a row; hold to repeat.
- **A:** toggle its checkbox. Enabling a group expands it.
- **Right/Left:** expand/collapse a group. Left on a child returns to its parent.
- **Left/Right on Water Height or Draw Distance:** change the value.
- **B:** close. **X inside the menu:** reset the water surface to the player's Y + 40.
- With swimming enabled and the menu closed, **L + Up/Down** raises/lowers the water surface.

The menu consumes controller-1 input and uses the existing `timeStop` mechanism
while open. This pauses object gameplay; it is not an emulator-wide frame pause.
The normal HUD shows a small reminder of the opening chord.

## Included

- **Collision:** loaded terrain triangles (green), object collision triangles
  (yellow), current object hit spheres (orange), water triangles (cyan).
- **Triggers:** crossing planes, rotated boxes, spheres, vertical cylinders
  (pink); optional line between the trigger's previous/current target sample.
  The engine's disabled flag makes a trigger grey. Geometry does not establish
  whether all of its game-bit/command conditions currently permit activation.
- **Forced Swimming:** uses the game's deep-water entry path and substitutes a
  player-local water surface/depth. A cyan grid shows that surface. Real map
  water geometry is unchanged. Disabling releases the swim flag and restores
  the real water query. Normal walls and collision still apply.
- **Draw Through Walls** and a **250–2500 unit Draw Distance** setting.

Collision/trigger/swimming groups start disabled. Individual geometry filters
are independent. Rendering is capped at 12,000 lines per frame; the menu reports
when the cap is reached. Only loaded objects/map blocks are visible. Trigger
timers, message-only triggers, curves, and every specialized interaction volume
are not covered by this first viewer. Noclip is not included yet.

## Build and apply

Use the repository's existing GC/1.3 MWCC and PowerPC binutils. The builder finds
them in `build/compilers` and `build/binutils`, including the parent checkout of
a Git worktree. Override with `--compilers` / `--binutils` if necessary. Current
commands use Windows compiler executables; applying an existing patch only
needs Python 3.10+ and this checkout.

From the practice worktree:

```powershell
python tools/practice/build.py build --enable `
  --iso "C:/Projects/SFA-Decomp/orig/GSAE01/Star Fox Adventures (USA) (v1.00).iso" `
  --output "C:/Projects/SFA-Decomp/orig/GSAE01/Star Fox Adventures (USA) (v1.00) (Practice v1.1).iso" `
  --patch "C:/Projects/SFA-Decomp/orig/GSAE01/SFA-EN-v1.0-Practice-v1.1.sfapatch"
```

The `.sfapatch` is a ZIP containing a manifest and the new payload, not a retail
DOL or ISO. Version 2 of the package format identifies the source by the clean
DOL hash, independent of the image's padding or compression. Apply it with:

```powershell
python tools/practice/build.py apply --iso "clean.iso" `
  --patch "SFA-EN-v1.0-Practice-v1.1.sfapatch" --output "practice.iso"
```

The executable transformation is also available without a disc container:

```powershell
python tools/practice/build.py apply --dol "main.dol" `
  --patch "SFA-EN-v1.0-Practice-v1.1.sfapatch" --output "practice.dol"
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
  --patch SFA-EN-v1.0-Practice-v1.1.sfapatch --output practice.iso
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
needs about 20 KiB. A growing DOL cannot be replaced at that offset without
moving it or other disc structures; this writer moves only the DOL.

V1 failed before game entry because its section at `0x816C0000` exceeded both
the apploader's production (`0x80700000`) and development (`0x81200000`) limits.
V1.1 fixes the placement instead of modifying or bypassing the apploader. Older
version-1 patch packages are rejected by the corrected patcher.

JP, PAL, and later EN revisions need independently verified symbol/hook adapters
and binary hashes. The current tool refuses them; it does not search for vaguely
similar instructions and patch an unknown version.

## Validation and limits

```powershell
ninja all_source
ninja
python tools/practice/test_patch.py
python -m pip install --target build/practice/python unicorn==2.1.4
python tools/practice/test_payload.py
clang-format --dry-run --Werror src/practice/practice.c include/practice/practice.h
```

Patch tests cover original-section preservation, corrupt-input rejection,
disabled code elimination, in-place and relocated ISO fixtures, DOL-only
application, the old high-address boot regression, and overwrite protection.
Payload tests run the compiled PPC instructions with stubbed game/GX services:
menu debouncing/navigation/input consumption, arena bounds, swimming restoration,
trigger shapes, packed terrain vertices, water filters, and object transforms.
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

These checks do not establish in-game GPU-state compatibility, visual alignment
in every map, or swimming behavior in every movement/sequence state. Those need
playtesting in Dolphin; treat this as the first experimental practice release.
