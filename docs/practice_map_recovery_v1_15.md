# Practice v1.15 map recovery

This remains an optional `SFA_PRACTICE` payload on the isolated practice branch.
No retail source units, asset files or original ISO bytes are rewritten in place.
The package edits the new ISO's executable and its location pointer only.

## Dragon Rock Bottom

Retail `OBJECTS.bin` definitions 1148–1151 (`DR_LightHal`, `DR_LightPol`, and two
`DR_LightLam` definitions) request DLL 639 / 0x27F. Their placement IDs are 1238,
1268, 1299 and 1272. The corresponding registry entry points at the eight-byte
`gDll27FNullResourceDescriptor`, not a full object descriptor. The original
resource loader reads beyond that stripped record as if callbacks existed.

The practice patch replaces that single, checked registry pointer with its own
valid descriptor. It supplies a normal model-render callback and zero-sized
extra state; all other callbacks are null. Surviving models can render, without
inventing the missing light animation or interpreting placement parameters as
another object's state. Neighboring registry pointers stay identical.

The investigation lead came from the local Amethyst reference's `src/dll.c`
workaround (redirecting DLL 0x27F to 0x131). Its published
[release notes](https://segment6.net/sfa/amethyst) credit Jeebs for identifying
the crash workaround. Our descriptor keeps the repair separate from the
unrelated live door-light DLL. The actual registry and object definitions were
verified against EN v1.0.

Before: fresh-boot warp stalled at black with 72 objects and no frame progress.
After: 91 objects, advancing frames, completed fade, visible industrial interior
and Fox. Capture: `build/practice/repair-probe-v15b/map-052-spawn-01.png`.
This restores access and static scenery, not the deleted DLL's original logic.

## LinkA route presets

All five presets use retail warp 126's coordinates:

| Preset | LinkA act | Retained source bank | Retail onward route |
| --- | --- | --- | --- |
| To Ice Mountain | 1 | Thorntail Hollow (12) | Warp 2, map 23 |
| To Krazoa Palace: K2 | 2 | Thorntail Hollow (12) | Warp 32, Palace act 2, groups 5/6 |
| To Krazoa Palace: K3 | 2 | Thorntail Hollow (12) | Warp 34, Palace act 3, groups 8/9 |
| To Krazoa Palace: K4 | 2 | Thorntail Hollow (12) | Warp 34, Palace act 4, groups 8/9 |
| Return to Thorntail Hollow | 3 | Krazoa Palace (15) | Warp 15, map 7; retains current Hollow progression |

`warpstone_testEvent` and the `WM_spiritpl` sequence callback establish the normal
source-bank/act contract. `LinkALevControl_seqFn` handles the onward loading,
groups and warps. Its three spirit checks alone are hooked to select the chosen
Palace route. Actual inventory bits are never granted or removed by this
override, and all other game-bit readers remain unchanged. The override clears
on the next reload. Ice Mountain act 1 is prepared as in normal WarpStone travel.

Browsing presets has no effect; the selected context is latched with the warp
request and applied only when that same request commits. Superseding retail
warps retain their normal behavior.

All five corridor presets rendered the warp tunnel instead of fallback colored
geometry. Each was then tested from a fresh boot through its automatic onward
transition, reaching Ice Mountain, the three Palace arrivals, or Thorntail
Hollow, with visible level geometry. Captures and onward states:
`build/practice/repair-link-journeys-v15b/`. Separate short corridor captures:
`build/practice/repair-probe-link-v15b/`.

## Andross flight and Great Fox

`Landed_Arwing_SeqFn` retains Palace directory 15 when departing for maps 38 and
65. Arbitrary practice travel previously discarded it. Committed practice warps
now explicitly queue that auxiliary bank.

Fresh-boot captures show the actual Arwing and Andross arena, and the Great Fox
space scene, respectively. Files:
`build/practice/repair-extra-v15c/map-038-spawn-01.png` and
`map-065-spawn-01.png`. This checks scene loading/rendering, not the entire fight
or ending sequence.

## What remains unresolved

Animtest already contains its room and idling Fox; no restoration is claimed.
Its retail romlist contains one setup point. Rolling Demo, Discovery Falls,
Diamond Bay, Willow Grove, Kamerian and Duster Cave likewise have only a setup
point in their romlists. That is evidence of stripped object content, not proof
that every geometry asset is gone. Old Krazoa Palace and WGShrine retain richer
object lists (51 and 40 placements); they still warrant entrance/bank analysis.

The previous sweep's empty voids remain failures to establish a usable warp.
The gallery now calls its numeric condition **load/fade completed**, never a
passing warp. DIM Top, other void arrivals, and forced serial transition hangs
are not fixed by these changes. In particular, an immediate forced transition
from Dragon Rock Bottom to LinkA stalled, although both destinations load from
fresh boots. The harness bypasses menu busy-state checks and uses minimal Fox
setup; it is not a normal save-file playthrough or a test of every source map.

## Validation

58 compiled-PPC tests passed after the light/LinkA changes; the affected bank,
LinkA and Magic Cave tests passed again after adding the Palace bank retention.
Nine patch tests cover original section preservation, exact edit boundaries,
the isolated descriptor pointer replacement, and zero emitted payload when
`SFA_PRACTICE` is disabled. Dolphin tests use private profiles and do not read or
modify the user's saves.
