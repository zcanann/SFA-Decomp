# LinkA level-control routing

Slot 568 owns its API in `include/dlls/objects/568_LINKA_levco.h`. Its generated
source path and complete TU boundaries remain unchanged. The misleading
`gFireObjDescriptor` becomes `gLinkALevControlObjDescriptor`; the generic resource
registry includes the canonical header and casts the actual `ObjectDescriptor`
at its entry. All five symbol configs carry the name change without address or
size changes. PAL revision 0 receives naming consistency only: its local DOL
fails the configured checksum and was not used for matching evidence.

The sequence callback reads the object's map act, keeps sound `0x48B` alive,
and processes every event without clearing the event IDs. Event 1 defragments
memory and prepares a destination; event 2 selects a warp and then loads the UI
DLL, even when no route was selected; event 3 unloads a neighboring map.

| Map act | Event 1: prepare | Event 2: warp index | Event 3: unload |
| --- | --- | --- | --- |
| 0 or 1 | Clear ThornTail groups 0, 2, 3, 7, 10 and SnowHorn group 7; set `GAMEBIT_IM_TrickyRelated01ED`; load and lock Ice Mountain | `0x02` | ThornTail Hollow |
| 2 | Load and lock Krazoa Palace | Spirit-dependent, below | ThornTail Hollow |
| 3 | Load and lock ThornTail Hollow | `0x0F` | Krazoa Palace |

Act 2 first clears `GAMEBIT_WM_ObjGroups`, then tests the spirit bits in this
priority order:

| Acquired spirit | Palace act | Groups set to 1 | Warp index |
| --- | --- | --- | --- |
| Fear (`0xFF`) | 3 | 8, 9 | `0x22` |
| Combat (`0xBFD`) | 2 | 5, 6 | `0x20` |
| Strength (`0xC6E`) | 4 | 8, 9 | `0x22` |

No acquired spirit means no warp. Existing canonical game-bit names replace
all eight local aliases, including the three init flags `SawMagic`,
`SawBigHealth` and `SawApple`. The old Lightfoot label for `0x1ED` was unsupported:
its other direct consumer is `IMIceMountain_update`, which passes it to
`GameBitLatch_Update`. Its canonical broad Tricky-related name is retained.

EN revision 1 and JP `MAPINFO.bin` independently identify map slots 7, 10, 11
and 23 as ThornTail Hollow, SnowHorn Wastes, Krazoa Palace and Ice Mountain.
These sibling assets corroborate the names; EN's extracted asset directory is
unavailable. `mapGetDirIdx` converts map slots for locking and unloading.
Warp indices belong to a different table: `warpToMap` reads 16-byte
position/layer/angle records, with no map-slot field. The sibling `WARPTAB.bin`
files are identical, but the source keeps generic route constants instead of
promoting the old shrine label or inferring a precise entrance from coordinates.

The retail extra-size callback returns four, but no function in this TU accesses
extra state. A documented allocation constant suffices; no state or placement
layout is invented. Init preserves its codegen-proven flag temporary, sequence
callback, level unlock, environment reset and music fade. The final descriptor
keeps all ten slots in retail order. Casts remain where callback signatures
intentionally differ from the generic descriptor typedef.

EN owns ten functions at `0x8020930C..0x80209810` (1,284 bytes), the 56-byte
descriptor at `0x80329C80`, and the four-byte `1.0f` pool at `0x803E64D8`.
Independent checksum-verified EN, EN revision 1, JP and PAL revision 1 audits
agree on all normalized functions, allocation return, route/game-bit immediates,
pool and descriptor callbacks. No split, compiler or matching-flag changes.

All four full objdiff reports remain unchanged: ten exact functions, 1,284
matched code bytes and 60 matched data bytes. Only the controller and registry
objects change raw hashes. After the explicit descriptor-name substitution,
function bytes, allocated sections, named symbol layouts and physical relocations
are identical. The registry change is its slot 568 relocation at byte offset
2,272. The other 1,002 EN and 986 source objects per secondary version are
byte-identical. All four `all_source` builds and the strict EN retail checksum
pass within 30-second bounds, and the neighboring generated-path audit passes.
