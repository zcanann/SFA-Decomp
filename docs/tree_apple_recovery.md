# DLL 687: apple children and placement tint reads

The numbered `src/dlls/objects/687/687.c` path remains unchanged. Tree is an
internal family name, not a recovered original source filename. The canonical
header is `include/dlls/objects/687.h`.

## Recovered contracts

EN `tree_getExtraSize` at `802358FC` returns `0x5C`. The state owns three
`GameObject*` apple pointers, three positions and three respawn timers; the loop
bound independently establishes that capacity. Rendering supplies the path-point
positions and sets `userData2`, which gates child updates until those positions
are available.

The spawn helper at `802356CC` allocates `0x28` bytes for object ID `0x210`.
The existing `AppleOnTreePlacement` describes its exact writes. The former
"colour" bytes at `0x20–0x24` are apple phase thresholds, `0x25` is water
acceleration percent, and `0x26` is the despawn game bit. The zero write at
`0x18` remains opaque. The helper names are now `tree_spawnApple` and
`tree_updateApples`; the child interface ABI is unchanged.

The eleven burst profiles at EN `8032BBE0` contain a position offset and radius,
not effect colours. The update function scales and rotates that offset before
spawning particles. The `0xB0`-byte table precedes the terminal `0x38`-byte
descriptor at `8032BC90`; their order and ownership are preserved.

## Tint reads cross secondary serialized records

EN `tree_render` at `80235904` loads the placement pointer from object offset
`0x4C`, then loads bytes at placement offsets `0x20`, `0x21` and `0x22`.
`objSetColorFilter` at `8003B608` stores those arguments as RGB and enables the
filter.

The packed-record loader preserves the pointer:

1. `piRomLoadSection` (`80048328`) decompresses into the destination buffer.
2. `mapInstantiateObjects` (`800553B0`) passes its record cursor to
   `objSetupObject`, advancing by the record's size byte multiplied by four.
3. `objSetupObject` (`8002DF90`) forwards the pointer to `loadCharacter`
   (`8002D55C`), which stores it as `placementData`.

Every DLL 687 placement found in EN rev1 and JP is eight words: **731 records
per version, all `0x20` bytes**. Every one has a following record, so the RGB
reads consume that next record's object-ID bytes and size byte. For example,
`arwingdarkice.romlist.zlb` at decompressed offset `0xBA4` contains a SnowTree1
record followed by another SnowTree1; the tint reads are `00 39 08`.

The renderer and the four loader functions have equal normalized instruction
signatures in EN, EN rev1, JP and PAL rev1. EN placement assets are unavailable
locally, so its serialized extent remains unproven. `TreePlacementPrefix`
therefore owns only the known prefix through `0x1F`; rendering preserves the
three explicit byte accesses beyond it. The source does not enlarge the record
or change the retail behavior.

The asset audit uses `tools/orig/romlist_params.py`'s ZLB, object-definition and
OBJINDEX readers, walks each decompressed record by its encoded word count, and
selects definitions whose DLL ID is 687. This distinguishes record ownership
from the bytes merely reachable through a placement pointer.

## Validation

All six functions (2,696 code bytes), allocated section bytes, symbol offsets
and relocations remain identical after normalizing the two helper names.
Compiling with the old names restores the complete original object. The
registry's sole include change preserves its raw object.

The six retail functions have equal normalized signatures across the four
verified versions. The 64-byte constant pool and 176-byte burst table are each
byte-identical across those DOLs. All four source builds and match reports are
checked, with EN's strict retail checksum as the final link gate. PAL rev0 gets
symbol-name consistency only because its local artifact fails that version's
configured hash.
