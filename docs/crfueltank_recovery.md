# CloudRunner fuel-tank recovery

Object DLL 607 retains its generated source path
`src/dlls/objects/607_CRFuelTank/CRFuelTank.c`. The public API and unit-owned
types now live in the self-contained `include/dlls/objects/607_CRFuelTank.h`.
The old `main/crfueltank.h` is removed. `modelEngine.c` includes the canonical
header and casts the actual `ObjectDescriptor` at its generic resource registry
entry, replacing the incompatible hand-written `ResourceDescriptor` declaration.

## Retail contracts

EN `crfueltank_getExtraSize` at `80210E8C` returns 0x10. The only accessed state
field is the float at +0xC, passed to the timer helpers; the leading twelve bytes
remain opaque. The canonical state asserts both the allocation-backed size and
the `respawnTimer` offset. The timer starts at 1,800 and decreases by `timeDelta`;
expiration reenables hit detection, clears the hidden flag, and restores alpha.

The signed placement halfword at +0x1A is divided by ten and passed as the third
argument to `ObjHits_SetHitVolumeSlot`. That routine stores it as `hitVolumeId`;
its second argument, 0x1D here, is the hit priority. The imported
`idleFrameCount`/`crfueltank_animFrame` names incorrectly implied animation.
They are now `hitVolumeIdTimes10`/`crfueltank_hitVolumeId`. The signed halfword at
+0x1E is tested against -1 and passed to `mainGetBit`/`mainSetBits`, establishing
`hitGameBit`.

The old header asserted a complete placement size of 0x20 without an EN
allocation or serialized-record witness. The available EN rev1 and JP
`cloudrace.romlist.zlb` files are byte-identical (SHA-256
`efde7cfb373a8d12cf644e6af9ee1da2a59e9e0e461d146769db9229c4040157`).
Each has three CRFuelTank placements, definition 0x109 / DLL 0x25F, all nine
words (0x24 bytes). Their sampled parameter words are
`0000012C 0000FFFF FFFF0000`: the recovered collision value is 300 and the game
bit is -1. The extra trailing word has no established EN consumer.

```
python3 tools/orig/romlist_params.py --files-root orig/GSAE01_rev1/files --search dll:607
python3 tools/orig/romlist_params.py --files-root orig/GSAJ01/files --search dll:607
```

EN's extracted files directory is empty, so the secondary size is not promoted
to an EN fact. `CrFuelTankPlacementPrefix` explicitly represents only the
EN-evidenced reader view through +0x1E, with field-offset assertions and no claim
of a complete record size. It must not determine an allocation or copy extent.
This removes the unsupported full-size assertion while keeping the proven reads.

The preexisting 0x38C snowbike trigger ID remains local. Slot 597 also uses that
ID privately; choosing a shared owner and migrating that family is separate work.
The inline division helper, tested casts and predicates, and final descriptor
position are retained.

## Boundary and build checks

EN text spans `80210E8C..802110F8`: nine functions, 620 bytes. The 56-byte
descriptor occupies `8032A468..8032A4A0` and has nine nonzero callback pointers.
Its only assigned constant is the four-byte upward-velocity adjustment at
`803E6760`. Neighboring slots 606 and 608 retain their complete text and data
ranges; no artificial fragments, section overrides, or new pool claims are added.
The generated-path audit passes for all three slots against the preceding commit.

All four configured DOL hashes pass. EN, EN rev1, JP, and PAL rev1 retain nine
exact functions and 60 exact data bytes. Every compiled source object, including
the shared registry, is byte-identical; complete objdiff reports are unchanged.
All four `all_source` builds and the strict EN retail checksum pass. Formatting
is separate and preserves the raw object in each version.
