# Proximity-mine placement and state recovery

DLL 608 drives the CRDropBomb and ProximityMi family. Its source remains at the
canonical generated path `src/dlls/objects/608/608.c`; the public contract now lives
in `include/dlls/objects/608_ProximityMine.h`.

## Retail evidence

EN `snowclaw_spawnDropBomb` at `8020F214` allocates **0x24 bytes** for object ID
`0x5FF`: the allocation arguments are loaded at `8020F250` and `8020F254`, followed
by `Obj_AllocObjectSetup` at `8020F258`. The producer previously declared only a
0x1C-byte prefix. It now uses the allocation-sized canonical placement, retaining
the unaccessed eight-byte tail as opaque storage.

The signed halfword at placement `+0x1A` has three mode-specific interpretations:

| Spawn mode | Producer / mine interpretation |
| --- | --- |
| 0, timed | Detonation delay; SnowClaw supplies 150 frames through the legacy-named `gSnowClawDropBombAngle`. |
| 1, launched | Full launch rotation; SnowClaw aims it toward the player. |
| 2, proximity | Player trigger distance, also copied into the mine's explosion radius. |

The canonical union exposes each interpretation. Placement `+0x18` remains a
signed rotation high byte and `+0x19` a signed mode. The mine changes mode to 2
for object ID `0x789`. EN rev1 and JP independently map `OBJINDEX[0x5FF]` to
object definition `0x10E`, CRDropBomb, and `OBJINDEX[0x789]` to definition `0x465`,
ProximityMi; both definitions use DLL 608 and class 48. These secondary assets
corroborate family identity; the allocation-size evidence comes from EN code.

`ProximityMine_getExtraSize` at `8021122C` returns **0x34**. The recovered state
separates attachment following, growth, flight, detonation, delayed hit enabling,
and destruction. Growth initially lasts 40 frames; a waiting proximity mine arms
with a 120-frame detonation timer. The glow state remembers the previous enabled
value to detect an edge. The field at `+0x24` only initializes to five, and byte
`+0x2E` only initializes to zero; their meanings remain unknown. The former
`flashMode` name was unsupported. All observed offsets and both proven sizes are
asserted beside their canonical definitions.

Hit priority 13 is a private constant. It is passed as the priority argument of
`ObjHits_SetHitVolumeSlot`, not as a volume index. The generic descriptor registry
now includes the owning header and casts the real `ObjectDescriptor` pointer at
its `ResourceDescriptor*` storage boundary.

## Boundaries and verification

The complete EN TU occupies text `802110F8..80211C24`, descriptor data
`8032A4A0..8032A4D8`, small data `803DC230..803DC250`, and constants
`803E6768..803E67A0`. CRFuelTank precedes its text and descriptor; KT_RexLevel
follows them. The descriptor remains last, with its existing callback ordering.
The mixed-width small-data declarations retain their original order and padding.
No split, compiler profile, or matching classification changes are needed.

All ten functions (2,860 code bytes) and 144 data bytes remain exact in EN,
EN rev1, JP, and PAL rev1. Full source builds and freshly generated objdiff
reports are checked in all four versions; every source object remains byte-for-byte
identical. EN also passes the strict retail DOL checksum target. Formatting of
DLL 608 and its canonical header is committed separately and checked for unchanged
object output; shared producer and registry edits remain surgical.
