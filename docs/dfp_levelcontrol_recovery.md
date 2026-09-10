# DFP level-controller storage and floor-table capacity

Slot 553 owns its state, placement prefix, public API and extended runtime
interface in `include/dlls/objects/553_DFP_LevelCo.h`. The common
`ObjectInterface` replaces eight opaque pointer slots; the controller-specific
`copySafeFloorTiles` callback remains at interface offset 0x20. Its complete
interface size is 0x24, matching the 11-slot descriptor's exported portion.

Floor-bar slot 559 and wall-bar slot 560 both find this controller through
`anim.romDefNo == 0x431` before calling the same export. They now include the
canonical header and use its shared object ID. The descriptor registry includes
that header and casts the real 60-byte descriptor at its generic resource
boundary. Unrelated uses of the number 1073 in the player animation table are
not object-ID lookups.

## Nine safe-floor entries, not ten

EN resets and copies exactly nine signed-halfword tile values. Act 1 randomizes
the first six and clears the final three; act 2 randomizes all nine. The copy
routine at `80204548` emits nine bytes in three groups of three, truncating each
signed halfword. The wall-bar consumer's receiving array also contains nine
bytes. The complete extracted EN relocation scan finds references to the
halfword table only in this owner.

The previous declaration counted two alignment bytes as a tenth tile. Declaring
nine entries emits the same 80-byte `.data` section: 18 table bytes, two automatic
alignment bytes, then the 60-byte descriptor. The table remains at `80329848`;
the descriptor remains at `8032985C`, ending at `80329898`. No explicit padding
or synthetic tail object is added. The active symbol size changes from 0x14 to
0x12 in EN, EN rev1, JP and PAL rev1.

## State and placement evidence

The extra-size callback returns 0x0C. The canonical state records the signed
zap timer at zero, stored placement mode at 0x02, untouched bytes at 0x04,
previous puzzle-pad byte at 0x06, sound-trigger bitfield byte at 0x07, and music
latch at 0x08. The latter now uses the actual `GameBitLatchState` consumed by
three shared latch calls, removing casts from an anonymous integer mask.

EN initializes the sound-trigger bits with masks 0x80, 0x40 and 0x20 while
preserving the remaining bits. The placement mode is a signed halfword at
0x1A. Its condition accepts nonzero values less than or equal to two, including
negative values. No later code in this TU reads the stored mode; update obtains
the current act from the map-event interface. The field name records that
distinction without changing the original predicate.

The old 0x1C placement-size assertion was unsupported. EN establishes the
prefix through 0x1B only. The available EN rev1 assets contain two 0x24-byte
records, which also contradict treating the old declaration as a universal
full-record size; they are not promoted to an EN allocation contract. The
canonical prefix retains offset assertions and leaves total size unclaimed.

## Validation

The 13 functions remain `80204098..80204970`, totaling 2264 bytes. The complete
80-byte `.data` section, eight-byte `.sdata` section, relocations and all global
positions remain unchanged. Source object comparison differs in exactly one
byte: the table symbol's size changes from 20 to 18. Both bar consumers and the
registry remain byte-identical, with their shared edits kept surgical.

Full source builds and fresh objdiff reports are checked in EN, EN rev1, JP and
PAL rev1. The unit remains exact in code and data, and EN passes its strict
retail checksum. Formatting is committed separately and checked for unchanged
objects. This is storage and API recovery; no additional matching bytes are
claimed.
