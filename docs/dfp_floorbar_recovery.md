# DFP floor-bar state and table boundaries

Slot 559 uses the level controller's nine safe-floor tile values to lower the
correct row of the electric-floor puzzle. Its canonical header is
`include/dlls/objects/559_DFP_floorba.h`; the source path and public symbols
remain unchanged.

## State and placement

EN's extra-size callback at `8020647C` returns 0x0C. The state contains the two
placement halfwords at offsets zero and two, four bytes for lowered state,
row index, safe tile and previous show-solution state at offsets four through
seven, then the controller object pointer at eight. The first halfword is
initialized but has no subsequent reader in this TU. The second selects the
game bit that causes initialization to place the bar 3.2 units below its
placement height.

The placement uses the common `ObjPlacement` prefix. EN proves the rotation
byte at 0x18, row byte at 0x19, motion-scale divisor halfword at 0x1C and game-bit
halfwords at 0x1E and 0x20. The rotation byte is sign-extended before shifting
left eight bits. A nonzero motion-scale divisor sets `rootMotionScale` through
the original two divisions, `1.0f / (divisor / 1000.0f)`; it does not determine
the lowering distance. The available EN rev1 assets contain nine nine-word
placements, but this is not used to assert the unavailable EN v1.0 record size.

The hit-detection callback now accesses the typed state and controller instead
of indexing an `int**`. Its mask 0x40 is read from `anim.flags` at object offset
six. It is not replaced by the similarly valued object flag stored at 0xB0.
The update retains the retail search loop, signedness and player-position
predicates, including the absence of an upper X limit on the fourth tile.

## Nine entries and three alignment bytes

The initializer at `8020692C` clears nine bytes in three groups of three. The
controller export copies exactly nine bytes, and a complete extracted EN
relocation scan finds this receiving table referenced only by slot 559. The
previous twelve-byte array included three bytes between its last tile and the
descriptor. Declaring nine entries lets MWCC emit those three alignment bytes
automatically, without changing the section contents or descriptor position.

The table symbol size is corrected from 0x0C to 0x09 in EN, EN rev1, JP and
PAL rev1. EN's `.data` remains `80329A20..80329A68`, with its 60-byte descriptor
at `80329A2C`. The existing descriptor wrapper and final zero word are retained;
this table-capacity correction does not establish a different descriptor size.
The 48-byte constant pool remains `803E6408..803E6438`, and the neighboring
wall-bar and force-away units retain their boundaries.

## Validation

All ten functions remain exact, totaling 1268 code bytes and 120 data bytes in
each of the four verified versions. The only raw owner-object change is one
symbol-table byte recording the array's size, 12 to 9. Function bytes,
allocated sections, relocations and symbol positions remain unchanged, as do
all other compiled source objects. The registry's only edit is its canonical
header include.

Full source builds and fresh objdiff reports cover all four versions. EN also
passes the strict retail checksum. Formatting is committed separately and
checked for byte-identical objects. No additional matching bytes are claimed.
