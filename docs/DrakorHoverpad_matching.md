# DLL 625: complete EN match

The September 6, 2026 pass starts at `56de130706`. The complete TU at
`src/dlls/objects/625/625.c` now links from source for GSAE01: all 29
functions (7,176 bytes) and all 384 assigned data bytes match retail.

The TU retains the common game compiler, GC/1.3, and its existing
`nopeephole,noschedule` optimization profile. Automatic inlining replaces
the previous `noauto` exception. Three ordinary static curve helpers are
defined before the route-walking functions: initialization, sine tangent,
and cosine tangent. Their calls inline as in retail, while their initial
compilation emits the constants in the required order. Explicit `inline`
definitions do not reproduce that emission order, even at the same source
positions. Moving the initialization helper alone is also insufficient.

Using the float literal `2.0f` removes the named speed-step constant and
the cast that previously bypassed its const qualification. This also
removes a duplicate anonymous `2.0f` from the pool. The resulting 104-byte
`.sdata2` matches retail byte for byte, including its eight-byte alignment
and the padding before the integer-conversion constants.

Path event 16 computes the absolute command speed before capturing the
signed value used by either multiply. MWCC combines the repeated field
reads and retains retail's floating-point load order and registers.
Capturing the signed value before the absolute-value expression instead
hoists the comparison constant and introduces a reload in the doubling
branch when using literals.

The complete data match and source-linked DOL checksum also validate the
descriptor, generated switch table, and packed `.sdata` symbol offsets.
The generated slot path and existing descriptor position are unchanged.
`ninja all_source` and the strict matching `ninja` both pass with their
30-second timeouts. The separate formatting commit is checked for object
equality and with `clang-format --dry-run --Werror` on the TU and header.

## Source recovery on the complete match

The path-event handler's four copies of the bounce sequence (reverse the
speed at 0.8, clear the commanded speed, shake the camera while the player
is riding) now come from one static helper, as in the Dinosaur Planet mine
cart (`734_DR_PushCart`, `dll_734_func_133C`). Automatic inlining
reproduces all four copies; the helper sits between the direction poll and
the event handler so its `0.8f` constant enters the pool after the direction
poll's `-2.0f`, keeping the retail `.sdata2` order. A single sine/cosine
tangent helper with a mode flag changes the walker function, so the two
tangent helpers stay separate; the node-slot macros in the walker are
replaced with direct calls.

The three vehicle callback slots that had numeric names take the names of
their `VehicleInterface` slots (getNormalizedSpeed, resetToRomListPosition,
getLookTargetYaw); the direction poll and the segment advance are named
updateDirection and advanceToNextSegment, and the three `.sdata` literals
are the roll scale and the camera Y/Z offsets. The renames are applied to
all five version symbol tables; `pairing_check.py` reports no retail-only
symbols, and the unit stays at 100% code and data.
