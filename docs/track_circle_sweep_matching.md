# Circle-to-point sweep matching

`trackSweepCircleAgainstPoint` now matches all 164 EN v1.0 retail instructions
under the existing game GC/1.3 profile. Its 656-byte body improves from
99.939026% to 100%; `track_dolphin` has 23/30 exact functions, up from 22/30.

The initial circle-distance calculation squares the X-distance temporary in
place and forms `quadraticC` directly from the two squared distances and radius.
The former `startDistanceSq` local is named `startDeltaXSq` because it holds only
the X contribution. Arithmetic order and the collision/response branches are
preserved.

Assigning the X square in one expression leaves the sum in `f1` instead of the
retail `f0`. Merely introducing a separate sum fixes that register choice but
moves the X multiply after the Z load and subtraction. The in-place square plus
direct coefficient calculation reproduces both the retail operation order and
registers. This resolves the older worklist's claimed source-level closure.

The object comparison changes only two bytes in this function. All other 29
function bodies, relocation records, named-symbol layouts, and non-text section
bytes remain identical. Formatting the TU and `track_line.h` produces no source
change and preserves the raw object hash.

Both `ninja all_source` and the strict retail checksum build pass. The TU remains
`NonMatching` for its other functions; the strict link therefore uses its retail
object. Instruction identity for this function is established separately by
objdiff and the instruction comparison.
