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
