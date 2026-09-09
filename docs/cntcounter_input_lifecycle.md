# CNTcounter input lifecycle

DLL 692's nine EN functions occupy `802383E0..8023852C`. Its only data is the
terminal 56-byte descriptor at `8032BE88..8032BEC0`; it owns no constant pool.
The generated `692_CNTcounter/CNTcounter.c` path remains unchanged.

`CntCounter_getExtraSize` returns eight bytes: a signed remaining count at
offset zero, an unsigned HUD selector at four, and three opaque bytes.
Initialization clears the two recovered fields. It does not read the initial
placement count, modify either game bit, or reset the shared HUD number.

The update at `8023842C` uses one game-bit field for two roles:

1. When the remaining count is zero, a nonzero input loads the placement's
   initial count and HUD selector. It leaves the input pending.
2. On a later update with a nonzero count, it publishes the current count to
   the HUD if enabled, then reads the input. A nonzero input is cleared and
   its full value is subtracted from the remaining count.
3. If that subtraction leaves a nonpositive result, the count is clamped to
   zero, the done bit is set, the HUD is hidden if enabled, and the local HUD
   selector is cleared. This DLL does not clear the done bit on restart.

The canonical field name `countInputGameBit` reflects both starting and
counting. The consumed local remains signed `int`, preserving the retail
subtraction and signed completion comparison. `mainGetBit` can return a
multi-bit value; the source does not replace it with a boolean. Zero initial
counts keep taking the idle branch without consuming the input. Negative
initial counts are also preserved, with completion checked only after a
nonzero input is consumed.

`hudNumberSet` at `800140B4` writes one shared global. Its renderer hides only
the `-1` sentinel and submits other values to text box 13. The counter publishes
the pre-decrement value, so a nonterminal decrement appears on a subsequent
update. Freeing a HUD-enabled counter hides that shared value without an
ownership check. None of these timing or ownership behaviors are changed.

The placement reader has a HUD byte at `0x19`, signed initial count at `0x1A`,
signed done-bit ID at `0x1E`, and signed input-bit ID at `0x20`. Unaccessed bytes
remain opaque. No EN allocation or serialized width was established; the
canonical type is a prefix through `0x21`, with field offsets asserted rather
than an invented full size.

EN rev1 and JP each contain one 36-byte CNTcounter placement, object `0x6BB`,
in `hollow.romlist.zlb` at offset `0x8248`. Both records specify count one,
HUD disabled, input `0xA2D` and done bit `0xA2F`. Their BITTABLE entries are
one-bit fields in bank zero. This corroborates the secondary placement and
usage without narrowing the generic code or claiming an EN record width.

The nine owner functions plus the two game-bit helpers and two HUD helpers have
equal normalized instruction signatures across the four verified EN, EN rev1,
JP and PAL rev1 DOLs. Source recovery preserves complete compiled objects and
the existing exact match. Four-version source builds and full objdiff reports,
followed by the strict EN retail checksum, gate the change.
