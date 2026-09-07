# Staff segment transform contract

EN v1.0 `staffUpdateSegmentTransforms` at `0x8003B620` consumes two signed
16-bit controls in the staff's existing `0xC0`-byte state:

| Offset | Field | Retail evidence |
| --- | --- | --- |
| `0xB0` | `geometrySegmentCount` | Signed loop bound; `staff_init` at `0x8016EEF0` initializes it to two. |
| `0xB2` | `orientationSegmentIndex` | Selects the B endpoint used for orientation; `staff_func10` at `0x8016E8B8` stores its argument here. |

The canonical staff header asserts both offsets. The engine uses these fields
through `StaffState`; the owner keeps the same signed stores and allocation.
The existing six two-element coordinate arrays remain unchanged.

The transform loop starts at attachment index one, transforms B from the next
attachment and A from the current attachment, then advances by two attachments.
Both retail branches test the current attachment index against the count;
the B branch does not separately check the next index. That behavior is retained.
After the loop, the selected B endpoint and the last transformed A endpoint
supply the orientation vector. Although the A vector is passed to `updateSwipe`,
the current staff callback passes that argument to an unused context parameter;
it does not rewrite the vector. The selector is not clamped.

`playerStateAttack` supplies the selector from byte `0x5C` of a `0xB0`-byte
`PlayerMoveSlot`. Direct typed-array and typed-record spellings changed its
already-exact load sequence from add/lbz to addi/lbzx. The player source remains
unchanged pending a source shape that preserves that sequence.

## Public API and compiler behavior

The engine definition now agrees with its existing public pointer prototype,
and its direct caller passes pointers. Including `objprint_api.h` in the owning
TU checks that contract during compilation. The existing local aliases and casts
remain: removing them changes MWCC allocation in the transform function.

Including the header also exposed the glow setter's byte alpha definition versus
its public int parameter. An old-style C definition retains the byte parameter
while agreeing with the int prototype through default argument promotion.
Changing the definition to an int parameter instead emits an extra mask.

## Verification

The complete `objprint.o` and staff slot 226 object are byte-for-byte identical
to their pre-recovery versions, including code, symbols, data, and relocations.
Formatting the active engine TU and the relevant headers produces no changes.
This is type and field recovery; it does not claim an increase in match score.

`python3 configure.py --matching`, the 30-second-bounded `ninja all_source`,
and the strict `ninja` target pass (`main.dol: OK`). Objdiff retains the existing
matching status of both units; the complete player object also remains unchanged.
