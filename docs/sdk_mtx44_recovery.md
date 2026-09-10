# Recovering the SDK matrix constant pool

`dolphin/mtx/mtx44.c` previously reproduced its 24-byte pool with six named
constants, redundant extern declarations, and casts that prevented constant
folding. Four of the EN-address identities mapped to unrelated EN rev1 data;
two collided with retail definitions in `DR_Creator.o` during source linking.

The SDK implementation provides a stronger reconstruction. Both Mario Party 4
and Pikmin 2 place `C_MTXFrustum` before `C_MTXPerspective` and `C_MTXOrtho` in
their `mtx44.c`. The existing SFA SDK header already declares that public API.
Restoring the complete frustum function and using ordinary literals in the
other two functions produces the exact retail constant pool naturally:

| Offset | Value | Raw word |
| --- | --- | --- |
| `00` | 1 | `3F800000` |
| `04` | 2 | `40000000` |
| `08` | 0 | `00000000` |
| `0C` | -1 | `BF800000` |
| `10` | 0.5 | `3F000000` |
| `14` | Degrees to radians | `3C8EFA35` |

A control compilation of the same clean source without `C_MTXFrustum` instead
emits the order 0.5, degrees-to-radians, 1, 0, -1, 2. This explains why simply
replacing the old named loads with literals loses the pool match. The retained
function is the real SDK API and implementation, not an invented helper whose
only purpose is to emit constants. Its original presence in this particular
archive is inferred from SDK lineage and the compiled pool; there is no retained
SFA frustum body to compare against.

The rebuilt object emits a 156-byte `C_MTXFrustum`, which the linker discards.
The two retained retail functions still match all 360 code bytes, and their
24-byte pool matches exactly. No split, compiler profile, pragma, alignment,
retention directive, or progress annotation changes. The six named constant
definitions and every casted load are removed. `MTXDegToRad` supplies the SDK's
existing conversion constant.

## Cross-version evidence

Both retained functions have globally unique normalized correspondences in
all five verified originals. Nine retail r2-relative loads per version establish
all six constants independently; every reference agrees with its TU-owned pool.

| Version | Pool start | Pool end (exclusive) |
| --- | --- | --- |
| EN | `803E7630` | `803E7648` |
| EN rev1 | `803E82C8` | `803E82E0` |
| JP | `803E7750` | `803E7768` |
| PAL v1.0 | `803E8E60` | `803E8E78` |
| PAL rev1 | `803E9028` | `803E9040` |

All five versions pass direct objdiff comparisons with completion annotations
disabled, source builds, and original-DOL comparisons with this matrix unit
and the repaired player unit substituted together. The source-only frustum
function does not increase the reported retail function count. This is an SDK
source reconstruction; it does not alter the separate older game-math compiler
investigation.

Donor files inspected: `reference_projects/marioparty4/src/dolphin/mtx/mtx44.c`
and `reference_projects/pikmin2/src/Dolphin/mtx/mtx44.c`. The donor directories
remain unchanged.
