# Remaining core math: exact recovery

The user extended the GC/1.2.5n compiler exception to these seven `main/`
units on 2026-09-20. All 25 functions now match retail code and data. Together
with the four previously matched `MSL_C` units, the complete eleven-unit
core-math family has 49 exact functions, 10,584 code bytes and 1,196 data bytes.
This count describes that family, not every math-related operation in the game.
Exact reconstruction does not establish game authorship or MSL membership;
see the [compiler and provenance investigation](compiler_gc125_investigation.md).

| Unit | Previous EN code fuzzy | Final code/data | Functions |
| --- | ---: | ---: | ---: |
| `acosf.c` | 75.160446% | 100% / 100% | 8 |
| `math_80292d3c.c` | 59.060608% | 100% / 100% | 1 |
| `reciprocal.c` | 84.46154% | 100% / 100% | 1 |
| `trig_float_helpers.c` | 69.17949% | 100% / 100% | 3 |
| `math_8029312c.c` | 85.69697% | 100% / 100% | 3 |
| `trig.c` | 83.592026% | 100% / 100% | 8 |
| `sincosf.c` | 60.7% | 100% / 100% | 1 |

The seven units contribute 6,300 code bytes and 592 data bytes. They retain
their existing TU boundaries, constant pools and game category. All use
GC/1.2.5n; `trig_float_helpers.c` and `sincosf.c` additionally use TU-level
`-opt functions`. No assembly or source pragmas are added.

## Source and ABI evidence

Separate locals recover the retail lifetimes of absolute values, reduced
angles, squares, roots and polynomial results. The reciprocal needs only the
compiler change. `atanf` uses a `register float` absolute-value local and
separate, sequenced division and squaring statements. This selects the retail
FPRs without restoring the earlier undefined, unsequenced expression.

The combined sine/cosine function uses conditional expressions in its first
two quadrant cases. These preserve the original zero/NaN comparison and the
retail branch structure. Polynomial evaluation and output-store order remain
unchanged.

Six integer-angle trig functions have an `int` public interface but need a
two-byte parameter slot internally. Simply changing their prototypes to `u16`
changes code in `shader.c`, `intersect_memcard.c`, and object DLLs 211 and 229,
including already-exact callers. Old-style C definitions with a `u16` parameter
are compatible with the existing promoted `int` prototypes under this compiler.
They reproduce the exact callee stack layout and leave all four caller objects
unchanged, including their relocations and symbol layouts. This is a supported
reconstruction of the observed interface, not proof of the original spelling.
The two Approx functions retain their existing `u16` prototypes.

## Verification

EN `all_source`, the complete objdiff report, and the strict retail checksum
pass with all seven source units included. The DOL SHA-1 remains
`e750e8e894707a52446118a4b84f1b58b677b269`.

EN revision 1, JP, PAL and PAL revision 1 each pass input-DOL hash verification,
`all_source`, and 100% code/data reports for all seven units. For each region,
`tools/verify_source_link.py` verifies both the all-retail link and a complete
DOL with all seven source objects substituted together. Their exact units are
recorded in the regional matching manifests.

The compiler-profile tests and existing host `atanf` range-reduction tests pass
(14 tests). The latter check debug and optimized host builds, including signed
zero, subnormals, reduction boundaries, infinities and NaNs, and reject
unsequenced expressions during compilation.
