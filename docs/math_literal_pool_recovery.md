# Game math literal-pool recovery

The [retail boundary audit](math_boundary_audit.md) also covers direct loads
outside current object claims, including the external power coefficients and
reciprocal constant, across four verified versions.

## Shared sine/cosine sign handling under GC/1.3

`mathSinCosf` now conditionally negates the existing approximation in switch
cases zero and two. The previous self-selecting ternaries made GC/1.3 introduce two
additional floating-point temporaries, six register copies/branches, and eight
associated save/restore instructions. The source now uses the same conditional
assignment shape as the other two quadrant cases.

The condition deliberately remains `!(angle >= gSinCosZero)`: replacing it with
`angle < gSinCosZero` would change the unordered/NaN case. Polynomial evaluation,
coefficient types, quadrant selection, and output-store order are unchanged.

The shared source improves **38.6375% to 54.6375%**, shrinking from **109 to 95
instructions**, against retail's 80. This result is identical for EN v1.0,
EN revision 1, JP, and PAL revision 1. Each DOL passes its configured SHA-1;
their address-normalized retail function bodies agree. All four builds emit
the same before and after objects. PAL revision 0 is not claimed here because
the local file at its path does not have that target's configured hash.

Among allocated sections, only `.text` changes. All allocated non-text bytes,
layouts, and named constants are preserved, including the complete 32-byte
coefficient pool. The TU remains `NonMatching`; remaining differences include
the current compiler's prologue/epilogue. Compiler profiles and regional
matching classifications are unchanged.

A temporary host differential harness compares 2,560 before/after calls at
each of `-O0` and `-O2`, with bit-identical outputs. It supplies quadrant and
reduced-angle values to exercise every switch path, ignored quadrant bits,
positive/negative zero, subnormals, infinities, NaNs, and aliased output pointers.
This checks the sign-handling rewrite, not the real quadrant reducer or overall
trigonometric accuracy. Formatting preserves the raw object. EN `all_source`
and the strict retail checksum gates pass with 30-second limits.

## Shared power-function result selection under GC/1.3

The high-precision and fast power cores now assign their fractional-exponent
approximation through `if`/`else`. Each former ternary required an additional
saved FPR under GC/1.3. Explicit assignments remove its four save/restore
instructions while adding one branch-local result store, reducing each function
by three instructions. The comparisons, polynomial expressions and their
precision, negative-base sign handling, and final exponent-bit adjustment are
unchanged.

| Function | Before | After | Retail / new instructions |
| --- | ---: | ---: | ---: |
| `powfCoreHighPrecision` | 84.253624% | 86.71739% | 138 / 147 |
| `powfCoreFast` | 81.76596% | 85.489365% | 94 / 103 |

These results hold for EN v1.0, EN revision 1, JP, and PAL revision 1, using
SHA-1-verified DOLs with identical address-normalized retail bodies. The four
builds emit the same complete source object. The other five function bodies,
all allocated non-text bytes and named layouts, and every function's ordered
relocation destinations are unchanged. Later text symbols move back 24 bytes;
the local vector calls continue to resolve to those same functions. The existing
44-byte literal pool is preserved. No compiler settings, splits, or matching
classifications change; the unit remains `NonMatching`.

A temporary host harness compares 4,514 input pairs through both complete power
cores: 9,028 bit-identical before/after results at each of `-O0` and `-O2`.
It covers zero bases, positive and negative bases, integral and fractional
powers, and fractional-exponent branch boundaries. It uses retail coefficient
values and host casts in place of the fast conversion helpers, with strict
aliasing disabled for the existing float/word accesses. This is a differential
check of the rewrite, not PowerPC conversion emulation or a libm accuracy claim.
Formatting is separate and preserves the raw object. EN `all_source` and the
strict retail checksum gates pass with 30-second limits.

## September 6: Three complete pools under GC/1.3

The following units now use ordinary typed numeric literals instead of late
`extern const` definitions. MWCC emits their complete retail constant pools
without section attributes, synthetic arrays or extra definitions.

| Unit | Functions | Exact pool bytes | Code fuzzy, unchanged |
| --- | ---: | ---: | ---: |
| `main/math_8029312c` | 3 | 12 | 81.63636% |
| `main/trig_float_helpers` | 4 | 80 | 59.221153% |
| `dolphin/MSL_C/PPCEABI/bare/H/math_80293da4` | 7 | 184 | 83.05306% |

Thirty-six named scalar definitions and their forward declarations are removed.
Float suffixes and double precision are preserved. The reciprocal helper's
external `sFastReciprocalTwo` is not part of the angle-vector pool and remains
external. No removed definition has a source consumer outside its owning TU.

The angle-vector polynomials use a consistent Horner form with `angleSquared`
on the left of each nested product. Substitution alone reversed two functions'
multiply-add operands; this source form preserves their original instructions
while retaining the exact pool. Evaluation still follows the same polynomial
degrees, intermediate precision and fused operations.

All 14 function byte sequences are identical to the preceding source objects.
An isolated rebuild of the preceding sources reproduces their recorded SHA-256
hashes. Auditing all relocations verifies 159 local floating-point loads retain
their exact four- or eight-byte payloads; other relocation records are unchanged.
The new pools have exactly the retail sizes, eight-byte alignment and contents.
MWCC marks its `.sdata2` object section writable while the extracted retail
object does not; this is not a claim of identical ELF metadata or complete TUs.

Objdiff now credits 276 additional data bytes. Code, compiler versions, compiler
flags, matching classifications, splits and active-target symbols are unchanged.
The units remain `NonMatching`: the strict DOL gate links their retail objects,
so it supplements rather than replaces the source-object comparison.

## Remaining evidence

The square-root arithmetic already agrees instruction-for-instruction with
retail apart from its prologue and epilogue. GC/1.3 emits paired-single saves
and restores absent from retail. Changing only `-proc gekko` to `-proc 750`
does not remove them; that ineffective flag experiment is not retained.

Literal-only probes of `trig`, `acosf`, `sincosf` and `math_8029454c` emit pools
in different orders from retail. None is landed here. `math_float_helpers`
also takes addresses of some named scalars, so a blanket literal substitution
does not compile. Those uses require source recovery beyond this substitution.

Local probes and relocation audits are under `build/flag_probe/`:
`math_literal_pool_probe.py`, `angle_vec_literal_probe.py` and
`math_literal_pool_audit.py`. The baseline audit uses `git show HEAD:<source>`;
pin it to the pre-change revision when rerunning after this checkpoint.

Those historical local scripts may not persist in other checkouts. The shared
`tools/pool_value_sequence.py` audit now supports version selection and a merged
`.sdata,.sdata2` scan; see `docs/pool_value_sequence.md`.

The current `math_float_helpers` object places the exponential constants in
40 bytes of `.sdata` and the floor constants in 32 bytes of `.sdata2`. A merged
scan confirms identical complete SDA21 value sequences for `exp2f`, `expf`, and
`fastFloorf` in EN, EN rev1, JP, and PAL rev1 after DOL checksum verification.
The values are already correct. Literal substitution moves the floor constants
four bytes earlier or deduplicates its zero/one values; moving the named
exponential definitions before their users duplicates 32 bytes instead. Neither
probe is retained. These are placement/compiler-pooling obstacles, not evidence
for changing the coefficients or forcing padding into the source.
