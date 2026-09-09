# Game math literal-pool recovery

The [retail boundary audit](math_boundary_audit.md) also covers direct loads
outside current object claims, including the external power coefficients and
reciprocal constant, across four verified versions.

## Complete power-function pool

`math_802927a4.c` now emits its complete **324-byte** `.sdata2` pool using
ordinary float and double literals. This replaces 35 unresolved scalar `extern`
declarations and recovers the 280-byte prefix previously left in an automatic
gap. The EN claim now begins at `803E7AB8` and retains its end at `803E7BFC`.
The compiler supplies both four-byte alignment holes; no padding declarations,
section attributes or synthetic coefficient arrays are added.

Floating truth tests (`if (base)`, `if (fractionalExponent)`, and the equivalent
remaining checks) preserve the former zero comparisons, including signed zero
and unordered inputs. Spelling these as explicit comparisons with a literal zero
makes GC/1.3 reverse some compare operands and change load order. The truth-test
form keeps **all seven function bodies byte-identical**, with unchanged sizes,
named-symbol layouts and every function's objdiff score. Code fuzzy remains
83.927376%; this is data recovery, not another exact function.

Every one of the source's **60 EN constant-load relocations** retains its
instruction offset, destination address, width and retail payload after moving
from external symbols to local literals. All other relocations retain their
destinations. A scan of the extracted EN retail objects finds all 49 relocations
to the 35 former external symbols in this TU alone, and the source/header search
finds no other consumers. The `.text` bytes are unchanged; `.sdata2` grows from
44 to 324 bytes, preserving the old 44-byte suffix exactly.

The same source emits the identical complete object in EN v1.0, EN revision 1,
JP and PAL revision 1, each checked against its configured retail SHA-1. The
324 emitted pool bytes agree with each DOL. The secondary projection retains its
existing additional four bytes of trailing linker alignment, which objdiff
accepts: reported matched data rises **44 to 324 bytes in EN** and **48 to 328
bytes in each verified secondary version**. All four units retain 100% data
agreement and their previous code scores. The units remain `NonMatching`.

`version_progress.py --write` refreshes the three verified secondary split
claims. Unrelated symbol-file regeneration changes are discarded. PAL revision
0 remains excluded because the local file fails that version's configured hash.
All four `all_source` builds pass under their 30-second limits. Formatting is
committed separately and preserves the raw object hash:
`8dcff2a62455de4830b94f5386cfcf2b8fc21db37ba6b1e972179813ba17935e`.

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

The initial literal-only probes of `trig`, `acosf`, `sincosf` and
`math_8029454c` emitted pools in different orders from retail. Those probes
were not retained; the named-pool recovery below resolves their placement. `math_float_helpers`
also takes addresses of some named scalars, so a blanket literal substitution
does not compile. Those uses require source recovery beyond this substitution.

Local probes and relocation audits are under `build/flag_probe/`:
`math_literal_pool_probe.py`, `angle_vec_literal_probe.py` and
`math_literal_pool_audit.py`. The baseline audit uses `git show HEAD:<source>`;
pin it to the pre-change revision when rerunning after this checkpoint.

Those historical local scripts may not persist in other checkouts. The shared
`tools/pool_value_sequence.py` audit now supports version selection and a merged
`.sdata,.sdata2` scan; see `docs/pool_value_sequence.md`.

Before the named-pool recovery below, `math_float_helpers` placed the exponential
constants in 40 bytes of `.sdata` and the floor constants in 32 bytes of `.sdata2`. A merged
scan confirms identical complete SDA21 value sequences for `exp2f`, `expf`, and
`fastFloorf` in EN, EN rev1, JP, and PAL rev1 after DOL checksum verification.
The values are already correct. Literal substitution moves the floor constants
four bytes earlier or deduplicates its zero/one values; moving the named
exponential definitions before their users duplicates 32 bytes instead. Neither
probe is retained. These are placement/compiler-pooling obstacles, not evidence
for changing the coefficients or forcing padding into the source.

### Exponential and floor source contracts

The exponential result now has an explicit local union containing its float
value and unsigned binary32 word. `exp2f` first approximates `2^fraction` with
the existing degree-four polynomial, then adds the signed integer exponent
to the exponent bits through an unsigned shift. This replaces dereferencing
an incompatible `u32*` over a float local. The native union emits the identical
complete object before any symbol renaming.

Fourteen consumed constants now have shared names in the source and the four
verified version configs. The names distinguish the exponential underflow
threshold, zero/one and fractional polynomial coefficients from the floor
routine's independent pool. The log2(e) conversion record retains its eight-byte
extent: only its first word is consumed, and its zero tail remains unexplained.
The separate unreferenced trailing floor word is also retained without assigning
it a role. No constant definition moves or changes type or value.

Regional names are assigned by offsets within the byte-identical 72-byte retail
pool, not by the address suffix of an old anonymous label. Some EN-style labels
still identify unrelated native-address constants in secondary configs. Those
unrelated records retain their names; the new semantic names identify the actual
math pool at EN rev1 `803E8610`, JP `803E7A98`, and PAL rev1 `803E9370` (EN
`803E7978`). All existing addresses, extents, and symbol attributes are preserved.

The floor thresholds describe two conversion paths: absolute values below
65,536 use unsigned-halfword fast casts; values below 8,388,608 use integer
conversion. Negative fractional values then receive the demonstrated correction.
Larger magnitudes return the input. This is the retail approximation's contract,
not a replacement with host `floorf` or a claim about every exceptional input.
Likewise, the exponential's explicit early return below -127 and its unchecked
exponent-word adjustment are preserved rather than replaced with host `exp2f`.

Apparently redundant float-address views in `expf` and `fastFloorf` remain:
removing them changes the generated object with the current compiler. The
existing per-function optimization pragmas and fast-cast assembly are unchanged.
All eight function bodies, allocated section bytes/layouts, and relocation
destinations are identical in EN, EN rev1, JP, and PAL rev1, modulo the fourteen
symbol names. Every other source object and all objdiff scores are unchanged.
The data placement mismatch described above remained at that checkpoint. Each
input DOL passes its configured hash; all four `all_source` builds and the strict EN checksum pass.

## Tangent units and the bitwise log estimate

The tangent helper's locals now distinguish an even octant count from the
remainder in **pi/4 units** returned by `trigReduceQuadrant`. Its four odd-power
coefficients are named `sTanReducedCoeff1/3/5/7`; they approximate the tangent
of the scaled remainder, not a polynomial taking radians directly. Bit 1 of
the even octant count selects the negative reciprocal. The final comparison
still preserves the original unordered-input sign path.

`log2fBitEstimate` now constructs its normalized mantissa through an explicit
float/word union. For normal inputs and the usual fast-cast register setup,
its expression is the raw exponent minus 127 plus the mantissa fraction. The
source subtracts 128 because the constructed float already includes a leading
one. It ignores the input sign and does not implement libm special cases:
zero produces -127, infinity produces 128, and NaN payload bits participate in
the finite estimate. The public declarations record those contracts.

The six constant identifiers are propagated to all four verified symbol
configs without moving data or changing sizes. All function instructions,
allocated section bytes, symbol layouts after renaming, and relocation
destinations remain unchanged in each source object. Every function score and
target's aggregate report measures remain unchanged. Literal and local-constant
probes move the tangent coefficients into `.sdata2` but place the negative-one
and zero values after the polynomial coefficients; that incorrect order is not
retained at that checkpoint. The named-pool recovery below resolves the
24-byte tangent pool's placement.

## Complete exponential/floor pool from named constants (2026-09-08)

The exponential definitions now precede their consumers. This lets GC/1.3 place
those 40 bytes in `.sdata2`, adjoining the floor constants and the compiler's
integer-conversion bias. The complete **72-byte** section matches retail in EN,
EN rev1, JP, and PAL rev1. No split, coefficient value, symbol name, compiler
profile, pragma, or matching classification changes.

Moving the definitions alone produces a 104-byte section: scalar constant
propagation emits another 32 bytes of anonymous literals and changes two
instruction bytes in `exp2f`. The exponential now uses the address-based
constant access idiom already present in `fastFloorf`, retaining `const` on the
pointer view. These reads preserve the named constants without duplicate
literals. Plain scalar access, `*&constant`, and `(&constant)[0]` all retain the
duplication; the explicit pointer view matters to this compiler. This is an
observed declaration/access model, not proof of the original source spelling.
The floating objects are read through their own type without discarding const
or introducing aliasing between incompatible types.

The nine exponential definitions retain offsets 0 through 32 in their new
section. The floor definitions begin at offset 40, their unused zero word is
at 60, and the anonymous eight-byte conversion bias is at 64. The unused tail
words stay unexplained. All named consumed constants agree with their regional
retail offsets; the unused address-labeled floor word is compared by position
and bytes because its retail label is region-specific.

All eight function bodies remain byte-identical. Every source relocation is
checked at its instruction offset, retaining its loaded width, payload and
intended offset within the retail pool; non-pool destinations are unchanged.
The source and retail functions consume the same 19 SDA21 values in the same
order. The full section bytes are independently compared with each SHA-1-verified
DOL, including unused words and alignment. Reproduce the load-sequence check
for each version with:

```sh
python tools/pool_value_sequence.py \
  src/dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.c --version GSAE01
```

Objdiff credits **72 additional matched data bytes in each verified version**,
raising this TU's data match from zero to 100%. Code fuzzy remains 70.99383%
and one of eight functions is exact; the unit stays `NonMatching`. Every other
source object and every other objdiff unit remains unchanged. All four
`all_source` builds and the strict EN retail checksum pass with 30-second
limits. Formatting is checked separately for unchanged object output.


## Complete named trigonometric pools (2026-09-08)

The exponential/floor declaration model also recovers all four remaining
trigonometric constant pools. Each TU defines its existing named constants
before the functions, in the original definition order, and reads them through
same-type `const` pointer views. The redundant forward declarations are removed.
GC/1.3 emits the same bytes directly into `.sdata2`, without additional literal
copies. The existing float/double distinctions and all polynomial grouping are
preserved; no arrays, padding declarations, section attributes, compiler changes,
or version-specific source branches are introduced.

| TU | Newly matched bytes | Unchanged functions | Ordered constant loads |
| --- | ---: | ---: | ---: |
| `acosf` | 248 | 8 | 143 |
| `trig` | 192 | 8 | 138 |
| `sincosf` | 32 | 1 | 11 |
| `math_8029454c` | 24 | 2 | 6 |
| Total | **496** | **19** | **298** |

These results hold for EN, EN rev1, JP, and PAL rev1. For every version, the
complete section bytes agree with the SHA-1-verified retail DOL, including the
inverse-trigonometric pool's double-alignment gaps. Each named constant retains
its offset, size, linkage, and visibility, with only its source section changing
from `.sdata` to `.sdata2`; its new location agrees with its regional retail
symbol. No symbol configs or split claims change.

Every function instruction is byte-identical. All relocation records are
compared at their exact instruction offsets, preserving constant name, pool
offset, load width, and payload. Non-pool relocation destinations remain
unchanged. The 298 source constant-load values also match retail's per-function
sequences. This checks placement independently of objdiff's byte accounting;
no runtime arithmetic rewrite needs a new approximation oracle.

All four units now have 100% data matching. Their code scores remain unchanged,
and the units remain `NonMatching`; the unmatched save/restore and other code
sequences still need recovery. Every unrelated source object and objdiff unit
is unchanged. All four full source builds and the strict EN retail checksum
pass with 30-second limits. Formatting is committed separately. All function
bytes, allocated sections, symbols and relocations remain identical in all four
versions; only the existing `-sym on` debug `.line` records change to track the
new source line numbers. All other ELF section contents are checked unchanged.

The address-based spelling is a compiler-observed way to preserve named pools,
not a claim to have recovered the original source syntax. The separate pool and
function-boundary evidence remains in [the retail audit](math_boundary_audit.md).
Reproduce the load checks with `tools/pool_value_sequence.py`, selecting each
source path above and each verified `--version`.


## Explicit binary32 storage in the power routines (2026-09-08)

The three power approximations now model their local normalized mantissas and
results as unions of `float value` and `u32 bits`. This replaces incompatible
pointer accesses over six float locals while retaining the same storage and
expression order. The two polynomial cores add `(u32)resultExponent << 23` to
the result word: conversion to unsigned before shifting expresses the retail
32-bit wraparound even for negative exponents. It does not introduce a clamp,
a numeric multiplication, or a library power call.

EN supplies direct instruction evidence for these views:

- `powfCoreHighPrecision` at `802927A4` masks the base's mantissa, inserts
  `0x3F800000`, and stores a word at `802927E8` before reading it as a float.
  At `80292980..80292990`, it reads the result as a word, shifts the signed
  exponent by 23, adds the words, and reads the stored result as a float.
- `powfCoreFast` at `802929CC` performs the same mantissa construction. Its
  signed halfword exponent is loaded at `80292AF8` before the word shift/add.
  The existing fast-cast calls and their quantization-register contract remain.
- `powfBitEstimate` at `80292B44` scales its exponent estimate by 8,388,608,
  converts to an integer, and adds the binary32 representation of one.
  Its negative-base correction toggles the result's sign bit with `xoris`
  at `80292BEC`, matching the union's word XOR.

For ordinary normal inputs, the mantissa construction produces a value in
`[1, 2)`. The polynomial cores approximate the logarithm and fractional power
before modifying the exponent word. The bit estimate uses the mantissa itself
as a linear log estimate; its subtraction of 128 accounts for the leading one.
All three retain the zero-base branch and the negative-base sign rule based on
the truncated power's parity. These are the existing approximation contracts,
not libm special-case handling or newly established accuracy guarantees.

The input parameter's existing word view remains. Moving it into a separate
local union changes the observed parameter spill/reload and register allocation;
that probe is not retained. The local union spelling establishes an explicit
storage interpretation, not the original author's exact C syntax.

Every source object is byte-identical in EN, EN rev1, JP, and PAL rev1; fresh
objdiff reports are unchanged. Each DOL passes its configured SHA-1. All four
`all_source` builds and the strict EN checksum pass within 30 seconds. The
complete power object retains its seven function bodies, 324-byte literal pool,
symbols and relocations. Formatting is committed separately and checked for
unchanged object output. This recovery claims no additional matched bytes.
