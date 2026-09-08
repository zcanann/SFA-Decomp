# Retail math boundary audit

September 8, 2026; source baseline `51367a241e`, GC/1.3 game compiler.

Follow-up: [the complete power pool is now recovered](math_literal_pool_recovery.md#complete-power-function-pool).
The tables below describe the pre-recovery claims; the power unit's 280-byte
gap has since been claimed with an exact literal pool and unchanged code.
The [reciprocal boundary repair](reciprocal_boundary_recovery.md) also separates
the reciprocal helper from the three angle-vector approximations and recovers
its four-byte constant without changing their compiler profiles or code.

The remaining low math scores are not evidence that donor MSL implementations
generally failed. All **28 active MSL units outside the four game-category math
paths** have 100% code fuzzy agreement in the current EN report. The ten older
game-category math units are a separate frontier. Their current category and
filenames are hypotheses about provenance, not independent proof of Rare
authorship or compiler version.

## What the DOL says about the splits

`tools/retail_pool_audit.py` reads the hash-verified retail DOL directly. It
derives r2 from `__init_registers`, scans the executable sections for supported
direct r2 loads into `.sdata2`, and associates each full-width load with the
current text and data claims. It includes constants in automatic gaps that an
object-local relocation check cannot see. JSON retains every instruction address,
load width, payload, function, source claim and pool claim.

The EN interval `80291CBC..80294640` contains the ten math units and `rand`:

| Current unit | Direct loads | Distinct address/width pairs | Loads outside its pool claim |
| --- | ---: | ---: | ---: |
| `math_float_helpers` | 19 | 15 | 0 |
| `acosf` | 143 | 41 | 0 |
| `math_802927a4` | 60 | 45 | 49 |
| `math_80292d3c` | 3 | 3 | 0 |
| `rand` | 0 | 0 | 0 |
| `trig_float_helpers` | 23 | 21 | 2 |
| `math_8029312c` | 12 | 3 | 0 |
| `trig` | 138 | 34 | 0 |
| `sincosf` | 11 | 8 | 0 |
| `math_80293da4` | 126 | 33 | 0 |
| `math_8029454c` | 6 | 6 | 0 |

The 51 outside-claim loads all target automatic gaps, not another source's
claimed pool:

- Power routines reference **272 distinct bytes** within the 280-byte interval
  `803E7AB8..803E7BD0`. The difference is eight bytes not read by these supported
  loads; this audit does not assign them a meaning. The existing source retains
  external constants here.
- `fastReciprocal` loads the four-byte `sFastReciprocalTwo` at `803E7C18` twice.
  Its neighboring angle-vector pool starts at `803E7C20`.

No supported direct loads elsewhere in the DOL reference the selected units'
claimed pools or overlap the constant bytes read by these 51 functions. This is
a useful ownership constraint, not a proof of complete reference coverage.
Indexed accesses, materialized pointers, paired-single accesses and other base
registers are not scanned. Decoding executable bytes is not a reachability proof.

Several groups share the same *addresses* across their functions: the inverse
trig family, integer-angle sine/cosine family, radian sine/cosine family, and
square-root trio. That supports keeping those groups together. Conversely,
`exp2f` and `fastFloorf` use different zero and one constants within the current
`math_float_helpers` claim (`803E797C/803E79A4` and `803E7980/803E79B0`). Separate
original files are one possible explanation, but named constants and compiler
pooling are others. This evidence alone does not justify splitting the TU.

The exact same normalized evidence holds for **EN v1.0, EN revision 1, JP and
PAL revision 1**: 51 normalized PPC function signatures,
541 ordered direct loads with equal payloads and function-relative instruction
offsets, the same claim relationships, and no outside consumers in this scan.
Each input passes its configured SHA-1. PAL revision 0 is excluded because the
local file at its path is revision 1 and fails the configured hash.

## Why donor source and boundaries do not close the code gap

The local Melee and Sunshine MSL `trigf.c` implementations use
`__four_over_pi_m1`, `__sincos_poly` and `__sincos_on_quadrant` tables. SFA already
has that MSL family at `802947CC..80294BB8`, with a 100% unit. The preceding
low-scoring radian family instead calls `trigReduceQuadrant` and evaluates
several different scalar polynomial approximations. These are distinct
implementations present in the same retail binary, not merely different names
for the same donor function. A search for several distinctive coefficient
spellings across the available reference sources found no match; that negative
search does not establish the original library or author.

`source_leaks.py` and `source_matrix.py` provide no matching direct source-name
evidence for these math filenames. Historical rehoming commits `4876820fab` and
`45c4a69347` correctly rejected incompatible fdlibm function identities, but
their link-order and current-cflags arguments should not be elevated into proof
of source provenance or exact TU boundaries.

For `mathTanf`, retail has **37 instructions / 148 bytes**, while the current
source produces **48 instructions / 192 bytes** and scores **43.675674%**.
Retail calls `_savefpr_28` and `_restfpr_28`; GC/1.3 emits individual double and
paired-single saves/restores for f28–f31. The polynomial and quadrant body
already agree closely. The extra parameter copy in retail and frame offsets
are additional differences. Changing a data boundary cannot itself remove this
save/restore disagreement. The earlier independent compiler controls are
recorded in [the compiler migration audit](compiler_gc13_migration.md).

No compiler profiles, text boundaries or data claims change in this audit.
Claiming the incomplete pools still requires source that emits their actual
layout without duplicate constants or synthetic placement, followed by object
and strict DOL checks. This work adds visibility; it claims no new source match.

## Reproduce

```sh
python3 tools/retail_pool_audit.py \
  src/dolphin/MSL_C/PPCEABI/bare/H/math_802927a4.c \
  src/main/trig_float_helpers.c
python3 tools/retail_pool_audit.py src/main/trig.c --version GSAJ01 --json
python3 -m unittest discover -s tools -p test_retail_pool_audit.py -v
```

Pass any exact source path from the selected version's `splits.txt`; several
sources can be inspected together. `incoming` reports outside loads into the
selected pool claims. `other_consumers` also finds outside loads overlapping
the selected sources' referenced bytes in unclaimed gaps. Neither field treats
a shared global as an automatic split error. Load counts retain repetitions;
the Markdown detail table groups repeated loads by function/address/width.

Synthetic DOL tests exercise signed displacements, load widths, complete-span
ownership, unclaimed and foreign data, unnamed code, repeated loads, outside
consumers of automatic gaps, invalid startup patterns and hash rejection.
All 21 pool-audit tests pass. EN `all_source` and the strict retail checksum
also pass, each within its 30-second limit (20.87 and 24.07 seconds).

## Vector helper type recovery

The shared vector API now uses `const Vec*` inputs and `Vec*` outputs. Its
lighting consumers pass their existing local/world direction vectors directly;
the redundant scalar direction aliases are removed, with offsets asserted at
`0x28`, `0x34` and `0x40`. In-place normalization and the original squared-length
expression order are preserved.

`Vec_normalize` is another example of a misleadingly low aggregate score:
**75.52941%**, despite both retail and source having 17 instructions. EN retail
at `80292C30` and the reconstructed body both retain the input in r31, preserve
the output pointer on the stack, and call `Vec_lengthSquared`, `invSqrt`, then
`Vec_scale`. The differences are the frame size (24 versus 32 bytes), stack
slot offsets, and prologue/epilogue instruction ordering. Its two vector callees
already match exactly. There is no constant pool involved in these helpers.

The type recovery leaves every existing source object byte-identical in all
four hash-verified targets, including the exact lighting TU; it does not claim
a score increase or establish a different compiler profile.
