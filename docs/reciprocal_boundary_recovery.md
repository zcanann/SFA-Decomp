# Reciprocal / angle-vector boundary

The reciprocal helper and the three integer-angle vector approximations now
have separate source units. This corrects a best-effort historical grouping;
it does not introduce different compiler settings for the functions.
`reciprocal.c` describes the recovered role. The original filename is unknown.

## Retail evidence

In EN v1.0, `fastReciprocal` occupies `80292DEC..80292E20`. Its two direct
constant loads both read the float `2.0f` at `803E7C18`. The three following
angle-vector functions occupy `80292E20..8029312C` and share an 80-byte pool
beginning at `803E7C20`. The intervening four bytes are zero alignment space.
The direct-load audit finds no other consumers of the reciprocal constant.
As documented in [the broader boundary audit](math_boundary_audit.md), this
scan does not cover indexed accesses or materialized pointers.

The same boundary and bytes recur in every hash-verified available version:

| Version | Reciprocal text | Reciprocal constant | Angle-vector pool |
| --- | --- | --- | --- |
| EN v1.0 | `80292DEC..80292E20` | `803E7C18` | `803E7C20..803E7C70` |
| EN revision 1 | `8029354C..80293580` | `803E88B0` | `803E88B8..803E8908` |
| JP | `80292EDC..80292F10` | `803E7D38` | `803E7D40..803E7D90` |
| PAL revision 1 | `8029375C..80293790` | `803E9610` | `803E9618..803E9668` |

At each constant address, the first 16 bytes are
`40000000 00000000 37c8dde4 a71f16c1`: reciprocal's float, the gap, and the
first two angle coefficients. PAL revision 0 remains excluded because the
local artifact fails that version's configured checksum.

History supplies an independent reason to revisit this grouping:

- `634c8882fb` separated `rand`/`srand`, leaving reciprocal's 52-byte window
  as its own placeholder.
- `e53d712b86` absorbed reciprocal and the angle helpers into `rand.c` through
  explicitly best-effort attribution to the closest preceding named SDK file.
- `b6eca0b2b7` removed the four non-rand helpers together. Later rehoming kept
  that grouping, without establishing an original common translation unit.

The current combined source with ordinary `2.0f` literals emits an 84-byte
pool: the reciprocal constant immediately followed by all 80 angle bytes.
All function bodies stay unchanged, but the retail alignment gap is absent.
Separate units emit four and 80 bytes respectively and naturally permit that
inter-unit alignment. Taken together with the historical grouping and the
independent retail pools, this supports the boundary repair. No explicit
section placement, synthetic padding, or per-function flag change is used.

## Source and configuration

`fastReciprocal` retains its intrinsic estimate and two Newton refinements.
The source uses `2.0f` directly instead of an external placeholder constant.
Its sole caller in `acosf.c` includes the new unit-owned header. The three
angle helpers retain their source and shared pool.

Both objects use exactly the former combined unit's GC/1.3 compiler and
optimization profile. Both remain `NonMatching`: the boundary repair cannot
resolve the existing instruction-generation differences. The EN split claims
only the four-byte literal. Conservative secondary projection also includes
the following four alignment bytes; no source definition manufactures them.

## Validation

All four verified versions produce identical source objects for the respective
units. Every function body remains byte-identical to the former combined
object; function-relative relocation targets remain equivalent. The remaining
angle pool is unchanged, the new reciprocal pool is exactly `40000000`, and
the complete `acosf` caller object is unchanged. The two generated compiler
commands are identical after normalizing their input/output filenames.

Objdiff reports 100% data for both new units in every version. EN gains four
matched data bytes; each secondary report gains eight, including its projected
alignment. Function scores remain 84.46154% for reciprocal, 54.754097% for the
fast angle approximation, 57.53846% for the middle approximation, and 60% for
the precise approximation. This is a structural and data recovery, not an
instruction-match gain.

`ninja all_source` passes for EN, EN revision 1, JP, and PAL revision 1 in
20.26, 20.78, 21.05, and 21.25 seconds respectively. The active source files
and their headers pass `clang-format --dry-run --Werror`; running the formatter
makes no changes. Final EN `all_source` and strict checksum builds pass in
20.24 and 22.25 seconds. The linked DOL retains SHA-1
`e750e8e894707a52446118a4b84f1b58b677b269`.
