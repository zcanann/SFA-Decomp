# Older math grouped with MSL

The user approved moving the older math block into MSL on 2026-09-20,
following the [binary-neighborhood audit](math_library_neighborhood.md).
All twelve TUs, including the adjacent random-number unit, now live under
`src/MSL_C/PPCEABI/bare/H/`, belong to `MSLLib("MSL_C", ...)`, and count as
third-party code. Public headers live under the corresponding include directory.
MSL is the working ownership classification; the descriptive filenames are not
claims about recovered vendor filenames.

| Previous source | Filename under `MSL_C/PPCEABI/bare/H/` |
| --- | --- |
| `MSL_C/PPCEABI/bare/H/math_float_helpers.c` | `math_float_helpers.c` (unchanged) |
| `main/acosf.c` | `inverse_trig.c` |
| `MSL_C/PPCEABI/bare/H/math_802927a4.c` | `power_helpers.c` |
| `main/math_80292d3c.c` | `trig_reduce.c` |
| `main/rand.c` | `rand.c` |
| `main/reciprocal.c` | `reciprocal.c` |
| `main/trig_float_helpers.c` | `angle_vectors.c` |
| `main/math_8029312c.c` | `sqrtf.c` |
| `main/trig.c` | `trig16.c` |
| `main/sincosf.c` | `sincosf.c` |
| `MSL_C/PPCEABI/bare/H/math_80293da4.c` | `sincos_approximations.c` |
| `MSL_C/PPCEABI/bare/H/math_8029454c.c` | `tanf_log2.c` |

The seven moved headers follow these names; `acosf_api.h` becomes
`inverse_trig_api.h`. Consumers, active tools/tests, all five regional split
files and the four regional matching manifests use the new paths. Header
guards no longer identify the moved headers as main/game headers. Historical
audit documents retain original path references; this table translates them.

The eleven math TUs keep their exact GC/1.2.5n options, including the two
`-opt functions` profiles. `rand.c` explicitly retains GC/1.3 and its existing
flags. Public function/data names, TU boundaries, section alignment and
matching status are unchanged. `power_helpers.c` still owns its vector and
reduction helpers; `tanf_log2.c` still owns both functions. Neither TU is split
for naming.

The EN progress change is classification only: 12 units, 51 exact functions,
10,628 code bytes and 1,200 data bytes move from Game Code to Third-Party Code.
Overall match totals remain unchanged. The compiler-profile test no longer
needs game-math exceptions and checks MSL grouping explicitly.

Renamed objects may have changed file symbols and debug records; loaded
sections and their relocations remain equal. All 60 math objects across the
five versions compare equal after stripping debug/file metadata, including
remaining symbols and relocations. All 987 effective EN C compiler profiles
are unchanged. The EN report retains 51/51 exact functions for this block.

All five versions pass `ninja all_source` and their strict checksum targets.
Each secondary version also passes a verified-retail link and a link replacing
exactly these twelve retail objects with source objects. The thirteen compiler
profile tests, two atan behavior tests, and formatting checks pass. Running
clang-format introduces no formatting changes, so no formatting-only commit
is necessary. Regional progress refreshes were inspected; unrelated generated
symbol/boundary changes were discarded and final checks rerun on path-only
regional changes.
