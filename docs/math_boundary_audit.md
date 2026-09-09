# Retail math boundary audit

September 8, 2026; source baseline `51367a241e`, GC/1.3 game compiler.

Follow-up: [the complete power pool is now recovered](math_literal_pool_recovery.md#complete-power-function-pool).
The tables below describe the pre-recovery claims; the power unit's 280-byte
gap has since been claimed with an exact literal pool and unchanged code.
The [reciprocal boundary repair](reciprocal_boundary_recovery.md) also separates
the reciprocal helper from the three angle-vector approximations and recovers
its four-byte constant without changing their compiler profiles or code.
The subsequent [named trigonometric pools](math_literal_pool_recovery.md#complete-named-trigonometric-pools-2026-09-08)
and exponential/floor pool now match retail data without changing function
instructions or redrawing their existing boundaries.

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

## Fresh same-source compiler controls (2026-09-08)

At staging `c1ac51716c`, the older math family occupies eleven current TUs
because the reciprocal helper has since been separated. It has 49 functions,
10,584 code bytes and 1,196 data bytes. Four paths remain under `dolphin/MSL_C`,
but these select the game compiler explicitly. Those directory names do not
establish MSL lineage. The other 28 MSL units still have 100% code fuzzy agreement.

Recompiling the **same current source** into scratch directories produces:

| Compiler control | Exact functions | Exact code bytes | Code fuzzy | Data agreement |
| --- | ---: | ---: | ---: | ---: |
| Current GC/1.3 and current flags | 3 / 49 | 92 | 74.948980% | 100% |
| GC/1.2.5n, otherwise identical flags | 42 / 49 | 8,176 | 98.734695% | 100% |
| GC/1.2.5n plus `-opt functions` | 45 / 49 | 8,956 | 99.555176% | 100% |

[Per-function objdiff results](math_compiler_control.csv) retain all 49 rows.
The older compiler's extra option closes the three angle-vector functions.
The four remaining mismatches are `atanf`, `powfCoreHighPrecision`,
`powfCoreFast` and `mathSinCosf`; current source rewrites mean the older compiler
alone no longer makes this entire family exact.

This isolates the compiler as the cause of most **current** score loss. It does
not infer original provenance from an aggregate score or authorize restoring
compiler exceptions. Independent retail save/restore evidence is also concrete:
`invSqrt` has 16 instructions, including nine arithmetic/load/result instructions
between its saves and restores. Those nine already agree with GC/1.3. The current
compiler adds four `psq_st`/`psq_l` instructions and enlarges its frame from
32 to 48 bytes; its remaining four operand differences are stack offsets/frame
sizes. `sqrtf` and `sqrtfHighPrecision` show the same four added instructions and
four frame-related operand differences. Changing the GC/1.3 processor selection
to 750 or 604, or toggling `-use_lmw_stmw`, leaves those differences unchanged.
An O1 control changes arithmetic register allocation and removes retail saves,
so it does not reproduce these functions either.

The donor-project question has a separate answer. Melee's MSL `trigf.c` uses
`__four_over_pi_m1`, `__sincos_poly` and `__sincos_on_quadrant`; SFA's already-exact
MSL `trigf.c` uses that same family. The older angle-vector approximations have
different coefficients and fast-cast calls. A fresh read-only search across the
available reference projects found no occurrence of three distinctive coefficient
spellings (`2.2949214e-15`, `0.000023968449`, `8.8444e-37`). This is only a negative
source-text search, not proof that no donor contains an equivalent implementation.
The shared-pool and function-boundary evidence above remains the basis for split
decisions; the compiler comparison changes no boundaries.

Each scratch compile starts with its actual `ninja -t commands` source command,
redirects `-o` to a separate directory, and changes only the compiler executable
and the explicitly listed extra option. The function comparison checks nonempty
retail/source instruction streams and relocation-aware operands. Separate
objdiff projects point to the unchanged EN retail objects and each scratch set;
the figures above come from those reports, not a manually estimated score.
The current-compiler control reproduces the active report. All constant-pool data
also remain exact in every control. Scratch commands, objects, instruction diffs,
source hashes and full reports are under `/tmp/sfa-math-abi-refresh/` locally.
No configured compiler, source, matching classification or expected checksum
changes. The immediately preceding all-source and strict EN gates remain valid
for this documentation-only audit.

## Neighboring MSL labels and source lineage (2026-09-08)

A matching reconstruction does not establish library membership. The current
paths mix implementation evidence, inferred filenames and historical placement.
The DOL supplies bytes and addresses, not original archive membership; the names
in `symbols.txt` and `splits.txt` are reconstruction annotations. In particular,
noncontiguous MSL-labeled text is a reason to audit those annotations, not by
itself proof that all intervening code belongs to MSL or to one other library.

| EN text interval | Current identification | Evidence and remaining uncertainty |
| --- | --- | --- |
| `80291948..80291CBC` | `s_copysign`, `s_frexp`, `s_ldexp`, `s_modf` | Double-precision fdlibm implementations. Mario Party 4 contains the same word-level exponent/sign operations, subnormal scaling and special-value branches. This supports their source family; it does not recover the original archive name. |
| `80291CBC..80294640` | Older math family, with `rand` between reducers | Four files remain under `MSL_C`, despite selecting the game compiler. Scalar approximation coefficients, fast-cast calls and shared pools distinguish this family from the later table-based implementations. No donor or original archive has been identified for the complete family. |
| `80294640..8029471C` | PPC helpers, ctype and console I/O | These helper implementations interrupt the math layout. Their position cannot establish either neighboring math family's ownership. |
| `8029471C..80294724` | `hyperbolicsf.c` absolute-value helper | Sunshine and Pikmin place a corresponding helper in `hyperbolicsf.c`. An eight-byte absolute-value body is weak evidence for a specific original filename or TU boundary. The configured C++ name is not a name recovered from a DOL symbol table. |
| `80294724..802947CC` | `floorf.c` | Behavior and generated code are recovered, but no matching donor body was found in the inspected references. Commit `47cb2127e0` created the split from a reconstructed function; `96ca95bf3a` subsequently named it. MSL membership and the original filename remain provisional. |
| `802947CC..80294BB8` | `trigf.c` | Donor table contents and reduction/polynomial structure support the MSL float-trig family. The retail constructor and writable-table initialization also support C++ compilation; these do not prove an archive name. |
| `80294BB8..80295334` | `exponentialsf.c` / `powf` | Its logarithm kernel consumes the same reciprocal table used by donor MSL logarithms. This supports a related table-based family, but the local Sunshine `exponentialsf.c` contains no implementation. It is not a source donor for the recovered `powf`, and its filename alone cannot establish exact provenance. |

The shared tables provide a stronger check than decimal-string searches.
Converting the source initializers to big-endian binary32 gives identical bytes
in SFA, Sunshine's `Single_precision/common_float_tables.c` and Melee's
`src/MSL/math_data.c`. Those bytes also equal the hash-verified EN DOL:

| Configured table name | EN address | Compared bytes |
| --- | --- | ---: |
| `__one_over_F` | `80332A28` | 516 |
| `__sincos_on_quadrant` | `80332C2C` | 32 |
| `__sincos_poly` | `80332C4C` | 40 |

Melee's `src/MSL/math.c` independently shows the seven-bit mantissa-table index,
eighth-bit rounding decision and reciprocal-scaled residual used by the later
SFA logarithm kernel. Its natural-log function is not the same function as SFA's
base-two kernel, so this is structural lineage evidence, not a whole-function
donor match. Likewise, the intervening SFA `rand` uses `1664525` and
`1013904223` and returns the full state; donor MSL `rand` uses `1103515245`,
`12345` and a restricted result. Generic math names do not identify one library.

The four legacy `MSL_C` paths and the weaker neighboring labels should therefore
remain provenance questions. Do not use their current directory, an exact
reconstruction, or adjacency as the sole reason to choose a compiler or merge
TUs. This audit changes no paths, boundaries or compiler profiles. Local table
digests are retained under `/tmp/sfa-msl-neighbor-audit/`.

## PAL v1.0 cross-check (2026-09-09)

PAL v1.0 is now available and passes its configured SHA-1
`c5bb4a7fd3c4aff48c40e282d4d54795c37155f0`. All 49 functions in the current
11-unit older math family have the same ordered normalized instruction
signatures as EN. All 541 supported direct r2 constant loads also agree by
owning unit, instruction offset, width, exact bytes and pool ownership. No
outside consumers appear in this scan. This extends the earlier four-version
evidence; it establishes no new archive provenance or compiler exception and
supplies no reason for a regional algorithm difference or additional split.
