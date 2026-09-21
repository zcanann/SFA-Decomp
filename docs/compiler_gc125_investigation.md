# GC/1.2.5 versus GC/1.3 investigation

2026-09-20, source baseline `2f6ddc36dc`, EN v1.0. The user explicitly
authorized investigating older game compilers and rematching source.

**The older math family's authorship is unresolved. A single GC/1.2.5 build
for all game code is less consistent with the retail save sequences than a
mixed compiler history.** This conclusion does not come from recompiling
source tuned for GC/1.3 and observing regressions. The decisive new evidence
is a compiler-generated floating-point save convention, reproduced with small
independent C functions and found directly in the verified retail DOL.
It distinguishes the tested 1.2.5 builds from the later compiler family; it
does **not** identify 1.3 uniquely against 1.3.2 or other later builds.

No production source, compiler setting, split, matching status, or checksum
changes in this investigation. No new function is claimed matching.

## Math provenance

The 11 older math units now have 49 exact functions, but neither their
`game` category nor the four legacy `MSL_C` paths identify their original
archive or author. They could include older library code. Do not call them
proven game-authored math merely because their reconstruction is exact.

The [boundary audit](math_boundary_audit.md#neighboring-msl-labels-and-source-lineage-2026-09-08)
already establishes two distinct float-math implementations in retail:
the older scalar approximations and the later table-based MSL-related family.
The latter shares actual table bytes and algorithm structure with donor MSL.
That distinguishes the implementations, not the older family's authorship.
Fresh `source_leaks.py` / `source_matrix.py` searches for math, trig, acos and
exp2 still give no direct math filename evidence. Coefficient-text searches
in the available references and sibling Dinosaur Planet checkout add no donor.
These negative searches are not proof of absence. Keep the existing boundaries
and leave provenance open.

## Actual executable differences

| Local compiler | SHA-256 | Bytes | Reported runtime build |
| --- | --- | ---: | --- |
| GC/1.2.5 | `0443b5c02b1aa7b575b61e0e24c4d5ad6bed8fd54cc42de5a2204a5216001914` | 1,651,200 | 2.3.3 build 163, Apr 23 2001 |
| GC/1.2.5n | `ccf4b465cec73b5aae9c5c5543dcf8cda8a62aba246f89e2e0b200d742f2e55c` | 1,651,200 | same |
| GC/1.3 | `4e502c38465500d4fda8d966b268151a6c74c730508e3d9b7efd23d1a6083715` | 2,053,120 | 2.4.2 build 53, Jan 10 2002 |

These are embedded build stamps, not independently established release dates.
The [later-version audit](compiler_gc_versions.md) remains a separate question.

1.2.5n differs from 1.2.5 in **53 bytes**, all in `.text`; every other
PE section has the same digest. Its inserted text reads
`Hacked by Ninji 2023-07-15 `. This is a modern patch, not an independent
historical release. The patched branch at VA `0x4abd9a` reaches `0x506510`:

```asm
add esp, 0x14
push 0x400
call 0x49cf70
pop ecx
jmp 0x4abdb6
```

The callee ORs the argument into a field at offset `0x16` of an internal
record. The record's semantic type and complete flag meaning are not recovered.
However, generated-code controls show an observable effect: with scheduling
enabled, the patched compiler keeps `mtlr` after the final restores and stack
adjustment where stock 1.2.5 schedules it earlier. All 14 scheduled C-menu TU
variants differ between these executables; the other 70 paired TU objects are
byte-identical. The `cMenuSetItems` score itself ties in all 84 paired cases.
Calling this only a host-compatibility patch would be unjustified.

The tool records complete help output and its diff. Material differences:

| Setting | 1.2.5 / 1.2.5n | 1.3 |
| --- | --- | --- |
| Default plain `char` | signed | unsigned |
| `-O4` | level 4, peephole, schedule, functions | level 4, peephole, schedule |
| `-opt functions` | accepted; documented as prologue/epilogue optimization | unknown option |
| `-use_lmw_stmw` default | on | off |

The help's description of `use_lmw_stmw` also changes from structure copies to
function prologues/epilogues. Game commands explicitly select signed char, so
that default is not an explanation for their present score differences.
Identical flag strings do not imply identical effective compiler settings.

## Independent save-convention controls

The generated fixture retains three `float` values across external calls.
Its double-precision counterpart uses the same source shape. No game source,
inline assembly, artificial padding, or compiler-specific intrinsics are needed.

| Fixture | 1.2.5 / 1.2.5n | 1.3 |
| --- | --- | --- |
| live float locals | 48-byte frame; three `stfd` / `lfd` pairs | 64-byte frame; also three `psq_st` / `psq_l` pairs |
| live double locals | 56-byte frame; three double-save pairs | 32-byte frame; three double-save pairs, no paired-single saves |
| escaped 9-byte local array | 24-byte frame | 32-byte frame |

The float arithmetic and call sequence agree; the additional saves are
compiler output. The distinction survives `use_lmw_stmw` on/off, peephole,
scheduling, O1, O4, and processor 750 controls. Default-char controls separately
produce `extsb` on 1.2.5 and `clrlwi ...,24` on 1.3.

Scanning hash-verified EN retail finds the corresponding save pattern in
**690 functions across 241 current game-category units**. The scan requires
`stfd` followed within two instructions by `psq_st` of the same nonvolatile
FPR, based on r1, using GQR0, at the double-save offset plus eight. It considers
only the first 128 bytes of each annotated function, and records every hit.
Examples include `modelRenderInterpolateRootTransform` at `80007F78`,
`Sfx_SetObjectChannelVolume` at `8000B888`, and `gameUiLoadResources` in
the same TU as `cMenuSetItems`.

The older math family's different saves are independently documented in the
[math controls](math_boundary_audit.md#fresh-same-source-compiler-controls-2026-09-08).
Together these support multiple compiler profiles in retail. Absence of this
pattern does not classify a unit as 1.2.5: leaf functions, double-only functions,
save helpers and handwritten assembly need separate evidence. The finite fixture
matrix is not proof that every conceivable older option/source can be excluded.

## C-menu rematching, not only a compiler switch

Compiled the entire 118-function engine-0 TU for **14 source variants × six
profiles × three compilers = 252 cases**. Every case compiled and scored.
Variants replace the one-element offset array with a scalar, replace manual
offset accesses with typed HUD indexing, move invariant zero initialization out
of the clearing loop, use a countdown clearing loop, and test register hints
for locals crossing calls/phases. The duplicated inventory paths and Tricky
behavior remain. Every variant passes 10,000 deterministic behavior cases at
both host O0 and O2 with UBSan, comparing complete state and ordered engine calls.
This checks reconstructed behavior, not equivalence to running retail PPC.

| Source/profile | 1.2.5 | 1.2.5n | 1.3 |
| --- | ---: | ---: | ---: |
| current source, configured flags | 87.350990% | 87.350990% | 98.841060% |
| scalar offset, configured flags | 86.821190% | 86.821190% | 96.970200% |
| typed indexing, configured flags | 86.870860% | 86.870860% | 96.572845% |
| best in this matrix | 87.745030% | 87.745030% | 98.841060% |

The older compiler's best uses `-use_lmw_stmw off`. These experiments do not
finish the function, and they do not exhaust plausible source reconstructions.
They supplement the earlier [engine settings audit](engine_compiler_settings_audit.md).
Do not treat their scores as proof of the original compiler. The neighboring
retail floating-point saves provide the stronger independent constraint on
the complete TU. Its confirmed boundary must not be split for per-function flags.

A separate unchanged-source migration survey attempted all 790 MWCC game TUs:
789 compile on 1.2.5n; `model.c` rejects the reconstructed inline-assembly helper
syntax (`illegal use of 'inline'`). ProDG `zlb.c` is excluded. The aggregate
report includes that failed object as zero, and retained completion metadata
is not candidate completion. It is migration-cost data, not provenance evidence.
No whole-program percentage is used to decide compiler identity here.

## Reproduce

```sh
python3 tools/compiler_gc125_probe.py --rematch
python3 tools/compiler_impact.py --all-mwcc-game --compiler GC/1.2.5n \
  --output build/gc125n-investigation/impact --jobs 6
```

The first command records compiler hashes, patch offsets, help differences,
retail save sites, fixture assembly, full-TU commands, source hashes, compile
diagnostics, behavior results and objdiff scores under
`build/gc125n-investigation/compiler/`. Without `--rematch`, it runs just the
binary/help/retail audit and 30 small compiler controls. Unknown options and
failed compiles are errors, not silently accepted measurements.

Validation: all 282 compiler cases succeeded, all 28 host behavior runs passed,
and the existing C-menu regression test passed. `python3 configure.py --matching`,
`ninja all_source`, and strict `ninja` pass. A fresh explicit DTK checksum check
also reports `build/GSAE01/main.dol: OK` against the unchanged expected hash.

The next useful compiler investigation is to recover the older/later register
allocator and frame-emitter differences, and test them against a smaller stuck
function with a clear retail constraint. This audit does not claim a complete
reverse engineering of either compiler or a unique historical 1.3 attribution.
