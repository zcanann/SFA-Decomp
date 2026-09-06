# GC/1.3 source cleanup migration

EN v1.0 (`GSAE01`), 2026-09-05. This pass follows the NW_tricky seed in
`4c83fd6190` and migrates twelve more complete game TUs to GC/1.3. Eleven gain
indexed traversal; LGTControlL gains canonical header and descriptor ownership
while retaining its existing loops. All twelve remain source-linked and exact:
92 functions, 21,700 code bytes, and 1,688 assigned data bytes.

The final source also matches GC/2.0 in every migrated TU. No clean form in this
pass uniquely requires GC/1.3. The compiler migration and the search for a
compiler discriminator are separate results; an unchanged-source regression
under GC/1.3 is not enough to reject that compiler.

## Landed units

Existing TU flags are preserved, including LGTControlL's level-1 override.
No source paths, splits, allocation sizes, or data ownership boundaries change.

| TU | Exact functions | Source recovery |
| --- | ---: | --- |
| Engine 72, static camera | 7 | `objects[i]` replaces the nearest-anchor cursor. |
| 198, AnimatedObj | 5 | `objects[result]`; reuse the loaded `other` for the sequence owner. |
| 238, EffectBox | 9 | `targets[targetIndex]` covers both single-object and group-list modes. |
| 267, FireFlyLant | 8 | Indexed `for` loops create and free fireflies. |
| 277 | 10 | Initialization indexes `completionGameBits[step]`. |
| 310, WaveAnimator | 13 | Flat height/color indices replace byte offsets, duplicate counters, and one-element cursor arrays. |
| 316, XYZAnimator | 8 | Both triangle loops index `mapEntry[index]` and the typed vertex array. |
| 420, NW ice | 5 | Pair lookup indexes `pairedObjects[objectIndex]`. |
| 565, DFP_TargetB | 10 | Collision probes use `floorPoints[i].x/y/z`. |
| 611, GM_MazeWell | 6 | Item scan uses its own integer index; the final hit-volume call uses its declared function type. |
| 684, LGTControlL | 9 | Canonical header and truthful descriptor registry declaration; indexing remains pending. |
| skystars | 2 | Constellation generation uses the point index directly. |

Slots 565, 611, and 684 now own self-contained headers under
`include/dlls/objects/`. Their shared consumer changes are limited to the
necessary declarations, includes, and registry cast. The old MazeWell table
declaration in KT_Rex's header and obsolete owner headers were removed.

## Findings that matter for the next pass

MazeWell originally matched GC/2.0 but its update fell to 97.66234% on GC/1.3.
The final function-pointer cast became `lis/addi/mtctr/bctrl` instead of retail's
direct `bl`, adding twelve bytes. Removing that cast restores the direct call
and allows an exact whole-TU migration. Its existing integer/pointer argument
cast remains: passing `obj` directly changes register allocation on both
compilers. The readiness scan also retains its enum index and cursor; sharing
one integer across both indexed scans gives 99.707794% for update on both.

WaveAnimator's height loop initially retained an explicitly hoisted `xRadians`
temporary and scored 99.176956% on both compilers. Returning that expression to
its point of use lets the compiler hoist it in retail order, making both table
passes exact without their old offset bookkeeping.

XYZAnimator's clean fixed-trip loops use `index != 3`. Substituting `< 3`
changes captureGeometry's unrolled destination addressing and gives 91.507935%
on both compilers. Its other one-element offset arrays remain because scalar
conversion changes initialization and register allocation. AnimatedObj likewise
retains its existing `while` and multi-role `result`: moving initialization into
a `for` header or splitting the local regresses both compilers.

Slot 277's update cursor crosses from `completionGameBits` into the adjacent
`activeGameBits` for FINISH/DONE. Direct indexing into the first array would
cross its bounds. The preserved access is documented; bounds-aware alternatives
currently change codegen under both compilers.

## Unfinished probes

These scores describe the affected function, with identical outcomes on both
GC/1.3 and GC/2.0. Rejected source and flag experiments were not landed.

| Target | Indexed result | Remaining issue |
| --- | ---: | --- |
| DIM2RoofRub update | 98.181816% | `nopropagation` preserves an unnecessary initial index calculation and changes traversal registers. Removing only that flag also regresses `spawnEffects`; the TU remains unchanged. |
| `gameTextMeasureById` | 99.46154% | Direct entry indexing is not exact; simplifying the unusual loop condition regresses further. TU unchanged. |
| `initMapBlocks` | 98.87363% | Indexed sentinel traversal of `gTrkBlkTab` does not retain retail code. TU unchanged. |
| `ControlLight_update`, existing level 1 | 87.89474% | Indexing stays as shift/indexed-load operations instead of retail pointer induction. |
| `ControlLight_update`, level 4 with scheduling/peephole disabled | 97.56579% best | Natural indexing and an inverse test at its use recover loop shape, but register allocation still differs. Keep the original level-1 profile and cursors for now. |

Further object-list candidates remain in slots 244, 282, 329, 388, 397, 441,
484, and 505. Those are source-inspection leads, not verified cleanup results.

## Verification

Each migration used the real Ninja compile command for the entire TU and
compared original and candidate source under both compiler versions. Allocated
section bytes/layouts, named symbol offsets, literal-pool locations, and
relocations were checked beyond objdiff's percentages. Permitted object churn
was confined to compiler metadata and anonymous literal names at unchanged
locations. ModelEngine and KT_Rex consumer edits preserved their complete raw
objects.

The active TU and owner header pass clang-format. Generated DLL paths were
audited. Every landed TU passed the strict matching build and `ninja all_source`
with a 30-second timeout; the final DOL remains byte-identical to retail:
SHA-1 `e750e8e894707a52446118a4b84f1b58b677b269`.

Local source variants, compile commands, object comparisons, reports, and build
logs are retained under `build/gc13_indexed/`. The source/config changes are
recorded as individual TU commits on `staging`. The broader migration tool can
recheck current clean source against the former compiler with
`python3 tools/compiler_impact.py --compiler GC/2.0 --output build/compiler_impact/<new-directory> --jobs 6`.

## September 6: DIMLavaSmas mask recovery

Object slot 455 gains its last exact function, `dimlavasmash_setBlockSurfaceFlags`
(276 bytes), by applying the shader clear mask at its use instead of keeping a
manually hoisted `u32 clearMask` across the loop. Its triangle-group masks also
use ordinary `~2` and `~1` instead of unnecessary 64-bit literals. Both owning
fields are `u32`; the stored values are unchanged for every input.

The same source change has different results under the two compilers, with the
complete existing TU profile held constant:

| Source | GC/1.3 function / TU fuzzy | GC/2.0 function / TU fuzzy |
| --- | ---: | ---: |
| Previous masks and hoisted local | 98.840576% / 99.69811% | 98.840576% / 99.69811% |
| Native masks at their use | **100% / 100%** | 91.159424% / 97.69811% |

This is a new match under GC/1.3, rather than a compiler-only gain on unchanged
source. Removing the 64-bit suffixes alone is byte-neutral in the function
under 1.3; removing the hoisted shader mask resolves the register assignments.
Unsigned mask literals were also tested and regress, consistent with the
compiler's sensitivity to literal types.

All **11 functions, 1,060 code bytes, and 60 assigned data bytes** now match.
The other ten function bodies remain unchanged. Allocated data, named symbol
offsets, and relocations are preserved; two anonymous literal symbols are
renumbered at unchanged locations. Slot 455 is now source-linked for EN v1.0.
Its TU boundary, generated path, compiler flags, canonical header, and shared
consumers are unchanged. Artifacts are under `build/gc13_new_matches/lava/`.

Formatting and the generated-path audit for slots 454-456 pass. The strict
checksum build and `ninja all_source` both exit 0 within their 30-second limits;
the final DOL remains byte-identical to retail with slot 455 linked from source.
