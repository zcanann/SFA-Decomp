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

## September 6: Wisp animation-event flags

`wispBaddieProcessAnimEvent` (1,000 bytes) reaches 100% by using ordinary
compound updates on its `u32 controlFlags`: `&= ~0x40` and
`|= BADDIE_CONTROL_SEQUENCE_DRIVEN`. The previous expressions unnecessarily
widened the operations to 64 bits. The stored flags are identical for every input.

| Source | GC/1.3 function / TU fuzzy | GC/2.0 function / TU fuzzy |
| --- | ---: | ---: |
| Previous widened expressions | 99.156% / 99.89016% | 99.156% / 99.89016% |
| Native compound updates | **100% / 100%** | 98.68% / 99.82822% |

All 11 functions, 7,684 code bytes, and 5,780 assigned data bytes in
`dlls/objects/202/sharpclaw.c` now match, allowing EN source linkage. The other
ten function bodies, data, named symbol offsets, and relocations are preserved.
The existing compiler profile and TU boundaries are unchanged. Formatting was
checked against the intended C tokens and the unformatted candidate object;
the canonical header is unchanged. The generated-path audit, strict retail
checksum build, and `ninja all_source` pass. Artifacts are under
`build/gc13_new_matches/wisp/` and `wisp_gc20/`.

## September 6: Player state-entry flags

Three more functions become exact with native compound updates of the
32-bit player flag word. They clear `PLAYER_FLAG_HITDETECT` and set
`PLAYER_FLAG_NO_POS_VELOCITY` on entry. The two shared definitions now use
ordinary integer literals; all existing macro uses are in this TU and access
the same `u32 flags360` field. The stored values are unchanged for every input.

| Function | Bytes | Previous GC/1.3 | Native updates GC/1.3 | Native updates GC/2.0 |
| --- | ---: | ---: | ---: | ---: |
| `playerState1B` | 1,636 | 99.39854% | **100%** | 99.53545% |
| `playerState19` | 1,396 | 99.29513% | **100%** | 99.45559% |
| `playerStateMountBike` | 1,452 | 99.40496% | **100%** | 99.545456% |

Together these add **4,484 exact code bytes** and improve the complete player
TU from 99.80901% to 99.82937%. All other function bodies, data, symbol offsets,
and relocation targets remain unchanged, including the other consumers of the
shared flag macros. Each changed function moves one existing float-literal
load by one instruction. The TU retains its existing compiler profile and remains
NonMatching because other functions still differ.

The formatted source emits the same object as the independently compiled
candidate. Formatting checks, the generated-path audit, the strict checksum
build, and `ninja all_source` pass. Local source/compiler controls are under
`build/gc13_new_matches/player_batch/`, `player_batch_gc20/`, and
`player_macro_batch/`.

## September 6: Sky animation and state arrays

Engine 6 (`dlls/engine/6/6.c`) now matches all **18 functions, 9,236 code
bytes, and 380 assigned data bytes**. In `sky2_run`, keeping the selected
sample offset in float elements resolves the last register mismatch. The fog
sample access uses `offsetof(SkySlotAnim, cur2)` instead of the literal byte
offset; its layout assertion is beside the owning type.

The source also recovers `gSky2States[2]`. The allocation loop visits two
slots, and initialization frees and clears both. These accesses establish the
eight-byte array at `0x803DD184`; the old scalar declaration accessed its
second slot out of bounds. Two unused filler globals are removed. Leaving
the scalar and fillers in place gave an exact objdiff report but failed the
retail checksum because the linker discarded the unreferenced storage.

| Final source | GC/1.3 | GC/2.0 |
| --- | ---: | ---: |
| `sky2_run` fuzzy | **100%** | 99.84277% |
| Whole TU fuzzy | **100%** | 99.95193% |

The complete TU uses identical existing flags for both controls. With the
real array declaration, GC/2.0 removes a pointer reload after clearing the
pending environment-update flag; GC/1.3 retains retail's `lwz r3,0(r31)`.
The float-offset change alone, before recovering the state array, matched
both compilers. The discriminator therefore applies to the final source.

Only this TU's compiled object changes; the other 1,004 objects are preserved
in the comparison against the starting tree. After rebasing onto current
staging, the strict matching build and `ninja all_source` both pass, with the
retail DOL byte-identical. The TU and type header pass clang-format. Local
source/compiler controls are under `build/gc13_indexed/sky2/`.

## September 6: Player projectile, render, and hit-detection recovery

A second player pass adds six exact functions, totaling **6,740 code bytes**:

| Function | Bytes | Before | After |
| --- | ---: | ---: | ---: |
| `playerStopRidingObject` | 356 | 97.34831% | **100%** |
| `playerFireCloudRunnerProjectile` | 668 | 99.041916% | **100%** |
| `playerSpawnRapidFireLaser` | 512 | 98.75% | **100%** |
| `staffShootFireball` | 1,056 | 99.393936% | **100%** |
| `playerRender` | 1,904 | 99.5063% | **100%** |
| `playerDoHitDetection` | 2,244 | 99.82175% | **100%** |

The three projectile spawners consume the low byte of `Obj_CanSetupObject`,
as shown by retail's `clrlwi; cmplwi` and already expressed by other callers
in this TU. The engine helper returns a boolean comparison, so the explicit
`u8` conversion preserves its result. These are call-site recovery wins;
they do not independently distinguish compiler versions.

The other three functions use native compound flag updates. Dismounting clears
`OBJ_MODEL_STATE_SHADOW_FADE_OUT` instead of a widened hexadecimal mask.
Hit detection clears the 32-bit `PLAYER_FLAG_WORLDPOS_OVERRIDE` without the
previous signed/64-bit conversions; its shared constant now has native integer
type. The two macro uses are both in this function. Rendering sets and clears
`SHADER_FLAG_DECAL_LAYER` through the canonical shader field.

The cached shader was misleadingly named `gPlayerHeldObject` and stored as an
integer. Its only producer stores the `Shader*` found in the Krazoa-spirit
render path; its consumer clears that shader's decal flag. It is now
`Shader* gPlayerKrazoaShader`, including the owning declaration and EN symbol
config. Its four-byte `.sbss` slot, neighboring symbol offsets, and declaration
order are preserved. The initialization function's body is unchanged.

The complete TU advances from 99.82937% to **99.85959%**, with **218/233 exact
functions**. Only the six listed function bodies change. All data bytes and
data-symbol offsets remain unchanged; all other function relocations are
preserved after normalizing the shader rename and anonymous literal numbering.
Anonymous symbols are renumbered at unchanged pool locations. Every assigned section remains
exact except `.text`. The TU stays NonMatching with its existing GC/1.3 flags.

Formatting, generated-path and stale-symbol audits, the strict retail checksum,
and `ninja all_source` pass. Local controls are under
`build/gc13_new_matches/player_continue_first/`, `player_continue_second/`,
`player_hit_flags/`, `player_render_shader/`, and `player_six/`.


## September 6: Player attack, climbing, and shared ice-spell helpers

The next player pass adds **six exact functions, totaling 11,604 code bytes**:

| Function | Bytes | Before | After |
| --- | ---: | ---: | ---: |
| `playerStateAttack` | 2,836 | 99.908325% | **100%** |
| `playerCheckIfClimbingOntoWall` | 3,348 | 99.64038% | **100%** |
| `playerState30` | 1,500 | 99.96% | **100%** |
| `playerStateTryCastSpell` | 964 | 99.93776% | **100%** |
| `playerStateAimStaff` | 1,824 | 99.9671% | **100%** |
| `playerStateShootFireball` | 1,132 | 99.78799% | **100%** |

The attack state's raw staff call omitted an integer argument. Retail preserves
`moveSlotIndex` in r4 while loading its two floating-point arguments, and the
existing staff interface identifies slot 0x4C as `startSwipe`. Calling that
interface with the index fixes the call and agrees with `staff_startSwipe`,
which stores the supplied index in its selected swipe slot. The two move-table
floats are now `swipeStart` and `swipeLengthScale`, with layout assertions.
Offset-based accesses preserve the table's existing integer storage and the
retail address calculations, including the hit-window type lookup.

The climbing probe now masks its input heading and subtracts camera yaw in
separate compound operations. Its ledge flag uses native integer width and a
compound clear, eliminating the imported 64-bit mask without changing semantics.
Both uses of the shared flag constant are inside this probe.

Four spell states share the same particle setup and two spawn calls. Extracting
`playerSpawnIceSpellParticles` as a static inline helper reproduces retail's
cached flag register in all four callers. They use the canonical
`PartFxSpawnParams` packet. A simple indexed `playerFreeSpawnedObjects` helper
also matches the fireball state's cleanup, and replaces the artificial counter
and cursor arrays in the other three callers without changing their code.
This is evidence for a shared inline source structure; the original helper
names and compiler provenance are not established by the match alone.

The full TU advances from **99.85959% to 99.87313%**, and from **218/233 to
224/233 exact functions**. Only these six function bodies change. All
function-relative relocations, allocated data bytes, section sizes/alignment,
and data-symbol offsets are preserved; compiler-numbered anonymous literals
are normalized by their pool locations. All assigned data remains exact.
The TU retains its existing GC/1.3 profile and NonMatching status.

Formatting and generated-path audits, the strict retail checksum, and
`ninja all_source` pass. Local controls and the before/after object audit are
under `build/gc13_new_matches/player_round3*`.

## September 6: Native flags and indexed object loops

This pass cleans 35 TUs and removes 113 unnecessary 64-bit promotions without
changing any of their GC/1.3 function or data match scores. The complete TU
profiles are unchanged. Ordinary integer literals are intentional: replacing
them with unsigned literals can change GC/1.3 code generation too.

| Area | TUs | Removed promotions | Cleaner form |
| --- | ---: | ---: | --- |
| expgfx, modgfx, partfx, and engine slots 26–45 | 23 | 70 | Direct flag constants; remove `0LL` additions/ORs and use compound updates. |
| lightmap, lightmap_draw, pad, shader, texture, object | 6 | 24 | Native flag masks for rendering, C-stick buttons, animation, and model loading. |
| MikaBombShadow, DIM_Boss, EarthWarrior | 3 | 19 | Native masks, direct visibility checks, and simpler sequence-event handling. |
| DoorF4, MAGICMaker, WM_ObjCreator | 3 | 0 | Typed object arrays and `objects[index]` loops; remove redundant casts and visibility temporaries. |

For example, these replace `slot->renderFlags ^= FLAG | 0LL`, a widened
C-stick mask, and a walking object pointer:

```c
slot->renderFlags ^= EXPGFX_RENDER_ATTRACT_TO_PLAYER;
*currentButtons |= PAD_BUTTON_CSTICK_DOWN;
groupObject = groupObjects[i];
```

EarthWarrior also uses the existing `CurvesCollisionState` definition:
`&state->baddie.curvesCollision` replaces a byte pointer plus four, and
`pathState->activeTimer` replaces `pathState[0x264]`. Both offsets already
have canonical layout assertions. DoorF4's message IDs now use the `u32`
type required by the message API, eliminating pointer casts.

All 29 engine/main before-and-after controls score lower under GC/2.0 when
the widened expressions are removed. The three object flag cleanups show
the same distinction:

| Object TU | Original GC/2.0 | Clean GC/1.3 | Clean GC/2.0 |
| --- | ---: | ---: | ---: |
| MikaBombShadow | 100% | **100%** | 97.95918% |
| DIM_Boss | 100% | **100%** | 99.2901% |
| EarthWarrior | 100% | **100%** | 99.748665% |

MikaBombShadow provides a small instruction-level control: without the
widening cast, GC/2.0 folds retail's `lis`/`or` into `oris`; GC/1.3 preserves
the retail instructions. The three indexed object loops also match GC/2.0,
so they are cleanup opportunities rather than compiler discriminators.

Measured exceptions remain. Removing the widening in `Rcp_ClearRenderFlags`,
the pending-map-load `0x800` mask, or `mainSetBits` still regresses GC/1.3.
DoorF4 retains its one-element angle temporary and XOR narrowing casts.
MAGICMaker retains its loaded `groupObject`, and WM_ObjCreator retains the
local reused for state and the spawn condition. Splitting or eliminating
those locals changes code generation.

Allocated section contents, named data-symbol offsets, and normalized
relocations are unchanged in all 35 TUs. Only expgfx and the three indexed
object TUs renumber anonymous literals at preserved pool offsets; the other
31 complete objects remain byte-identical. Other source consumers retain
their objects. Independent Player changes arriving through staging are
excluded from this pass's comparison and match totals.

The object changes land one slot per commit; the mechanical engine and main
audits are separate commits. Active sources and their owning headers pass
clang-format, and the six object paths pass the generated-path audit.
Every landing passes the strict matching build and `ninja all_source` within
30 seconds; the final retail DOL remains byte-identical. Controls and
before/after artifacts are under `build/gc13_indexed/nicer_*`, with the
object packets beside them.


## September 6: Player climbing and backend allocation recovery

Three more functions become exact, adding **4,712 code bytes**:

| Function | Bytes | Before | After |
| --- | ---: | ---: | ---: |
| `playerSetMoveBlendFromPlane` | 708 | 99.66102% | **100%** |
| `playerBuildLedgeClimbProbe` | 1,296 | 99.69136% | **100%** |
| `playerStateClimbWall` | 2,708 | 98.69867% | **100%** |

The blend weight is a signed halfword converted directly from the scaled
floating-point blend factor. Removing the intermediate `int` conversion
matches the helper while preserving its signed-halfword return type and both
already-exact callers. Changing only its return type to `int` would match the
helper but introduce unnecessary extensions in those callers.

The ledge probe now uses `GameObject*` for the hit object, avoiding the previous
pointer-to-integer-to-pointer conversion at its transform calls. Declaring the
plane cursor first also reproduces the retail allocation. The wall-climbing
state similarly declares its player-state pointer first, and uses the existing
native-width hit-detection and position-velocity flags. Its player-state load
remains before the position-dirty call.

`player_SeqFn` also improves from 98.96656% to **99.091156%** after removing
unnecessary 64-bit flag promotions. It remains unfinished. The complete TU
advances from **99.87313% to 99.90971%**, reaching **227/233 exact functions**.
Only these four function bodies change. All allocated data bytes, section
sizes/alignment, and data-symbol offsets remain unchanged. Other functions'
relative relocations are preserved; the changed wall-climbing and sequence
bodies move some relocations along with their instructions. Assigned data
remains 100% exact, and the TU keeps its GC/1.3 profile and NonMatching status.

GC/1.3 backend traces now cover the ledge probe, wall-transition probe,
wall-climbing state, and sequence callback. The decoder recognizes five
additional observed opcodes: `addze`, `oris`, `or`, `rlwimi`, and `fnmadds`.
Each trace passes full instruction/register alignment, GPR graph replay, and
ordinary-versus-instrumented raw object equality. The ledge trace exposed an
extra integer-conversion register lifetime; source controls then verified the
cast and declaration changes. These traces describe this reconstructed source,
not proven original variable names or compiler provenance.

The backend/LLDB tests, formatting and generated-path audits, strict retail
checksum, and `ninja all_source` pass. Controls, captures, and object audits are
under `build/gc13_new_matches/player_round4*`.

## September 6: Further native expressions, with separate formatting commits

Seven more TUs gain cleaner source while preserving every GC/1.3 function
and data match score. The six object TUs retain all **77 exact functions,
34,012 code bytes, and 9,001 assigned data bytes**. Together they remove
27 unnecessary 64-bit promotions. Existing TU profiles and boundaries remain
unchanged; the ProDG decompressor is untouched.

| Object TU | Original GC/2.0 | Clean GC/1.3 | Clean GC/2.0 | Source cleanup |
| --- | ---: | ---: | ---: | --- |
| HitAnimator | 100% | **100%** | 98.28125% | Native polygon/shader masks, direct initial state, redundant casts removed. |
| DIMCannon | 100% | **100%** | 99.79885% | Ordinary indexed history initialization, canonical model flag, typed parent/player and timer accesses. |
| CloudRunner | 100% | **100%** | 99.81897% | Indexed game-bit scan, canonical render flag, direct object members. |
| Sharpclaw | 99.82822% | **100%** | 98.55544% | Native flags, existing animation/target fields, six typed row-speed accesses. |
| Firecrawler | 100% | **100%** | 99.01527% | Typed state locals, native compound flag updates, direct rotation fields. |
| Weevil | 100% | **100%** | 97.66414% | Typed state locals, native compound updates, direct tracked-object fields. |

Sharpclaw provides a discriminator beyond flag literals. Replacing its three
raw `state + 0x308` accesses with the existing `animPlaySpeed` field preserves
GC/1.3's exact idle update, but independently lowers that function from 100%
to 96.23989% under GC/2.0. Its previous GC/2.0 TU score already includes the
earlier Wisp animation-event cleanup.

Firecrawler's native mask expressions need the ordinary compound spelling:
`flags &= ~mask`. Removing the wide mask while retaining `flags = flags &
mask` changes GC/1.3 register allocation. Seven typed state locals then replace
253 repeated casts without changing the generated code. Weevil likewise uses
four typed locals instead of repeating its state casts at each access.

In `lightmap.c`, `getVisibleObjects` indexes `opacity[i]` instead of maintaining
another pointer cursor. Its function remains exact, and the complete TU stays
at 99.7038%. This particular indexing change has identical before/after results
under both compilers. DIMCannon's simpler initialization loop also matches both;
its native model flag supplies the GC/1.3 distinction.

Rejected simplifications remain unchanged: DIMCannon's rotation byte accesses,
CloudRunner's move-ID walk, Firecrawler's hit-volume walks, Weevil's frozen-state
conditions, two Sharpclaw row-speed accesses, and the other tested lightmap
object/child, map-layer, ROM-list, and texture-array traversals. These still
regress GC/1.3 when normalized.

Source cleanup and clang-format changes are separate commits throughout this
pass. Each formatting commit preserves the compiled object from its preceding
source commit. The runbook now explicitly requires this separation. Headers
shared by the slot-202 family keep their declarations and types unchanged;
the Firecrawler row header receives only brace formatting in its format commit.

The final audit preserves all 1,005 compiled objects' allocated contents,
section sizes/alignment, named symbols, relocation targets, and every unit's
match measures. Five cleaned TUs renumber anonymous literals at unchanged
addresses; HitAnimator and DIMCannon remain raw-object identical to their
starting versions. Generated paths and final clang-format checks pass. Each
landing passes strict matching and `ninja all_source` within 30 seconds, with
the retail DOL byte-identical: SHA-1
`e750e8e894707a52446118a4b84f1b58b677b269`.

Local controls and delivery artifacts are under `build/gc13_indexed/nice_313/`,
`dimcannon/`, `cloudrunner_cleanup/`, `sharpclaw/`, `nice_firecrawler/`,
`weevil_cleanup/`, and `lightmap_indexed/`. The full object snapshot is under
`build/gc13_migration/nicer_separate/`.
