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


## September 6: Player update and shared guard eligibility

`playerUpdate` becomes **100% exact**, adding **2,372 matched code bytes**.
Its existing sound-owner temporary is now a typed `const` pointer. GC/1.3
then moves the object into the argument register before selecting the sound
ID, matching retail. The compiler profile and flags are unchanged.

`playerStateMoving` improves from 99.7459% to **99.766396%**. The shared
`playerCanGuard` inline predicate separates the trigger test from guard
eligibility, reproducing retail's branch past the predicate when the trigger
is released. The common-transition handler uses the same predicate and
retains its exact instructions. Caching the sampled X velocity also fixes
four floating-point register differences in the movement state.

Player reaches **228/233 exact functions**, **99.91618% fuzzy agreement**,
and **123,260/139,108 exact code bytes**. Only `playerUpdate` and
`playerStateMoving` change their instructions. Every function's relative
relocations, all allocated data bytes and section layouts, and data-symbol
offsets are unchanged. Assigned data remains **10,168/10,168 bytes exact**;
the TU remains NonMatching.

The root-height-loop trace also verifies the `ble+` spelling of the
previously supported conditional-branch opcode. Its cache-pointer offset
is already folded before global optimization; the retail loop setup still
has two additional instructions. The five remaining functions are the root
height cache, wall-transition probe, sequence callback, moving state, and
state 25. No compiler exception or source split is introduced.

The backend tests, formatting and generated-path audits, strict retail
checksum, and `ninja all_source` pass. Controls, captures, and object audits
are under `build/gc13_new_matches/player_round5*`.

## September 6: Remaining slot-202 native flag expressions

Ten more complete enemy TUs retain all **54 exact functions, 21,320 code
bytes, and 1,696 assigned data bytes** while removing 30 flag widenings and
479 repeated `EnemyState` casts. A scan of every C source in slot 202 now
finds no remaining 64-bit type or literal expressions. The TUs keep their
existing GC/1.3 profiles, source linkage, boundaries, and generated paths.

Each original TU scores 100% under GC/2.0. The final sources give these
results with the complete TU flags held constant:

| TU | Clean GC/1.3 | Clean GC/2.0 | Additional source cleanup |
| --- | ---: | ---: | --- |
| PinPon | **100%** | 98.29384% | Typed state locals and direct curve-init arrays; redundant pointer/conversion casts removed. |
| Vambat | **100%** | 97.80806% | Existing state pointers replace repeated casts; compound flag and timer updates. |
| Hagabon MK2 | **100%** | 98.88285% | Typed matrix/state locals, canonical rotation and render flag, redundant object alias removed. |
| WB | **100%** | 98.74207% | Canonical animation fields and straightforward animation-speed decay. |
| GC robot patrol | **100%** | 99.0% | Scalar placement pointer and existing typed child-setup fields with the asserted allocation size. |
| Mutated Eba | **100%** | 99.347824% | Typed state/object access and simpler byte-table addressing. |
| Rachnop | **100%** | 99.33668% | Typed vectors in the angle/steering helpers and direct climbing predicates. |
| GuardClaw | **100%** | 99.56284% | Direct placement casts and indexed animation-table fields. |
| Spitting Eba | **100%** | 98.26879% | Separate target/projectile pointers and angle local; direct health-field comparisons. |
| Snowworm | **100%** | 99.68511% | Separate setup/projectile pointers, canonical rotation/hitbox fields, native counter increment. |

GuardClaw's old `flags | (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN` expression
becomes `enemyState->controlFlags |= BADDIE_CONTROL_SEQUENCE_DRIVEN`.
Simply removing the widening while retaining the expression based on the
cached `flags` local regresses GC/1.3. The local remains for the surrounding
control-flow reads. Its table access now uses `gSeq11EStateTable[index].anim`
and `.animSpeed` instead of byte offsets and an artificial table pointer.
Independent controls show that the table, placement, and state cleanups
also match GC/2.0; the native compound flag update distinguishes this TU.

Spitting Eba and Snowworm demonstrate that some deliberately reused integer
locals can now become separate typed pointers without changing allocation.
Other boundaries still need their existing spelling: PinPon's final ripple
calls, WB's look-direction call, Mutated Eba's final SFX calls, and Rachnop's
movement call regress when their retained casts are replaced with the typed
aliases. Hagabon keeps two array temporaries whose removal changes registers.

Vambat and Hagabon retain their one-element constant arrays. Scalar forms
can leave every function exact while moving or enlarging `.sdata2` and
changing relocations. Their existing pools and Vambat's documented precedence
bug are preserved. Snowworm's counter increment was tested independently and
matches both compilers without the previous signed-char pointer view.

Every source cleanup and clang-format pass lands in a separate commit.
Formatting, including configured control-brace insertion, preserves the raw
object from the preceding source commit. No shared headers, symbols, splits,
compiler settings, or ProDG decompressor source change in this pass.

All 1,005 compiled objects were audited. The ten cleaned TUs change only
anonymous literal names at unchanged pool locations; allocated contents,
section sizes/alignment, named symbols, relocation targets, and all unit match
measures are preserved. The independent Player improvement in `da68038d3a`
was rebased in and excluded from this cleanup's totals. Path and formatting
checks pass. Every landing passes strict matching and `ninja all_source` with
30-second limits; the final DOL remains byte-identical to retail, SHA-1
`e750e8e894707a52446118a4b84f1b58b677b269`.

Local before/after objects, source/format commit packets, and aggregate counts
are under `build/gc13_migration/native_family/`; full compiler controls are
under the corresponding `build/gc13_indexed/` TU directories.


## September 6: Player wall probe, root cache, and sequence prefix

Two more functions become exact, adding **2,168 matched code bytes**:

| Function | Bytes | Before | After |
| --- | ---: | ---: | ---: |
| `playerBuildWallTransitionProbe` | 1,816 | 98.57929% | **100%** |
| `playerCacheMoveRootHeights` | 352 | 97.045456% | **100%** |

The wall probe consumes the existing `TrackLineIntersectResult` and uses
its real collision object, normals, endpoints, interpolation fraction,
surface type, and trailing byte. Two `EmitPlane` records replace the flat
eight-float plane buffer. Declaring the plane cursor first and indexing the
ground-hit list reproduce the retail registers. The two-byte line cursor
retains its byte-pointer storage shape with the canonical `offsetof` at
each adjacent-line read. Its caller remains exact.

The root-height helper uses one cache index for slot 1 and the later
slots 12–15. Advancing the index across the skipped slots preserves GC/1.3's
retail `li`/`slwi` loop setup. The sampled move IDs and cache stores are
unchanged. A direct constant assignment folds this setup two instructions
short; the incremented-index controls established that difference before
retaining the reused cache cursor.

`player_SeqFn` advances from 99.091156% to **99.97034%**. A typed pointer
to the common `BaddieState` prefix fixes its broad allocation differences,
and promoting the signed-byte health limit to `int` fixes seven remaining
register operands. Eleven differences remain: nine operands in vehicle
selection and two in the initial maximum-health read.

Player reaches **230/233 exact functions**, **99.989075% fuzzy agreement**,
and **125,428/139,108 exact code bytes**. The remaining functions are
`playerStateMoving`, `playerState25`, and `player_SeqFn`. Only the three
functions changed in this pass alter their instructions. All allocated
data, section layouts, and data-symbol offsets are unchanged. Relative
relocations are unchanged outside the root-height helper, whose added
setup instructions move its later call relocations. Assigned data remains
**10,168/10,168 bytes exact**; the TU retains GC/1.3 and NonMatching status.

The strict retail checksum, `ninja all_source`, and generated-path audit
pass after rebasing onto current staging. Formatting is a separate commit
and is checked against the complete pre-format object. Controls and audits
are under `build/gc13_new_matches/player_round6*`.

## September 6: Talk-camera roll smoothing

Engine 69 (`dlls/engine/69/69.c`) reaches **100% for all six functions,
1,316 code bytes, and 120 assigned data bytes**, and is now source-linked
for EN v1.0. `CameraModeTalk_update` adds 1,076 exact code bytes, improving
from 99.90707% to 100%; the complete TU improves from 99.92401% to 100%.

The final roll update uses `(angleDelta * timeDelta) / 16.0f`, removing the
separate roll-step and smoothing-factor temporaries. GC/1.3 folds the division
into the existing multiply-add and assigns the intermediate product and the
integer-conversion constant to retail's registers. The backend trace validates
all 269 instructions, with ordinary and instrumented objects byte-identical.
The same source also matches under GC/2.0; this recovery does not establish a
compiler-version distinction.

Only five instruction bytes change, all in the update function. Every other
function, allocated data byte, section size/alignment, named symbol location,
and relocation record is preserved. The TU keeps its existing GC/1.3 profile,
boundaries, generated path, header, and shared consumers. Formatting is a
separate commit and preserves the raw object.

The generated-path audit and formatting checks pass. Both the strict retail
checksum build and `ninja all_source` pass within their 30-second limits,
with the source-linked DOL retaining SHA-1
`e750e8e894707a52446118a4b84f1b58b677b269`. Source/compiler controls, traces,
reports, and object audits are under `build/gc13_new_matches/camtalk/`.

## September 6: Indexed fragments and shared Baddie native flags

Seven more TUs preserve **102 exact functions, 40,872 matched code bytes,
and 1,852 assigned data bytes**. InvHit's ninth function remains just short
of matching; no existing match regresses. This pass removes 46 flag
widenings, including all 45 remaining in the shared Baddie TU, and replaces
139 repeated Baddie state casts with six typed locals.

| TU | Clean GC/1.3 | Clean GC/2.0 | Source improvement |
| --- | ---: | ---: | --- |
| maketex | 100% | 100% | Scalar checksum accumulators and the existing typed sequence-pair fields. |
| Baddie, slot 201 | 100% | 98.65094% | Native flags, typed state locals, canonical look-direction/velocity and placement fields. |
| InvHit, slot 241 | 99.90453% | 99.90453% | Indexed owner hit list and ordinary pointer conversions. |
| Explodable, slot 346 | 100% | 100% | Indexed chunks, model banks and child slots; typed fragment objects. |
| NW mammoth, slot 417 | 100% | 99.88799% | Native shadow mask, typed rescue-bush positions and direct animation-audio arguments. |
| WarpStone lift, slot 431 | 100% | 100% | Canonical contact count, pointer-sized stride and simpler visibility/placement expressions. |
| DBHoleContr, slot 579 | 100% | 100% | Typed placement, asserted state size, direct visibility and compound animation flags. |

Explodable's build loop now derives the chunk, child slot and model bank from
one fragment index. Changing those three walks together is exact; changing
each independently regresses. Its update loop also indexes children directly.
The existing separate state/placement address locals remain because deleting
them changes register allocation.

Baddie's 42 `LL` literals (including three local macro definitions) and three
`u64` casts become native expressions. Several require ordinary compound
updates. The two action-change assignments in `enemyObjAnimUpdate` retain
their full-assignment form because making those compound regresses GC/1.3.
The sequence callback copies named look-direction and velocity fields and
reads `EnemyPlacement.triggerSequenceId`; steering uses the named direction
instead of an integer address plus `0x2B8`. Shared flag definitions replace
their literal equivalents without introducing aliases.

Original Baddie and mammoth sources both score 100% under GC/2.0. Independent
controls show that their non-flag cleanups still match that compiler; the
native flags supply the differences in the table. Baddie's GC/2.0 regression
spans 12 functions. Mammoth's single shadow-mask control reproduces its final
GC/2.0 score. These are source/codegen controls, not compiler provenance.

InvHit's indexed owner scan preserves its existing instructions, but the
long-lived state pointer still occupies `r30` instead of retail's `r28` in
`InvHit_update` (99.84375%). WarpStone's contact-loop indexing and DBHoleContr's
indexed free loop still regress, so their walks remain. Mammoth retains its
one-element table-pointer array. The checksum helper's two accumulators can
be scalars, but its index still changes codegen, and scalarizing the
remaining save-routine accumulator arrays also regresses. Indexed maketex search loops also regress.

Source and formatting changes land separately. Swaplift needs no formatting
change; each of the other six formatting commits preserves the raw compiled
object from its source commit. Only owning headers receive formatting, with
no declaration or layout changes. No source boundary, generated path, compiler
profile, symbol config or ProDG source changes are part of this pass.

The audit checks all 1,005 compiled objects. Five cleaned TUs only renumber
anonymous literals at unchanged locations; Swaplift and DBHoleContr remain
raw-object identical to baseline. All allocated contents and section metadata,
named symbols, normalized relocations and per-unit match measures are
preserved. Independent Player changes through `ee51eddb36` and talk-camera
changes through `c03c2e64b7` were rebased in and excluded from these totals.
Every source/format landing passes the strict matching build and
`ninja all_source` with 30-second limits. The final DOL remains byte-identical
to retail, SHA-1 `e750e8e894707a52446118a4b84f1b58b677b269`.

Local baselines and whole-build audits are under
`build/gc13_migration/indexed_followup/`. Full source/compiler controls and
separate formatting packets are under `build/gc13_indexed/maketex_cleanup/`,
`baddie_native_cleanup/`, `invhit_cleanup/`, `explodable_cleanup/`,
`dll417_cleanup/`, `swaplift_cleanup/`, and `dbhole_cleanup/`.


## September 6: Player sequence callback exact

`player_SeqFn` reaches **100%**, adding **7,416 exact code bytes**. Vehicle
selection uses a loop-local `GameObject* candidate`; the existing integer
scratch retains its later role as the selected mount. This fixes nine
register operands without disturbing the callback's other allocation.

The maximum-health read reuses the existing integer scratch for the status
address and then its signed health value. The pointer-slot access uses
`offsetof(PlayerState, playerStatus)`, and the value uses the canonical
`PlayerStatus.maxHealth` field. Separate address/value temporaries produce
the final two mismatching operands; this shared scratch reproduces retail.

Player now has **231/233 exact functions**, **132,844/139,108 exact code
bytes (95.497025%)**, and **99.990654% fuzzy agreement**. Only
`playerStateMoving` and `playerState25` remain inexact. The sequence callback
is the only changed function body; every relative relocation, allocated
data section, section layout, and data-symbol position is preserved.
Assigned data remains **10,168/10,168 bytes exact**. The TU retains GC/1.3
and NonMatching status until the two remaining functions are recovered.

Strict matching and `ninja all_source` pass with 30-second limits; the DOL
SHA-1 remains `e750e8e894707a52446118a4b84f1b58b677b269`. The generated-path
audit passes. Controls and before/after audits are under
`build/gc13_new_matches/player_round7*`.

## September 6: World-map camera orbit smoothing

Engine 78 (`dlls/engine/78/78.c`) reaches **100% for all six functions,
3,548 code bytes, and 164 assigned data bytes**, and is now source-linked
for EN v1.0. `CameraModeWorldMap_update` adds 3,212 exact code bytes,
improving from 99.92528% to 100%; the complete TU improves from 99.93236%
to 100%.

Both orbit calculations now keep their orbit offsets and camera-position
errors in separate locals. The declarations pair each axis's offset and
error, with the horizontal X/Z pairs preceding Y. This preserves the
arithmetic order while giving GC/1.3 the retail FPR allocation. Reusing
the offset locals for the errors swapped `f4` and `f6` in six instructions
per calculation. The baseline backend trace aligns all 803 instructions
and preserves the ordinary compile's raw object. The accepted source also
matches under GC/2.0; this is source recovery, not a compiler discriminator.

Only 12 instruction bytes change, all in the update function. Every other
function, allocated data byte, section size/alignment, and named symbol
location is preserved. Anonymous literal symbols are renumbered; all 57
affected relocations retain their types, locations, and resolved targets.
The TU keeps its common GC/1.3 compiler, existing optimization profile,
boundaries, generated path, header, and shared consumers. Running
`clang-format -i` leaves the source and header unchanged, and both pass
`clang-format --dry-run --Werror`.

The generated-path audit and both build gates pass on fresh staging. The strict
matching build takes 20.04 seconds and `ninja all_source` takes 25.18 seconds, each
within its 30-second timeout. Only this TU's source object changes, and
the source-linked DOL retains SHA-1
`e750e8e894707a52446118a4b84f1b58b677b269`. Source/compiler controls,
reports, traces, and object audits are under
`build/gc13_new_matches/worldmap_match/`.

## September 6: Indexed object access and remaining object flag widenings

Seven more TUs retain all **150 existing exact functions out of 152**, across
43,840 code bytes and 2,712 assigned data bytes. Four pointer walks now use
ordinary indexing: the two nearest-object searches, object-list membership,
and child rendering. Fourteen artificial 64-bit flag widenings are removed:
three in DBSH_Symbol, one in DIM2PrisonM, nine in KT_Rex, and one in slot 263.

| TU | GC/1.3 after | GC/2.0 before | GC/2.0 after | Accepted source cleanup |
| --- | ---: | ---: | ---: | --- |
| objlib | 100% | 100% | 100% | Indexed nearest-object and membership scans. |
| objprint | 99.82651% | 99.82651% | 99.82651% | Typed model banks and child objects; indexed child rendering. |
| DBSH_Symbol, slot 406 | 100% | 100% | 98.939095% | Native shadow flags, direct object fields and compound spin updates. |
| DIM2PrisonM, slot 473 | 100% | 100% | 99.36937% | Native model flags and the canonical EarthWarrior state at the reused callback. |
| KT_Rex, slot 592 | 100% | 98.03416% | 97.62033% | Native phase flags and direct object arguments. |
| DLL 263 | 100% | 100% | 99.62939% | Native model flag, embedded animation fields and compound movement updates. |
| DFP_Lightni, slot 571 | 100% | 100% | 100% | Typed effect endpoints and an ordinary biased-double expression. |

The compiler comparisons hold the TU boundaries and other build settings
fixed. Rex's non-flag control retains its original GC/2.0 score; the native
flags account for its regression. The prison mammoth's native-mask-only
control also reproduces its final GC/2.0 score. These are source/codegen
comparisons, not proof of the original compiler version.

The prison mammoth's after-bones helper is installed only by DR_EarthWar.
It now explicitly casts the reused object's extra storage to the existing
`EarthWarriorState` and uses `sub.modelChain`, replacing a local padded
view. The canonical assertions place that field at 0x14F8 in the 0x14FC
EarthWarrior allocation; the mammoth's own 0x604 state remains separate.
Four descriptor casts are removed only where their prototypes exactly
match the callback typedef.

Lightning's endpoints become `Vec3f` values with typed pointer aliases.
Its unused conversion helper retains the exact 2^52 bias while replacing
64-bit construction and type-punning with double arithmetic. Deleting the
helper renumbers anonymous literals, so a compact explanation records why
it remains. No helper body is emitted, and its private rename has no callers.

The existing objprint mismatches in `objJointTracksAimAtTarget` and
`staffUpdateSegmentTransforms` remain unchanged. Indexed path-search heap,
node and link variants still regress, as do Rex's indexed lane/gamebit
walks and several longer-lived typed locals; those experiments are not
retained. The object-source scan now finds no `u64`/`s64` spellings or
`LL`/`ULL` integer literals outside Player, which remains a separate lane.
This does not claim that the remaining main-code conversions or genuine
64-bit arithmetic can be removed.

Each TU's source change and clang-format output land in separate commits.
All seven formatting commits preserve their source commit's raw object.
Only the existing owning lightning header needs a formatting change; the
other owning object headers already pass the formatter, and shared main
headers are untouched. No compiler override, TU boundary, generated source
path, symbol config or ProDG change belongs to this pass.

The complete 1,005-object audit preserves every unit's match measures.
Five cleaned objects are raw-identical to baseline; objlib and DBSH_Symbol
only renumber anonymous literals at fixed positions. Allocated section
contents, sizes, alignment and flags, named symbols and normalized
relocations are unchanged. Independent upstream Player `d51abdf78c` and
world-map camera `f10a37f854` changes were rebased in and excluded from
these cleanup totals. Their source was checked against the upstream
commits before updating only their baseline entries.

Strict matching and `ninja all_source` pass with 30-second limits for every
source and formatting landing. The final DOL remains byte-identical to
retail, SHA-1 `e750e8e894707a52446118a4b84f1b58b677b269`. The generated-path
audit passes for all five object slots. Baselines and the final audit are
under `build/gc13_migration/remaining_flags/`; source/compiler controls and
separate formatting packets are under `build/gc13_indexed/objlib_cleanup/`,
`objprint_cleanup/`, `dbsymbol_cleanup/`, `prisonm_cleanup/`,
`ktrex_native_cleanup/`, `dll263_cleanup/`, and `lightning_cleanup/`.

## September 6: Viewfinder camera transition state

Engine 68 (`dlls/engine/68/68.c`) reaches **100% for all ten functions,
5,944 code bytes, and 192 assigned data bytes**, and is now source-linked
for EN v1.0. `CameraModeViewfinder_update` adds 1,452 exact code bytes,
improving from 99.338844% to 100%; the complete TU improves from 99.83849%
to 100%.

The update uses separate locals for the curve-completion result and pitch
delta, and for the fade brightness and exit-completion flag. Keeping the
exit flag beside the brightness declaration reproduces retail's allocation:
the camera stays in `r31`, the fading target in `r30`, and the completion
flag in `r29`. Splitting only the pitch delta leaves three wrong flag
operands; separating both roles resolves all 47 differing instructions.
The accepted backend trace aligns all 363 instructions, replays all 117
GPR color choices, and produces the same raw object as an ordinary compile.
The source also matches under GC/2.0, so this is not a compiler discriminator.

Only 53 instruction bytes change, all in the update function. Every other
function, allocated data byte, section size/alignment, and named symbol
location is preserved. Nine relocations rename anonymous literals while
retaining their types, locations, and resolved targets. The common GC/1.3
compiler, existing optimization profile, TU boundaries, generated path,
header declarations, and shared consumers are unchanged. Formatting fixes
two indentation lines in a separate commit and preserves the raw object.

The strict matching build and `ninja all_source` pass with 30-second
timeouts. Only this TU's source object changes in the isolated build audit;
the source-linked DOL retains SHA-1
`e750e8e894707a52446118a4b84f1b58b677b269`. Source/compiler controls,
reports, backend traces, and object audits are under
`build/gc13_new_matches/viewfinder_match/`.

## September 6: Game-loop, egg, stealer-worm and SnowBike source forms

Four TUs retain **126/126 exact functions**, **45,916 code bytes** and
**4,980 assigned data bytes**. Five pointer walks become indexing: the
game-loop render list, DB_egg's ground-hit and sibling lists, and the
stealer-worm's parallel avoidance-group and weight arrays. The worm's
message stack also indexes its existing three-word records directly.

| TU | GC/1.3 before/after | GC/2.0 before/after | Accepted source cleanup |
| --- | ---: | ---: | --- |
| gameloop_main | 100% | 100% | Direct object-list indexing for model and fuzz rendering. |
| DB_egg, slot 575 | 100% | 100% | Indexed scans, typed setup state, named payload fields and compound updates. |
| DBstealerwo, slot 578 | 100% | 95.730446% | Indexed avoidance/messages, typed target union views and direct control/animation fields. |
| SnowBike, slot 597 | 100% | 96.4732% | Typed setup/placement access, direct bitfield tests, ordinary rank predicate and angle updates. |

All compiler controls use the complete TU and its existing profile. This
batch adds no new GC/1.3 discriminator: every accepted rewrite preserves
its original GC/2.0 result as well. The worm's existing GC/2.0 differences
remain in effect processing and update; SnowBike's remain in mount-state,
update and initialization.

DB_egg's setup uses one `DbEggState*` and `waterOffset`, and its pickup
messages take the address of `msg11C` instead of adding 0x11C to an integer
pointer. Existing mode and model-flag definitions replace numeric equivalents.
Descriptor casts are removed only for the two void callbacks and extra-size
callback whose prototypes exactly fit their slots. The source's descriptor
and diagnostic declaration order is preserved.

The worm uses the existing `linkedObject` and `savedTargetObject` union
members at +0x18 and +0x3C in the unchanged 0x50 control record. Four
control reads no longer alias `obj->extra` through a pointer-to-pointer.
Required casts at integer message handles, void target fields and reused
queue/object locals remain. Its documented scratch overruns are untouched.

SnowBike's rank predicate becomes an ordinary subtraction/zero comparison
instead of `__cntlzw`. Its typed setup pointer still occupies a one-element
array: scalarizing either the old byte pointer or new typed pointer changes
initialization codegen. `SnowBikePathSetup` remains 0x4C; the race-gamebit
access still crosses separate symbols to the table at .data+0xA4. Direct
table indexing regresses, so no field or enlarged setup record is invented.

Other retained forms have explicit controls: DB_egg's homing scratch-vector
access, ripple condition and hit-state macro; the worm's reverse/object/joint
scans; SnowBike's trail walks and cached hit-state alternatives. Main-code
probes also reject indexed matrix multiplication/copy, voxel occupancy and
shadow-caster/slot access, scalar debug-text cursors, and simpler gamebit
limit/decrement expressions. These experiments leave tracked code unchanged.

Formatting lands separately for the three object sources. Every formatting
commit preserves the raw object from its source commit. The game loop and
the worm/SnowBike owning headers already pass clang-format without changes.
DB_egg's two existing owning headers receive formatting only; their legacy
header consolidation and unrelated assertion imports remain outstanding.
No shared consumer code, compiler profile, symbol config, TU boundary,
generated source path or ProDG source changes belong to this pass.

The whole-build audit covers 1,005 objects and preserves all per-unit match
measures. Game-loop and SnowBike objects are raw-identical to baseline.
Egg and worm only renumber anonymous literals at fixed positions; allocated
bytes, section sizes/alignment/flags, named symbols and normalized relocations
are unchanged. Upstream viewfinder-camera commits `82b1014059` and
`96d350266f` were rebased in, checked against their published source, and
accounted for separately in the camera's baseline entry.

Every source/format landing passes strict matching and `ninja all_source`
with 30-second limits. The final DOL is byte-identical to retail, SHA-1
`e750e8e894707a52446118a4b84f1b58b677b269`; generated-path audits pass for
slots 575, 578 and 597. Baselines and the final audit are under
`build/gc13_migration/indexed_matrices/`. Controls and separate source/format
packets are under `build/gc13_indexed/gameloop_main_index_cleanup/`,
`dbegg_index_cleanup/`, `dbstealer_index_cleanup/` and `dll597_index_cleanup/`.
