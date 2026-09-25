# Map-rendering TU and pool recovery (2026-09-07)

Latest EN status (2026-09-24): **145/145 exact functions, 100% instruction
similarity, and 40,668 exact assigned data bytes**. The source object links to
the retail DOL SHA-1. The historical measurements below describe their
individual checkpoints.

The shared map-rendering `.sdata2` pool is now exact. The five artificial
fragments `shader`, `lightmap`, `lightmap_initmapblocks`, `lightmap_draw`, and
`tex_dolphin` have been reunited in `src/main/shader.c`, in retail function order.
At that checkpoint, all 40,656 assigned data bytes matched. The common GC/1.3
invocation produced 139/145 exact functions and a 99.62504% instruction fuzzy
score.

This supersedes the constant-pool blocker in
[lightmap_draw_recovery.md](lightmap_draw_recovery.md) and the historical
compiler-profile rejection in [dll_naming_manifest.md](dll_naming_manifest.md#yield).
The previous 29 drawing functions remain exact inside the combined TU.

## Retail boundary evidence

The unit occupies EN `.text` `0x80054F64..0x80061094`. Its pool occupies
`0x803DEBB0..0x803DEC58`. There are 151 direct r2-relative loads into that pool,
all within the combined text range. Constants such as `640.0f`, `0.5f`, and
`0.125f` are shared across the former file boundaries. The adjacent texture and
shadow units use separate pools. Compiling the combined source now reproduces
the complete pool's values, order, alignment, and named scale-symbol offset.

The stored filename `shader.c` is retained. Disc source-leak and source-matrix
searches did not establish an original filename for this span. Dinosaur Planet's
map source supplies related algorithmic structure, not proof of SFA's filename.

| Section | EN start | EN end | Assigned bytes |
|---|---|---|---:|
| `.rodata` | `0x802C1E58` | `0x802C1EA8` | 80 |
| `.data` | `0x8030E4B0` | `0x8030E864` | 948 |
| `.bss` | `0x8037E0C0` | `0x803879B0` | 39,152 |
| `.sdata` | `0x803DB620` | `0x803DB648` | 40 |
| `.sbss` | `0x803DCDC8` | `0x803DCED4` | 268 |
| `.sdata2` | `0x803DEBB0` | `0x803DEC58` | 168 |

## Source and storage recovery

Ordinary float expressions replace external declarations that merely named
compiler literals. Dividing packed coordinates by `8.0f`, the indirect matrix
scale by `2.0f`, and flare size by `256.0f` recovers the target reciprocal literals
and operand order. The initial white word is a real `GXColor` copied by shader
texture setup.

`gTexIndMtxScale` is a stored `0.0625f` at pool offset `0x74`. Reading it through a
local `const f32*` preserves its single allocation. Reading the same-TU constant
directly makes MWCC retain the named word and emit a duplicate anonymous literal.
The pointer's scope is the matrix-scale calculation, and the function remains
exact. No synthetic section declarations or padding objects are used.

The source emits 164 pool bytes; the linker supplies four bytes of alignment.
The two internal zero alignment words are at `0x803DEBBC` and `0x803DEC44`.
Neither those words nor the trailing word at `0x803DEC54` has a direct retail
load. The actual shared floating zero is at `0x803DEBCC`.

The render queue now has 1,000 typed 16-byte entries, matching its runtime flush
threshold, followed by an opaque 200-byte tail. Assertions retain the existing
`0x3F48` allocation and the tail's offset. The tail is not promoted into extra
queue capacity. BSS definitions are collected in the compiler's reverse
allocation order so all sixteen native BSS objects retain their retail offsets.
The audit also checks the other named data symbols; zero-filled section equality
alone would not catch their displacement.

The native layer-search loop in `mapSetup` and the indexed page walk in
`mapRomListFindItem` replace an unrolled search and an array-of-one cursor.
Both functions now match exactly. `beginLoadingMap` also becomes exact in the
combined unit. Native queue accesses preserve the drawing functions and reduce
the `renderObjects` mismatch.

## Remaining source-link blockers

The subsequent code pass restores four functions without changing their sizes
or any other function's generated instructions:

- `renderSceneGeometry`: initialize the horizontal cursor alongside the row's
  minimum X before computing the cell pointer. Keep the row bound and moving
  cursor as separate locals.
- `collectShadowTrackTriangles`: select the triangle flag with an explicit
  branch and declare the triangle count before the descriptor pointers. The
  compiler trace confirms the ternary introduced a temporary that colored
  ahead of the loop's persistent registers.
- `mapBlockRender_setShader`: read the three packed instruction bytes with
  offsets from an unchanged base pointer. This removes the mutable pointer web
  responsible for the final register swap.
- `mapInstantiateObjects`: correct `MapEventInterface.getMapAct` and its inline
  wrapper to take `int`, matching `SaveGame_getMapAct`, then restore the cursor,
  end pointer, and object-index declaration order. Dolphin's `s32` is `long`
  under MWCC; the old interface introduced an int-to-long conversion temporary.
  Comparing all 2,684 compiled objects before and after the interface correction
  found no changes outside this function in `shader.o`.

The GC/1.3 backend decoder now also recognizes the observed `andc`, `srw`, and
`psq_lx` records. They were validated against captured final instruction streams
and emitted ELF instructions. The diagnostic captures passed the ordinary versus
instrumented full-object hash gate, and their register graphs replayed without
high-degree removals.

A second code pass restores three more functions:

- `updateEnvironment`: separate inline routines update texture animations and
  texture scrolling. The animation routine uses a native indexed array walk;
  the scroll routine retains its byte cursor. Inlining makes the zero
  initializers eligible for commoning, and the local declaration order restores
  both the integer and floating-register assignments.
- `renderGlows`: ordinary `f32` locals retain zero and one across the FIFO
  writes, removing sixteen extra literal loads. Making those locals `const`
  reinstates the extra loads under the shared GC/1.3 profile. The render-flag
  test also keeps the retail signed comparison. The function and its complete
  pool-load sequence are now exact.
- `initMapBlocks`: initialize all five layers through the existing typed buffer
  view, then clear 120 ROM-list page pointers with one ordinary loop. MWCC
  supplies the forty-store unrolling that was previously handwritten. The
  page cursor is typed, and the existing two-part base-address expression is
  retained because collapsing it changes the address temporary's register.

The next pass restores `queueGlowRender` by directly indexing the frustum plane
array in its distance expression. The early local plane-pointer assignment made
MWCC place the plane-table address before the zero literal. The direct accesses
let the constant load precede that address, reproducing the complete function.
The GC/1.3 trace decoder also recognizes the observed `beqlr-` and `bgelr-`
conditional returns, so this function can pass its instruction-alignment audit.

`unloadMap` and `doPendingMapLoads` now share the private inline
`mapReleaseBlockReference` routine. It owns the negative-slot guard, reference
count decrement, final slot removal, shader-layer resource release, texture
release, optional buffers, and block free. The shader walk retains an explicit
byte cursor and an independent index; their initialization and update order
reproduce retail's zero sharing. The helper takes a promoted integer slot, which
also preserves the byte-load/sign-extension sequence in `unloadMap`. No
out-of-line helper is emitted.

This raises `unloadMap` from 97.92208% to 99.512985%, reducing 41 differing
instructions to twelve register-operand differences. `doPendingMapLoads` rises
from 98.458015% to 98.65522%. The two callers preserve the existing release order,
including clearing the slot before callbacks and freeing the block last. All
other function bytes and the assigned data remain unchanged.

A later pass gives the texture-release loop its own counter, declared before
its shader-loop counterpart. This recovers the four texture-counter operands in
`unloadMap`, leaving eight differences from the shader byte cursor and layer
cursor register swap. `unloadMap` reaches 99.67532%, and `doPendingMapLoads`
reaches 98.71247%, with every other function body unchanged.

The pending-load path also restores ordinary 16-by-16 loops for its vestigial
cell-grid walk. GC/1.3 performs the chunking itself and emits the retail
`1344`-byte and seven-row increments; the previous manually chunked source
emitted `1152` and six. The pointer and row registers still differ. This removes
two unused loop locals and raises `doPendingMapLoads` to 98.71501%. Both build
gates pass, all 120 native data-symbol layouts remain exact, and all forty
literal-consumer value sequences remain unchanged. Formatting preserves the raw
compiled object.

`sceneDraw` now reads the queue count through an explicit `const int*` view
when advancing it after each render-pass entry. As in the cloud renderer's
const-qualified extent reads, this spelling preserves loads that GC/1.3 would
otherwise merge. Both missing `lwz` instructions return, bringing the function
from 99.2% to 99.81333% and its size from 1,492 to the retail 1,500 bytes.
Eleven instructions still differ in register operands. This is a source-spelling
reconstruction, not evidence that the original used this exact cast; it adds no
volatile accesses and leaves the stored count type unchanged.

A follow-up captures a `const int queueIndex` for each pass entry and uses it
for both stores. This preserves the shared entry index and recovers the retail
registers for the sort key and scaled index. `sceneDraw` reaches 99.94666%:
only the deferred-object loop counter's initialization, increment, and comparison
differ (`r29` instead of `r28`). The two compiler traces reproduce their ordinary
objects exactly, align all 375 instructions, and replay GPR coloring with no
high-degree removals. An ordinary signed local index and a pre-scaled byte offset
do not reproduce the same code; no alternative compiler settings are involved.

The child-object pass now indexes the canonical `player->childObjs[i]` array.
GC/1.3 produces the same pointer-walking instructions as the previous byte cursor
and repeated `GameObject*` casts. All function and data-section bytes, named
symbol layouts, and relocation targets remain unchanged. Anonymous compiler
labels are renumbered, so raw object identity changes despite identical emitted
code and data. The deferred-loop counter still differs in three instructions:
retail uses `r28` (also used later for the player pointer), while the child-loop
counter correctly uses `r29`.

The ROM-list position fixup now uses `ObjPlacement.posX` and `posZ` instead of
unrelated `GameObject` animation fields at the same offsets. Its function bytes
are unchanged. Only `sceneDraw` changes compiled code in this pass; all other
144 functions, including both unload paths, retain their previous bytes.

`mapProcessRomList` now matches all 140 retail instructions. A private
`ShaderRomListCursor` groups the selected slot index with its entry pointer,
recovering six register operands. The cached-page store computes its byte offset
before the base address and adds them in that order. This recovers the remaining
`slwi` / `addis` / `add` ordering without changing the compiler profile.

| ROM-list source | Instruction fuzzy score |
| --- | ---: |
| Previous independent locals and cache expression | 99.64286% |
| Cursor only | 99.92857% |
| Explicit cache offset/base only | 99.71429% |
| Both changes | 100% |

The instrumented backend reproduces the ordinary object exactly, captures
17 stages, and aligns all 140 instructions with zero retail differences. GPR
simplification replays without high-degree removals.

The same cursor type improves ROM-list retirement in `doPendingMapLoads` from
98.71501% to 98.77226%. Its cell-loading walk also replaces the temporary
`zc[2]` array with named `cellIndex` and `row` fields; that change alone preserves
the complete raw object. Naming the shared cursor type likewise preserves the
object produced by the equivalent local records. Only `mapProcessRomList` and
`doPendingMapLoads` change function bytes in this pass; every previously exact
function remains exact.

The frustum builder now reserves sixteen matrix floats, matching the complete
`setMatrixFromObjectPos` write contract (`m[0]` through `m[15]`). It also uses one
sequential plane index instead of repeatedly assigning literal indices and
introducing a second zero-valued index for the first distance store. The
Dinosaur Planet frustum routine supports this sequential structure, but its
signed-short index is not adopted as EN type evidence. Both corrections preserve
the entire raw object, including anonymous symbols and relocations; they do not
change the remaining `updateVisibleGeometry` instruction differences.

The old `lightmap` and initializer fragments depended on extra `noprop` and
`nocse` flags. They now share shader's existing `nopeephole,noschedule` /
`-inline noauto` profile and the required common game compiler. No compiler
exceptions, per-function pragmas, or section-alignment overrides were retained.
The initial merge exposed six formerly exact functions: `updateVisibleGeometry`,
`renderObjects`, `renderSceneGeometry`, `initMapBlocks`, `renderGlows`, and
`queueGlowRender`. Three other functions became exact, so that merge changed the
combined exact function count from 132 to 129. The follow-up passes bring it to
139. All six remaining code differences must be recovered before
`MatchingFor` is justified.

All forty functions that directly consume this pool now have matching literal
value sequences. This includes `renderGlows`, whose extra zero/one loads were
removed in the second code pass.

At this stage, two zero fog-color records at `.sbss2` `0x803E8444` and
`0x803E8448` remained retail externs (`gTexShaderFogColor` and
`gTexLightmapFogColor`). They and the preceding glow-color template are now
recovered through native initializers in the
[zero-color ownership follow-up](shader_zero_fog_colors.md), preserving their
actual `.sbss2` storage and retail order.

The regional `version_progress.py <version> --write` refreshes were attempted
for EN rev1, JP, PAL, and PAL rev1, but their DOLs are absent in this checkout.
Only their already-established fragment claims were merged; no regional pool
claim, symbol projection, or new match was inferred. The deleted initializer's
stale matching-unit entries were removed.

## Verification

`python3 tools/map_render_data_audit.py` checks 40,656 assigned data bytes,
118 common native symbol layouts, 40 jump-table relocations including their
function-relative destinations, the unique stored scale, and all 151 direct
retail pool loads. It compares the pool against the original DOL as well as the
regenerated retail object. Deliberately corrupting a literal and moving the
queue symbol in separate scratch objects both correctly fail the audit.
MWCC's writable ELF flag on `.sdata2` differs from the reconstructed retail
ELF's flag; the audit permits that compiler metadata difference, which has no
DOL representation, while checking type, allocation, and alignment.

`ninja all_source` and the strict matching build pass with 30-second timeouts.
The matching DOL remains byte-identical to the prior retail build. This gate
still links this TU's retail object and is not a claim that its source-linked
DOL is exact. Formatting is committed separately and checked to preserve the
complete generated object; the TU and its internal header pass
`clang-format --dry-run --Werror`.


## Distortion, deferred objects, and cell-render state (2026-09-07)

The previous `distortionFilterVector[28]` declaration covered three independently
used objects. EN consumers establish this complete, nonoverlapping decomposition:

| EN address | Size | Recovered storage | Evidence |
| --- | --- | --- | --- |
| `0x803821C8` | `0x0C` | `distortionFilterVector[3]` | `turnOnDistortionFilter` writes three floats; `sceneDraw` passes that vector to the distortion renderer. |
| `0x803821D4` | `0x50` | `gLightmapDeferredObjects[20]` | `renderObjects` checks the count against twenty and stores object pointers; `sceneDraw` walks the same pointer list. |
| `0x80382224` | `0x14` | `gMapCellRenderState` | `sceneDraw` passes this address to `mapDebugRender`, which initializes the canonical five-field `ModelRenderInstrsState`. |

The final state ends exactly at the existing `gShaderMapRomBuffers` boundary.
The twenty-entry list comes from its runtime bound, not from filling a gap.
The EN symbol config now records these objects separately. Reverse source
declaration order preserves their existing BSS addresses and every neighbor.
Other regions retain their conservative previous labels.

`mapDebugRender` now accepts `ModelRenderInstrsState*` in its public declaration
and definition. The canonical state header asserts its size and all five field
offsets. The main, water, and transparent block renderers also use that type
instead of `int state[5]`, with named instruction-pointer and bit-cursor fields.

Two existing source shapes remain necessary in those already-exact renderers:
the instruction cursor adds its byte offset through an integer address, and
the skipped-entry loop writes the bit cursor through an explicit int cast.
Removing the latter lets MWCC combine the eight unrolled cursor stores; changing
the former to pointer addition changes the load sequence. Keeping those narrow
casts allows the real state type without changing a single function byte.

The scene-level queue-base accesses remain pending recovery. Direct references
to the newly named globals change `sceneDraw` or `renderObjects` code generation;
this pass establishes the storage ownership without substituting those probes.
All shader function bytes, allocated section bytes, and relocation records
remain identical to the prior source object. Only the old oversized symbol and
the two newly recovered symbol definitions change in its named storage layout.


The data audit passes with 40,656 assigned bytes, 120 native symbol layouts,
40 data relocations, and 151 direct retail pool loads. `mapDebugRender` and
all three typed block renderers remain 100% matched. Rebuilding shared-header
consumers changes only anonymous symbol numbering in `TexFrameAni.o` and
`camcontrol.o`; their function bytes, section bytes, named layouts, and every
relocation location, kind, addend, and target offset remain unchanged.
Both 30-second-bounded build gates pass after matching configuration
(`main.dol: OK`). Formatting is recorded separately and preserves generated
objects. The shader unit still links its retail object while its remaining
mismatched functions are recovered.


## Exact scene drawing (2026-09-07)

`sceneDraw` now matches all 375 instructions. Indexing the deferred-object list
with `deferred[i]`, together with declaring `player` before the loop index and
list pointer, recovers the target register allocation. MWCC generates the same
pointer walk from this ordinary array traversal. The index alone leaves the
previous three differences; the declaration order alone leaves four pointer
register differences. Both changes are required.

Only `sceneDraw` changes instruction bytes. All assigned data bytes and named
symbol layouts remain unchanged. Anonymous symbols after this function are
renumbered by one; relocation locations, kinds, addends, and target offsets
remain identical. The TU reaches 139/145 exact functions and remains
`NonMatching` while the other six functions are recovered.

The data and literal-sequence audits pass, as do `ninja all_source` and the
strict retail checksum gate with 30-second timeouts. Formatting preserves
the probe object byte-for-byte. The strict build continues to use the retail
shader object.


## Explicit layer traversal during block release (2026-09-07)

`mapReleaseBlockReference` now walks shader layers with an explicit byte cursor.
The cursor retains the retail shader-base bias; each iteration obtains its
`ShaderLayer*` through canonical `offsetof(Shader, layers)`, and advances by
`sizeof(ShaderLayer)`. Initializing the layer index before the pointer, and
advancing the pointer before the index, preserves retail instruction order.
The shader pointer, layer cursor, and shader byte offset declaration order
then recovers the layer cursor's target register.

`unloadMap` improves from 99.67532% to 99.77273%, reducing its eight differing
instructions to five. Its remaining mismatch swaps the shader pointer and
shader byte offset registers. The shared helper also improves
`doPendingMapLoads` from 98.77226% to 98.79135%. All other function bytes,
assigned data bytes, named symbol layouts, and relocation locations, kinds,
addends, and target offsets remain unchanged. The TU remains `NonMatching`
with 139/145 exact functions and a 99.577324% fuzzy score.

Formatting preserves the probe object byte-for-byte. The data and literal
audits, `ninja all_source`, and strict retail checksum gate all pass; each
Ninja invocation is bounded to 30 seconds. The strict build continues to
link the retail shader object.

## Typed deferred-object list (2026-09-07)

`renderObjects` indexes the deferred list as object pointers from its cached
queue base. This reproduces retail's base-first address addition and improves
the function from **99.73684% to 99.82456%**. Its 114-instruction size is unchanged;
the remaining two differences are operand order in the object-shadow entry
stores. Whole-TU fuzzy similarity rises from 99.62423% to 99.62504%, retaining
139/145 exact functions.

The old `LightmapDrawQueue` view misleadingly exposed twenty raw words after
padding. `MapDeferredObjectListView` now describes the actual twenty object
pointers and asserts their `0x4114` base-relative offset and `0x50` extent.
It is explicitly an address view: `gLightmapDeferredObjects` remains a separate
BSS allocation, and the actual render queue retains its `0x3F48` storage size.
The count limit, pointer stores, native BSS symbol and `sceneDraw` consumer
establish this layout. The exact consumer now uses the same view instead of
a literal offset.

The producer keeps a narrow pointer-array cast at the cached byte-base access.
Directly indexing the view member there makes MWCC use an indexed store with
an extra address calculation, unlike retail. No broader pointer lifetime or
allocation is introduced.

Only one instruction word changes in the complete object. Every other function,
all non-text section contents, named layouts and resolved relocations remain
unchanged. The data and literal audit passes, as do the full source build and
strict retail checksum with 30-second timeouts. Formatting preserves the raw
object. The TU remains `NonMatching`, so the strict link still uses retail.

## Cached queue addressing in object rendering (2026-09-07)

`renderObjects` now uses its cached byte base for both object-shadow queue
entries and the deferred-object list. The entry stores use the complete byte
offset, expressed with `sizeof(LightSortEntry)` and `offsetof(LightSortEntry,
type)`, and increment the queue count directly. The deferred store writes a
`GameObject*` using the existing pool-relative list view. The local model-state
pointer uses `ObjModelState`, and the sort/deferred indices have explicit names.

These accesses retain the proven common BSS base. Direct native-global accesses
rematerialize queue addresses; ordinary cached typed-array indexing instead
emits indexed stores and changes constant-load order. The selected byte-offset
expressions recover the retail instruction sequence without changing ownership
of the separate queue, sort-key, and deferred-list globals.

The function improves from 94.86842% to 99.73684% and shrinks from 472 to the
retail 456 bytes. All 114 instruction kinds now agree. Only three commuted
`add` operand pairs differ, at the deferred and two shadow entry addresses.
The surrounding tests, calls, stores, increments, and control flow match.

All other 144 function bodies remain byte-identical. Their relocation locations
relative to each function and resolved destinations remain unchanged, as do all
non-text section bytes and named data layouts. The changed function loses four
redundant queue-address relocations; its remaining relocation targets and kinds
are preserved. Subsequent function symbols move back sixteen bytes. The TU
reaches 99.62221% fuzzy, retains 139/145 exact functions, and keeps all 40,656
assigned data bytes exact.

The data and literal-sequence audits pass. Formatting is separate and preserves
the raw object. `ninja all_source` and the strict retail checksum gate pass with
30-second bounds; the TU remains `NonMatching` and the strict link uses retail.

## Typed map-layer allocation and reset (2026-09-07)

`MapLayerBuffers` now describes the types of the three already-owned pointer
tables. Its `cellEntries` member points to `MapCellEntry` records; `blockIndices`
and `cellStates` use the signed-byte types of the corresponding native globals.
The address view does not merge or resize those globals. Assertions fix their
pool-relative offsets at 0x41E0, 0x41F4, and 0x41CC respectively.

`initMapBlocks` allocates five layers of 256 entries for each table and advances
the typed pointers by 256 entries per layer. This preserves the existing 0x500
byte-index allocation, 0x3C00 cell-record allocation, and 0x500 state allocation.
`beginLoadingMap` uses the same record type and explicitly sets each cell's
`romListIndex` to -1 alongside its signed block index. The reset leaves the
other cell fields untouched. The canonical cell definition asserts that this
byte is at offset 0x09 within the existing twelve-byte record. The block-ID
reset also uses its native halfword array.

The cached common BSS base remains necessary. Its table accesses use signed
`offsetof` expressions, preserving the integer expression types accepted by
the existing compiler profile. No compiler options or storage definitions
change. Both initialization functions remain exact, and the complete shader
object is byte-for-byte identical before and after this recovery. Rebuilding
the shared headers leaves all 1,002 source object hashes unchanged.

Formatting is separate. Data and literal-load audits, `ninja all_source`, and
the strict retail checksum gate pass, with each Ninja run bounded to 30 seconds.

## Native-array pool allocation diagnostic (2026-09-07)

The three remaining commuted `add` operands in `renderObjects` can be reproduced
in retail order with native accesses to the queue, deferred list, and sort keys.
The deciding factor is when MWCC learns the BSS definitions, not private linkage:
moving the complete public definitions before the functions enables automatic
pool-relative addressing too. Those uninitialized objects are then allocated in
compiled use order, which changes their offsets. Reversing their declaration
order does not restore the retail layout in that configuration.

A separate scratch test defines the eighteen objects before the functions in
retail address order with explicit `{0}` initializers. This preserves their
relative offsets and makes native-array `renderObjects` 100% under the current
compiler and optimization flags. It is **not a valid matching change**: MWCC
moves all 39,152 bytes from `SHT_NOBITS` `.bss` into `SHT_PROGBITS` `.data`, growing
`.data` from 948 to 40,100 bytes. It also reduces `sceneDraw` to 99.44%. The
`explicit_zero_data off` diagnostic does not change that aggregate emission.
No initializer, linkage, definition-placement, or compiler-option changes from
these tests are retained.

This distinguishes an instruction-generation solution from an ownership
solution. A usable native-array recovery must preserve the BSS section, every
native symbol offset, and the already-exact functions as well as reproducing
the three adds. The retained source remains 139/145 exact, with `renderObjects`
at 99.73684% and the TU at 99.62221%. Fresh-staging all-source compilation and
the strict retail checksum gate pass with 30-second bounds; shader still links
its retail object.

## Shared view-frustum plane construction (2026-09-07)

`updateVisibleGeometry` now matches all 223 retail instructions (892 bytes)
in EN, EN revision 1, JP, PAL, and PAL revision 1. The same GC/1.3 source
raises each shader unit from 99.62504% to 99.85385%, with 140/145 functions
exact instead of 139/145. The five retail instruction bodies are identical;
each input DOL was verified against its configured SHA-1.

The private `appendViewFrustumPlane` helper writes the three normal fields,
computes the existing negative camera-position dot product in the same order,
stores the distance, and returns the next plane index. The caller builds its
five planes in the original order and passes the resulting count to the
corner-index update. The helper uses the canonical `FrustumPlane` fields,
removing the flattened `pw[n * 5]` access across separate records.

Advancing a narrow counter at the distance store recovers retail's `li`/`mulli`
index formation and indexed stores. A full-width counter instead remains live
across transformation calls and needs an extra saved register. Both byte and
halfword counter probes reproduce the target; `u8` fits the five-entry count,
but matching does not uniquely establish its original typedef. The helper name
and boundary are reconstructed source structure, not recovered original names.

Only this function's bytes change, growing from 824 to the retail 892 bytes.
All 144 other function bodies, allocated non-text bytes, and non-text named
symbol layouts are unchanged in all versions. Subsequent text symbols move by
68 bytes. Relocations retain their function-relative locations outside the
changed function and their resolved destinations throughout the object,
including data jump tables. No globals, sections, compiler flags, or TU
boundaries change. The shader TU remains `NonMatching` because five other
functions still differ; regional progress manifests are not promoted to exact.

## Map-cell neighbourhood ID view (2026-09-07)

`mapLoadUnloadObjects` reads three contiguous signed halfwords at byte offset
`0x594` in each of five map-cell layers. With the proven twelve-byte
`MapCellEntry`, that is entry 119, or cell `(7, 7)` in the sixteen-wide grid.
The halfwords are the owning map ID and its two adjacent map IDs.

`MapCellEntry` now exposes their existing named fields and a three-element
`mapIds` array as union views, with size and offset assertions. The loader uses
`MapCellEntry**`, the canonical layer-table offset, and the cell's array view.
Its existing eight-entry unique-ID buffer and signed count retain their storage
and traversal. The variable-length object walk keeps its proven integer-address
form; byte-pointer alternatives regress code generation.

The formatted source and header reproduce the complete pre-change shader
object byte-for-byte. All-source compilation, the strict retail checksum,
formatting, and the data audit pass. This recovers structure without changing
the retained 139/145 exact functions or the TU's 99.62221% score.


## Frustum aspect temporary reuse (2026-09-07)

`updateVisibleGeometry` now reuses the tangent-ratio temporary for the
aspect-scaled squared ratio before the square root and arctangent. This recovers
the retail `f1` constant load, `f0` multiplication result, and fused multiply-add
operands. The arithmetic and evaluation order are unchanged.

Only three instruction words change, at function offsets `0x178`, `0x17C`, and
`0x180`. All other function bytes, non-text section contents, and named symbol
layouts remain identical. Thirty-one text relocations receive renumbered
anonymous literal labels; their locations, types, addends, destination sections,
and destination offsets are unchanged. All forty literal-consumer sequences
and the complete data audit pass.

The function improves from 87.2018% to 87.3139%, and the TU reaches 99.62423%
with 139/145 functions exact. The unresolved frustum differences concern plane
indexing and its associated saved registers and frame layout. Formatting
preserves the selected probe object byte-for-byte. Both thirty-second-bounded
build gates pass; the TU remains `NonMatching` and the strict link uses retail.

## Exact block release through allocator replay (2026-09-15)

`unloadMap` now matches all 154 retail instructions. Its shared inline
`mapReleaseBlockReference` keeps the same loops and expressions; declaring the
scroll slot, shader byte offset, layer cursor, and shader pointer in that order
recovers the remaining shader-pointer/byte-offset register swap. The other locals
retain their order. This establishes an exact source spelling, not the original
local names or declaration order.

The macOS LLDB capture reproduces the ordinary full object byte-for-byte, aligns
all 154 instructions, and replays all 54 physical register choices with no
high-degree removals. Projecting retail operands onto the baseline graph found
that virtual registers 46 and 48 could exchange their physical colors without
interference. Replaying declaration permutations identified the retained order;
the actual compilation then confirmed the prediction. The final trace can be
regenerated with:

```sh
python3 tools/tricky_backend_trace.py --unit main/main/shader \
  --function unloadMap --graph --output build/shader_unload_trace
```

Only two function bodies change: ten bytes in `unloadMap`, and seven bytes in
`doPendingMapLoads`. Their sizes are unchanged. The latter improves from
98.79135% to 98.81043%. All other 143 function bodies, allocated non-text bytes,
named symbol layouts, and complete relocation records are unchanged. Formatting
preserves the entire compiled object.

Four functions still prevent a source-matching TU:

| Function | Instruction fuzzy similarity | Remaining evidence |
| --- | ---: | --- |
| `mapLoadUnloadObjects` | 98.58787% | Same 478-instruction mnemonic stream, but address formation, cursor lifetimes, and register choices differ. Retail register projection rejects the current value partition. |
| `doPendingMapLoads` | 100% (register-exact against the retail listing) | Per-layer tables and the saved-block records are indexed by counter, as in Dinosaur Planet's `mapUpdateStreaming`; see below. |
| `mapFillCellEntry` | 99.32447% | Coordinate-load order, initial slot-base/cursor copies, and register allocation differ. Declaration movement alone did not resolve them. |
| `renderObjects` | 99.82456% | Two address additions have commuted operands. Native indexed stores change instruction selection; the tested alternatives were not retained. |

The source remains `NonMatching`. `ninja all_source` and the strict EN checksum
target pass with 30-second bounds. The data audit checks all 40,668 assigned
bytes, 120 native symbol layouts, 40 data relocations, 151 direct retail pool
loads, and the three anonymous zero-color templates. Its six focused regression
checks pass. The original and matching DOLs retain SHA-1
`e750e8e894707a52446118a4b84f1b58b677b269`; that integration build still links the
retail shader object. Only the EN DOL is present in this checkout, so this pass
makes no new regional completion claims.

## Exact object-render queue stores (2026-09-17)

`renderObjects` now indexes a `u32` view of the queue's `type` field, with
the field base expressed by `offsetof(LightSortEntry, type)` and the stride
by `sizeof(LightSortEntry) / sizeof(u32)`. Both object-shadow paths retain
the cached queue base, store their existing kind, and increment the same
count. This spelling reproduces retail's base-first address additions without
moving the queue definitions or changing their storage.

The function improves from 99.82456% to **100%**, retaining all 456 bytes.
Only four instruction bytes change, in the two commuted additions. All other
144 function bodies, complete relocation records, symbol layouts, and allocated
non-text sections remain byte-identical. The TU reaches 142/145 exact functions
and 99.85951% fuzzy match. It remains `NonMatching` because the map load/unload,
pending-load, and cell-entry functions are still inexact.

The same source gives a 100% objdiff function match in EN rev1, JP, PAL, and
PAL rev1 after each input DOL passes its configured hash check. These are
function matches rather than whole-object completion claims, so regional
matching manifests do not change. The data audit passes all 40,668 assigned
bytes, 120 symbol layouts, 40 data relocations, and 151 direct retail pool loads.
The full source build and strict EN retail checksum pass. Formatting is verified
separately against the complete raw object; the strict link still uses this
TU's retail object.

### Loaded-object bitmap compound updates (2026-09-17)

`mapLoadUnloadObjects` now uses compound OR assignments at its two loaded-object
bitmap updates. This preserves the existing signed-byte lvalue and truncation,
while evaluating that lvalue once. Both instructions change from
`or r0,r4,r0` to the retail `or r0,r0,r4`. The preceding clear and all surrounding
instructions remain unchanged. An unsigned-byte compound lvalue regressed the
match; reversing the explicit RHS operands alone was byte-neutral.

EN function fuzzy matching improves from **98.58787% to 98.62971%**; the complete
TU improves from **99.85951% to 99.86113%**. This is a two-instruction improvement,
not a newly exact function. All five configured originals were hash-verified,
and EN, JP, PAL, EN rev1 and PAL rev1 show the same function-score improvement.
For each region the before/after objects differ in exactly four text bytes,
all in this function. The other 144 function bodies, allocated data, named-symbol
layouts and relocation destinations are unchanged. Anonymous literal labels are
renumbered by the semantic source edit; their sections, offsets and bytes agree.
The retail data audit also passes its 40,668 bytes, 120 native symbol layouts,
40 data relocations and 151 direct pool loads.

The investigation independently recovered the previously unimplemented GC/1.3
`PCodeUtilities.c` address emitter at `0x004e8f90` in the sibling `mwcc` project
(`src/versions/GC_1_3/AddressEmit.c`). Its 219-byte body passed 4,660 comparisons
with the original x86 routine in a hardened offline Unicorn sandbox. That model
clarifies MR/ADDI/symbolic-LI emission, but does not yet reconstruct the frontend
compound-assignment lowering responsible for this OR-order difference. No causal
proof or Win32 byte-match claim is made for that connection. The new compiler
model and fixture remain in that workspace alongside its pre-existing GC/1.3 work.

### Typed ROM-list group boundaries (2026-09-17)

The two ordinary-object traversal limits in `mapLoadUnloadObjects` read
`MapRomListIndex.groupsStart`, at pool offset `0x4208 + 0x88 = 0x4290`, with
0x8C-byte index stride. The index builder sets this boundary to the minimum of
the curve offset and all present group offsets, or the page size if none exist.
It is distinct from `objectsSize`, which only excludes the curve suffix.

`MapRomListBuffers` is an address view of the existing separate 120-entry index
array, not a new storage definition. All five symbol configurations confirm its
0x4208 pool origin and 0x83A8 end at the loaded-page array. Typed field accesses
correct the two ADD operand orders, improving the function from **98.62971% to
98.67155%** in all five versions. Exactly four text bytes change; the other 144
function bodies, all allocated data, named-symbol layouts and relocation
destinations remain unchanged. The hosted-page bitmap accesses now also use
`MapRomListPage.loadedObjectBits`; this cleanup preserves the generated object.
The complete TU improves from **99.86113% to 99.86275%** and remains NonMatching.

### Copy-coalescing boundary behind the cell-entry plateau (2026-09-17)

The sibling compiler project now contains an independent reconstruction of
GC/1.3 `InterferenceGraph.c`'s complete copy-coalescing routine, 1,098 bytes at
`0x005794f0` through `0x00579939`. Its native model agrees with the original in
1,504 offline sandbox cases spanning five register classes, interval boundaries,
interference, chained merges, two-block traversal, and operand rewriting.
Allocation, instruction unlinking, and assertions are stubbed dependencies;
Win32 binary matching remains unmeasured.

`tricky_backend_graph.py` now captures the actual eligibility interval and
post-coalescing parent map. For unchanged `mapFillCellEntry`, the physical limit
is 32, the inclusive merge interval is 46–144, and the protected GPR is 1.
The retained `slots` local is virtual register 42, the first inline cursor is
64, and its address temporary is 70. Thus 70 can merge into 64, but 42 cannot
merge with either. The resulting ADDI targets the cursor and copies to the
retained pointer, opposite the retail sequence. Reversing the C assignments
still yields the same raw object after value numbering and coalescing.

Both ordinary and instrumented baseline objects have SHA-256
`708f9fe319e600397a3fc57eb39d6fd18aaa92f3697c1740f13c421eca66036f`.
The complete graph simplification and color replay agree with the captured
compiler. Rejected probes include pointer aggregates, coordinate aliases,
shared lookup helpers, and reusing the object local between load phases.
Moving the complete BSS definition block earlier also disturbed its symbol
layout and was discarded. These findings improve diagnosis, not the shader
match percentage: all probes were restored, leaving 142/145 exact functions
and the existing 99.86275% TU match intact.

### Object metadata and shared BSS selection (2026-09-17)

The sibling compiler reconstruction now includes the 117-byte GC/1.3 object-name
lookup at `0x004fcd60` through `0x004fcdd4` (`ObjectName.c`). It follows aliases,
selects direct names or kind-specific cached names, and dispatches lazy builders.
Its native model agrees with 2,376 original-routine cases, each making two calls
to check caching. Name builders and assertions are stubbed; this is functional
agreement, not a Win32 binary match. The section-category predicate was separately
checked in 8,360 cases against the original without dependency stubs.

The backend graph capture now records symbolic operands' object kind, name,
flags and category, plus variable context and cached-name fields. This read-only
capture rules out the proposed exclusion-flag explanation for the pending-load
slot and table accesses: with their definitions after the functions, these
objects have flags zero, category `0x103`, and a null context pointer.

Moving the complete BSS definition group before the functions and using native
array accesses replaces those operands with the compiler-generated `...bss.0`
base (category `0x102`). However, storage follows first-use order in this probe,
changing the proven global offsets. The pending-load function also regresses
from 98.81043% to 97.18829%. Keeping the definitions late with the same native
accesses regresses further to 94.36896%. Both probes were discarded. Symbolic
relocation normalization can conceal the changed global offsets, so a shared
base alone is insufficient evidence of a correct source reconstruction.

Ordinary and instrumented objects agree byte-for-byte for all three captures:
the unchanged baseline, native accesses with late definitions, and native
accesses with early definitions. No shader source change is retained from this
experiment; the current TU remains 99.86275% with 142/145 exact functions.

### Addressing-mode exclusion ruled out for the BSS arrays (2026-09-17)

The sibling compiler project now reconstructs the ObjGen addressing-mode
classifier (`0x004b3ff0`, 352 bytes), its relative-mode predicate (`0x004b3fc0`,
35 bytes), and its alias-list lookup (`0x0042fb20`, 29 bytes). The classifier
passes 7,112 original/native comparisons both with a stubbed alias dependency
and with the recovered lookup. The lookup separately passes 4,196 comparisons,
including duplicate IDs and high argument bits. Preparation, allocation and
assertions remain stubbed in classifier tests; Win32 binary matching is unmeasured.

`tricky_backend_graph.py` now records signed object section IDs and the ordered
section/alias lists. In the ordinary baseline, `gLightmapDrawQueue` is section 9,
data mode 1. In the native-array-access probe, `gShaderRomListSlots`,
`gMapBlockCellEntryTables`, `gMapBlockLayerTables`, `gMapRomListIndexes` and
`gLoadedRomListPages` are also section 9, mode 1, with null shared-context
pointers. Mode 1 does not trigger the relative-mode exclusion (modes 2 and 6–8).
Small-data globals, including the map origins and slot count, use section 10,
mode 6. Thus the addressing-mode predicate does not explain the missing shared
context for these BSS arrays; storage visibility/allocation remains the lead.

The baseline and native-probe captures each preserve their ordinary object's
raw hash. The native probe remains rejected and was restored. Shader matching
stays 99.86275% with 142/145 exact functions.

### Section-record ownership and private-storage probes (2026-09-17)

The recovered section-record query now guides a read-only trace of records
selected by each captured variable's cached name. The trace records the owner,
byte size, offset, category, and owner's shared-base descriptor. It
preserves list order and both category variants of a name.

In baseline `doPendingMapLoads`, shared contexts are globally enabled, but
`gLightmapDrawQueue` has a category-0x103 record with flags 0x10, offset zero,
byte size zero, and an owner with no shared-base descriptor. The same
owner appears for the captured external map globals. The trace scans 228
records. This establishes a concrete missing owner base at this stage, beyond
the previously excluded flag and addressing-mode explanations.

No direct source consumers of the eighteen named BSS objects occur outside
shader.c. A private-storage experiment temporarily removed their public
extern declarations and made the complete early definition group static.
This still assigned storage by first use: the queue moved from offset zero
to 0x4640 and the ROM-list indexes from 0x4208 to 0x1c. Native pending-load
accesses remained 97.18829%; private linkage did not recover the retail layout.
All private-storage source/header changes were restored.

A typed eight-element slot-array view was also tested with cached and live
slot counts, using either the cached pool base or the queue's address. All
four variants regressed the pending-load function (98.23919%, 98.02290%,
94.283714%, and 94.59542%, respectively) and were discarded. No shader source
change is retained from these probes.

The early-definition/native-access trace scans 230 records and confirms the
positive case: `...bss.0` has category 0x102, flags zero, a nonnull owner-base
descriptor, and an enabled base pointing back to that generated symbol. Both
baseline and early-definition captures produce byte-identical ordinary and
instrumented objects. This validates the traced ownership transition; it does
not make the rejected early-definition layout correct.

### Corrected section-record size interpretation (2026-09-17)

Recovering the compiler's allocation creator at 0x004d07c0 establishes that
record +0x10 is the requested byte size, not a storage pointer. It returns
the section record itself and replaces its owner with the selected area.
The earlier zero/nonzero checks could not establish the field's type. The
trace now labels this word `size`; older captures' `storage` value is the
same word and must be read as a size. The baseline record's size is zero
and its owner base is null; the missing-base observation remains valid.

The creator passes 6,336 original/native cases, using the actual category
predicate and recovered native record lookup. Canonical allocation/section
and area/owner types are now unified in the sibling compiler project. This
is a correction to the model and trace terminology, not a shader match gain.

### `doPendingMapLoads` register allocation (2026-09-24)

The instruction stream already matched; 56 register operands differed. An
LLDB capture of GC/1.3's allocator (coordinator 0x506CD0, simplify 0x507070,
colour selection 0x506F50, copy coalescing 0x5794F0) replays exactly: K = 29,
simplify scans vregs upward, spill choice is the lowest cost/degree with ties to
the higher vreg, and colours take the lowest free register after claiming saved
registers from r31 downward.

The replay showed retail's top saved band (`cnt`, the layer-table and
cell-state bases, the section base, the record base) needs extra permanent
degree on the slot and table-base webs. Permanent degree comes from
coalesced copies: the coalescer keeps the child's interference in its
neighbours' degree counts, merges only inside the compiler-temporary window
(never two named locals), and roots the lower vreg. Retail's extra degree
therefore comes from compiler induction temporaries, not named cursor locals.

Dinosaur Planet's `mapUpdateStreaming` supplies that shape. Indexing
`gMapBlockCellEntryTables`, `gMapBlockLayerTables` and
`gMapBlockCellStateTables` by `layer` in all three loops, indexing
`recs[cnt]` / `recs[i]` directly, and counting the rom-list retirement loop
with `i` (DP's `var_s3`) reproduces every retail register. The function is
register-identical to the retail listing. All other function bytes and every
data section stay unchanged, apart from renumbered anonymous `@N` labels.

### Source-linked data completion (2026-09-24)

The deferred-inline profile left three `.sdata2` words in the wrong order:
the source emitted `-250.0f`, `0.4f`, `0.0625f` at offsets `0x74..0x7c`, while
retail stores the named indirect-matrix scale first. A TU-owned static scale,
read through a local pointer in the indirect pass, retains a single copy. Its
address-only reference in the adjacent bounds function emits no instructions
but creates the scale before the depth-threshold literal. The source pool now
matches every assigned byte and `gTexIndMtxScale` occupies offset `0x74`.

The retail link also retains `sShaderObjLoadMessages`,
`gLightmapDeferredObjects`, and `gMapCellRenderState` despite no direct
relocations to their symbols. The EN `force_active` list now retains them.
With `main/shader.c` selected as `MatchingFor("GSAE01")`, both the strict
build checksum and `verify_source_link.py GSAE01 main/shader.c` produce retail
SHA-1 `e750e8e894707a52446118a4b84f1b58b677b269`.
