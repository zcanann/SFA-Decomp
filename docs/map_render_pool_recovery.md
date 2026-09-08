# Map-rendering TU and pool recovery (2026-09-07)

The shared map-rendering `.sdata2` pool is now exact. The five artificial
fragments `shader`, `lightmap`, `lightmap_initmapblocks`, `lightmap_draw`, and
`tex_dolphin` have been reunited in `src/main/shader.c`, in retail function order.
All 40,656 assigned data bytes match. The common GC/1.3 invocation produces
139/145 exact functions and a 99.62504% instruction fuzzy score; the TU remains
`NonMatching` because six functions still differ.

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

Two zero fog-color records at `.sbss2` `0x803E8444` and `0x803E8448` remain retail
externs (`gTexShaderFogColor` and `gTexLightmapFogColor`). Their declaration and
emission order has not been recovered. They are not claimed by this change;
forcing either record into `.sdata2` or `.sbss` would misrepresent its storage.

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
