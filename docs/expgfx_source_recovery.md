# Expgfx Source Recovery

## Object APIs and independent effect tables (2026-10-06)

The effect helpers now accept `GameObject*` sources and `PartFxSpawnParams*`
origins. The latter are 0x18-byte rotation/scale/position packets, not full
objects. In particular, `objfx_spawnLightPulse`'s former `light` argument is a
spawn transform; `objDoHitParticleFx` has a separate `ModelLightStruct*` for
its actual light. Trail bursts instead take a three-float velocity, as
established by Effect20's `0x7B7` case. Source pools, table entries, cleanup,
rendering and simulation now retain `GameObject*` throughout. The fake
position-only object overlay and intermediate animation-prefix casts are gone.

The public Expgfx interface and descriptor share exact callback types. The
spawn slot takes `EffectSpawnConfig*`; the frame-state query returns `int`.
The update implementation retains two unused arguments to agree with
`Obj_UpdateAllObjects`'s four-argument call and the predecessor's
`dll_13_func_C18` contract. `gExpgfxDescriptor` replaces the untyped callback
array, with the generic resource cast confined to `modelEngine.c`.

Three burst helpers previously read twelve tables through byte offsets
`0x48` through `0x104` from the 30-byte `gObjFxCrystalSparkleTbl`. Those
accesses crossed unrelated objects and depended on their linked placement.
The constants actually belonged to a fabricated 0xE0-byte aggregate following
the color and pulse-variant tables. They are now independent definitions:
a five-element hit-pulse count table, then four arrays for each of the box,
arced and directional bursts. Each group has nine effect parameters, eight
spawn IDs, eight argument-2 values and eight argument-0 values. The two-byte
alignment gaps after the nine-element arrays are compiler padding.

Independent definitions let MWCC generate its shared `...rodata.0` base
naturally, preserving every retail instruction and table address. No explicit
section placement, enclosing synthetic record or out-of-bounds access is
needed. The former crystal-sparkle table is actually ten RGB triplets used
by `objDoParticleFx`; it is now `gObjFxParticleLightColors`, with typed channel
accesses. All five symbol configs describe the recovered array boundaries.

The stricter helper contracts also recover complete spawn packets in Baddie,
GC robot patrol, Landed Arwing, DB stealerworm, Lightfoot and DR EarthCall.
BombPlant's separate `lightPosition` and `hitPosition` locals are one packet;
DR BarrelGen's partial header and following path-position local are likewise
one packet. Their complete transforms preserve the retail stack locations.
The duplicate packet typedefs and redundant argument casts are removed.

CC Lightfoot has a distinct, apparent retail bug: the hit query, positional
emitter and SRT-based hit-particle helper all receive `r1 + 0x14`. The query
fills three floats there, but the last helper passes that same address to
partfx, whose source-copy path reads the SRT position at offsets 0x0C..0x14.
The narrow cast records that mismatch; this recovery neither shifts the
argument nor enlarges the local to conceal it.

Validation covers all five versions: every active game TU remains 100% in
the full objdiff inventory, `all_source` succeeds, and each fully source-linked
DOL equals its hash-verified original. The two pre-existing library report
artifacts (`__exception` and `sal_volume`) are unchanged. Every source object's
section contents, allocated-section metadata, symbol addresses and resolved
relocations are preserved, accounting explicitly for the renamed symbols,
new independent table boundaries and MWCC's generated rodata-base symbol.
The core object's compiler metadata adds only records for those new symbols.
Formatting is committed separately and preserves every raw source-object hash.

## Source-table identity and lifecycle (2026-10-06)

`ExpgfxTableEntry` now records an `ObjAnimComponent* sourceObject` and a
`GameObject* sourceParent`, alongside its resource pointer. These replace the
integer `sourceId` and `attachedTableKey`. In `expgfx_addremove`, the copy-source
behavior takes the source's world position/rotation/scale, retains its parent,
then clears the direct source pointer. The update loop later uses that parent's
transform-space index when converting the copied position. Source and parent
are therefore distinct parts of the table key, not interchangeable handles.

Dinosaur Planet's `UnkBss190Struct` likewise contains two `Object*` fields and a
`Texture*`; `dll_13_func_2060` interns the same three pointers. Its spawn path
takes the second object from the copied source's `parent`. Foxhollow widens the
corresponding SFA table keys to `uintptr_t`. SFA's own stores and consumers
establish the roles and preserve the asserted 0x10-byte target record.

Slot selection, table insertion, source cleanup and cleanup wrappers now accept
pointers directly. Pool-source walks, stores and clears use the existing typed
pointer array. Table lookups use ordinary indexing; the final added-slot global
is an `ExpgfxSlot*`. Texture pointers no longer pass through `u32` in table
insertion or the update loop. The separate update API's old `sourceId` parameter
is renamed `frameCount`: `Obj_UpdateAllObjects` passes `framesThisStep` there, and the
current update loop does not consume the parameter. Its integer ABI is retained.

`expgfxRemove` retains a cached pointer to the first resource field and a narrow
byte-stride access based on `sizeof(ExpgfxTableEntry)`. Using a table-base local
or recovering the enclosing record with `offsetof` adds three MWCC instructions.
The retained field-base form preserves target code while correctly walking
pointer-bearing records on a native host. The duplicate resource predicate in
bulk removal and the one-element local arrays remain unchanged.

`tools/test_expgfx_sources.py` extracts twelve production functions and the
canonical object, slot and table records. Its 3,936 scenarios pass at `-O0` and
`-O2` with ASan/UBSan and pointers above 4 GiB. They cover every table entry and
pool/slot position, all three pointer keys, table capacity and refcount overflow,
the reserved final automatic-allocation pool, resource-release/flush flags,
inactive removal, all source-free wrappers, and all three bulk-reset contracts.
Texture release and cache flush are spies. Slot fixtures encode the retail table
index explicitly; these tests do not exercise host bitfield serialization,
particle simulation or GPU rendering. The existing queue and slot-layout tests
also pass. Five negative controls reject truncated source pointers, omitted
source-key comparisons, fixed 16-byte native strides, 32-bit pool-pointer clears
and automatic allocation of the final pool.

Expgfx remains 46/46 functions and 100% code/data in all five versions. Every
source object's raw hash is unchanged, including Expgfx: symbol tables,
relocations and all sections are identical. Full objdiff inventories introduce
no new exceptions, all source builds pass, and all five source-linked DOLs match
their verified originals byte for byte.

## Pointer-preserving render-queue boundary (2026-10-06)

The slot-pool base table now stores `void*`, with pointer-width allocation and
walks. `renderParticlesBody` passes the pool pointer directly to the shared
render queue; `drawGlow` receives it as a pointer. The queued object path calls
`expgfx_renderSourcePools(GameObject*, int)`, whose source-table walk retains
the existing `ObjAnimComponent*` entries. Both render paths preserve their
pool filtering, frustum tests and ordering.

The cache update retains its long-lived mask-table byte offset. Directly
indexing the final pool write by `activePool` extends that local's lifetime
through the large slot loop and changes MWCC's spills. Converting the offset
to an index adds an instruction. The retained narrow pointer-table access
scales the mask byte offset by the pointer/mask element-size ratio: one on the
target, two on a 64-bit host. This preserves the exact retail instruction
stream without assuming that native pointers are four bytes.

Foxhollow's pool table and render payloads likewise use pointer-width storage.
This recovery is limited to the table and queue/render boundary; other effect
source-ID APIs and simulation accesses still contain 32-bit assumptions.
`tools/test_render_queue.py` executes both production pool-routing functions
through the production queue and dispatch loop with native pointers. Draw,
camera and frustum services are fixtures; it does not claim complete native
effect rendering. The existing slot-layout tests also pass.

All 46 functions and 6,660 data bytes are exact in all five versions. Section
contents, named symbol offsets and resolved relocations match the previous
objects, and each full source build and strict retail DOL checksum passes.

## Native storage and current EN match (2026-09-07)

Expgfx now reaches **100% match**, with **all 46 functions and all 6,660 data
bytes exact**. The unit is `MatchingFor("GSAE01")`, and the source-linked DOL passes
the strict retail checksum.

| Measure | Previous | Current |
| --- | ---: | ---: |
| Unit fuzzy match | 99.88683% | 100% |
| Exact functions | 44 / 46 | 46 / 46 |
| `expgfxGetSlot` | 95.89899% | 100% |
| `expgfx_updateActivePools` | 99.88024% | 100% |
| Update instructions | 2,311 | 2,313 |
| Exact data bytes | 6,660 | 6,660 |

### Emission and ownership

The Dinosaur Planet reference's `src/dlls/engine/13_expgfx/expgfx.c` uses
independent pool arrays and puts its constructor before its gameplay functions.
That source lineage, the reverse retail function order, and the successful
save-game recovery support GC/1.3 deferred emission here. The unit uses the
existing `cflags_dll_noopt_noautoinline_deferred` profile: the compiler remains
GC/1.3, with `nopeephole,noschedule` and `noauto`. There is no TU split or
per-function compiler setting.

Ordinary function definitions and tentative BSS definitions are ordered for
MWCC's reverse deferred emission. Complete definitions are available at code
generation, allowing MWCC to synthesize its shared BSS base. The two synthetic
`ExpgfxRuntimeDataLayout` and `ExpgfxStaticDataLayout` overlays and their offset
macros are removed.

The 0x1340-byte BSS span now has these independent definitions:

| Offset | Definition | Size |
| --- | --- | ---: |
| 0x0000 | resource entries | 0x200 |
| 0x0200 | pool bounds | 0x780 |
| 0x0980 | effect table entries | 0x500 |
| 0x0E80 | pool source modes | 0x50 |
| 0x0ED0 | tracked source pointers | 0x140 |
| 0x1010 | two source-frame masks | 0x10 |
| 0x1020 | plane-offset set IDs | 0x50 |
| 0x1070 | active counts | 0x50 |
| 0x10C0 | active-slot masks | 0x140 |
| 0x1200 | slot-pool bases | 0x140 |

The old crystal-burst struct incorrectly combined four amplitude scalars with
independent quad templates. Separate amplitude and template arrays recover
MWCC's shared data base in the quad initializer and update. Each used template
has four vertices, as established by its consumers. The unreferenced repeated
template bytes remain opaque. Likewise, the frame-flag array has 80 entries;
the following 32 unused bytes are retained separately. The predecessor's two
triangle records explain that latter byte pattern without inventing an EN
consumer.

Diagnostic strings are literals at their call sites. Deferred generation and
string reuse reproduce their retail order and preserve all initialized bytes.
The active symbol config records the recovered array boundaries; source paths
and TU section boundaries remain unchanged.

### Functions

`expgfxGetSlot` uses ordinary indexed searches over the native arrays. MWCC
performs the retail unrolling and emits all 198 instructions exactly. The
manual five-way search, cached mask snapshots, and extra pointer cursors are
gone. Both free-slot searches share their loop counter.

`expgfx_resetAllPools` also uses indexed arrays. Its inline resource cleanup
indexes entries instead of incrementing the entry argument. That distinction
preserves the retail register allocation and all 116 instructions.

The update keeps the active pool index separate from the texture/resource
address. A named byte offset is shared by the active-mask lookup and final
pool writeback. The next-pool scan has its own signed-byte cursor, separate
from the cache writeback buffer. All arithmetic, branches, instruction counts,
register operands, and stack displacements agree.

The earlier trail-vector recovery, narrowed ambient-color products, and direct
`s16` rotation-speed conversions are retained. The three rotation products
still require the direct floating-point-to-halfword spelling; an intermediate
`int` cast introduces sign-extension instructions.

A full source-link audit exposed a pre-existing false exact report in
`objfx_spawnFrameTimedHitPulse`: objdiff normalized two reversed SDA load
relocations. A direct truth test of the floating-point frame timer recovers
retail's timer-first, zero-second load order. The linked-byte comparison
verifies this correction.

### Completing the stack layout

Native array recovery initially left only 18 displacement bytes different in
the update, covering eight spilled values. The final blocker was the
`expgfxRemove` API: its first argument is a pool buffer pointer, but the
reconstruction declared it as `u32`. Its body immediately used the value as
the base of a slot address. All direct consumers are in this TU.

With the integer prototype, separating the scan cursor and writeback buffer
introduced a duplicate spill store. Naming the common pool byte offset moved
that value into the correct slot, but could not resolve the buffer's generated
temporary. Declaring the buffer argument as `void*` eliminates the cast at the
update call and allows the separate buffer local to retain the required stack
home. The integer-backed engine pool table is cast only at its call boundary;
the remover computes the slot address through a byte pointer.

Keeping the recovered scalar declarations in their codegen-proven order then
reproduces all eight retail stack locations, from the pool byte offset at
316(r1) through the active-mask pointer at 344(r1). Only the update's text
changes from the preceding recovery; every other function, symbol offset,
and non-text section remains byte-identical. No forced stack record,
volatile storage, or compiler override is used.

### Validation

- `ninja all_source` and the normal matching build pass, including the strict
  retail checksum with Expgfx linked from source. This verifies the new BSS
  offsets, initialized data, anonymous literals, relocations, and all functions.
- All allocated non-text section bytes, sizes, and alignments are preserved.
  Named array offsets and sizes are checked independently of zero-filled BSS
  section equality. Objdiff reports all 6,660 data bytes exact.
- The two slot-layout tests pass. They exercise the production quad-write
  sequence over 100 random slots and verify metadata and simulation bytes are
  preserved. The harness now stops at the native global declarations instead
  of the removed overlay macro.
- Formatting is a separate change, verified to preserve the complete object.
  TU and owning-header `clang-format --dry-run --Werror` checks pass.

Useful commands:

```sh
python3 configure.py --matching
# Each Ninja invocation must have a 30-second timeout.
ninja all_source
ninja
python3 tools/unitfuzzy.py dlls/engine/10_expgfx/expgfx.c
python3 -m unittest discover -s tools -p test_expgfx_slot_layout.py
```

## Spawn and Slot Contract (2026-09-06)

The EN `expgfx_addremove` entry at `8009F2CC` consumes the same 0x64-byte
`EffectSpawnConfig` produced by partfx and Effect1 through Effect20. The duplicate
`ExpgfxSpawnConfig`, byte-pair color overlay, and texture-word overlay are removed.
The consumer now uses the canonical scalar fields, including the unsigned
halfword loads for the color words at 0x58, 0x5A, and 0x5C.

The spawn word at +0x04 is narrowed into the slot halfword at +0x36. The update
function passes that halfword to the partfx spawn callback when triggering an
impact effect. It is not vertex padding: `quadVertex3Pad06` is now
`impactEffectId` in the canonical config and all 21 producer TUs that used that
name. The unrelated legacy `unk04` view is not reinterpreted in this pass.

Each 0xA0-byte slot begins with four 0x10-byte vertices. The recovered union
exposes that array and its metadata view without casting the entire slot to an
unrelated vertex type:

| Slot Offset | Metadata | Vertex Storage |
| --- | --- | --- |
| 0x06 | remaining lifetime | vertex 0 unused halfword |
| 0x0F | initial alpha | vertex 0 alpha |
| 0x16 | initial lifetime | vertex 1 unused halfword |
| 0x1F | start red | vertex 1 alpha |
| 0x26 | sequence ID | vertex 2 unused halfword |
| 0x2F | start green | vertex 2 alpha |
| 0x36 | impact effect ID | vertex 3 unused halfword |
| 0x3F | start blue | vertex 3 alpha |

The RGB bytes at 0x8C-0x8E are the end color. Remaining lifetime starts at the
configured duration and decreases; the update computes
`end + (start - end) * remaining / duration`. `drawGlow` takes color from vertex
0 for all four vertices, so the other three alpha bytes are available for these
endpoints. Geometry initialization writes only XYZ and ST, preserving metadata.

The update's local rotation/scale/translation record is the existing 0x18-byte
`MatrixTransform`, not a separate Expgfx-specific transform type.
