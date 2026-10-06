# Model-effects manager (modgfx, engine DLL 11)

GC/1.3, updated 2026-10-06. All 33 functions (14,928 EN text bytes) and
all 1,260 assigned EN data bytes match. The complete unit also matches EN rev1,
JP, PAL and PAL rev1. Its compiler and optimization profile are unchanged.

## Shared command, object and geometry contracts

The manager and 80 effect-producer TUs now use one `ModgfxCommand` record.
The old `GfxCmd`, `ModgfxPendingSpawn` and `ModgfxVertexGroupCmd` described
competing views of the same 0x18-byte storage. Its first word contains operation
flags, its three floats hold operation-specific values, and its pointer at
0x10 addresses signed 16-bit vertex indices. The 0x14 halfword is a vertex
count, effect/sound ID or branch parameter according to those flags; the byte
at 0x16 selects one of the seven effect stages. Names such as `tex`, `layer`
and `modelOrResource` obscured this interpreter contract.

`ModgfxSpawnPacket` embeds the actual 0x60-byte `ModgfxSpawnContext` followed
by its 32-command workspace. StaffCollision uses that same context with its
separate command workspace. This removes the duplicate layout, the integer
`ctx` object alias and the address-named field aliases. The context and live
0x140-byte `ModgfxEffectState` hold `GameObject*` source objects. The effect's
saved transform is a `PartFxSpawnParams` record at 0x0C, which its nested
particle and effect spawns actually consume. The old `initialDelayFrames`
name was stronger than the recovered behavior: that copied argument is now
`variant`, since the retail manager has no recovered reader of the field.

`spawnSequence` receives a `PartFxSpawnParams*`, not a source object: both
callers pass that packet, and the fallback path reads its position triple.
The actual source object comes from `beginSequence`. Public callbacks now
carry these types, `ModgfxEffectVertex*` geometry, signed triangle-index
arrays and `Texture*` resources. Source release/render callbacks use
`GameObject*`; the seven object consumers with redundant `void*` casts now
pass their objects directly.

The active table contains `ModgfxEffectState*`. Rendering and vertex updates
use the shared `LightmapVertex` and `LightmapTriangle` definitions. Allocation
still partitions the one evidenced variable-size block; raw color writes,
vertex-coordinate stores, source-object reads and the InvHit collision-object
lookup now use their canonical fields. Runtime records and callback slots
retain their retail sizes and offsets.

The descriptor embeds `ModgfxInterface`, uses function designators directly,
and retains its final unexplained word. This replaces the fabricated array of
integer-cast function addresses and its `u64` alignment union. The descriptor's
natural type alignment is four; MWCC still emits the same eight-aligned `.data`
section and identical link addresses. Its per-symbol alignment entry in the
non-loaded `.comment` section changes from eight to four. That single metadata
byte is audited separately; executable/data bytes and relocations are unchanged.

Dinosaur Planet revision `c4340802dc9f62e1181d00cc34c3175fca6ca4be`,
`src/dlls/engine/14_modgfx/modgfx.c` and its interface header corroborate the
source-object field at 0x04, typed effect table, geometry/texture pointers and
object-based release/render callbacks. They are lineage evidence, not recovered
SFA source. Foxhollow's corresponding unit has no post-import runtime-fix
history; its inherited layouts were checked but do not establish these types.

## Rendering and copying

`modgfx_renderEffects` uses integer masks for the two texture-frame traversal
limits. A byte cast produces the same frame selection but a different register
assignment in MWCC's unrolled walks.

`modgfx_spawnEffect` indexes the three geometry buffers directly. Its local
copy cursor keeps the buffer/command index, triangle input pointer, and shared
vertex/sequence element index together. Triangle input and output cursors
advance in retail order. The vertex loop derives its input position from the
element index instead of maintaining a second manual byte cursor.

The sequence copy retains the two evidenced address forms: the input sequence
pointer is read from the command base plus the byte offset and canonical
`offsetof(ModgfxCommand, vertexIndices)`, while the output command pointer is
formed from the byte offset plus its base. Flattening both expressions into
the same typed array access changes common-subexpression elimination.

## Active-effect updates

Empty and released slots pass through the retry-loop condition. The retry flag
is already zero there, so this preserves termination while recovering the
retail branch destinations.

A local command cursor carries the command index and byte offset. The explicit
spawn-position view uses the canonical `PartFxSpawnParams.pos` vector. The
command pointer in the nested spawning paths is refreshed by each loop test;
its fields remain available to the corresponding body and following mode test.
The accesses after callbacks retain their required fresh command loads.

The loop initializes both cursor fields with
`cursor.byteOffset = cursor.commandIndex = 0`. Two separate assignments make
MWCC copy the known zero between registers; the chained initializer emits the
two retail immediate loads. These local cursors describe transient processing
state, not newly claimed runtime layouts or proven original source names.

The typed global table is accessed directly during allocation. Keeping an
additional local alias makes MWCC hold two copies of its address around
`mmAlloc`. The stage dispatch reads `currentStage` and `emitterCommands`
directly; redundant cached locals change the first command's register choices.
Both simplifications preserve all 33 functions exactly.

## Pool alignment and validation

The old `.sdata2` alignment override of four bytes was incorrect for the
completed source link. The preceding pool ends at `0x803DF42C`; this unit's
retail pool begins at `0x803DF430` with eight-byte alignment. With the override,
the first four floats and their references move four bytes early even though
objdiff reports the unit exact. Removing the override restores the natural
alignment and the retail checksum without adding padding objects or constants.

- Objdiff: 33/33 functions, 100% code and data.
- Raw `.text`, `.data`, and `.sdata2` contents equal retail.
- Named `.bss` and `.sbss` objects preserve their section offsets and sizes.
  The source emits 20 `.sbss` bytes; normal alignment supplies the four trailing
  padding bytes present in the assigned retail section.
- `ninja all_source` and the strict source-linked checksum pass.
- DOL SHA1: `e750e8e894707a52446118a4b84f1b58b677b269`.
- Formatting is committed separately and preserves the complete object bytes.

The October recovery was checked against all five verified original DOLs.
Every game TU remains exact in a full objdiff inventory with completeness
flags removed. The two existing library-report artifacts (`__exception`
vector carving and `sal_volume` discarded data) are unchanged. All source
objects preserve allocated sections, named symbol offsets, anonymous pool
addresses and resolved relocations after the intentional symbol renames.
Only the manager and descriptor registry have different raw object hashes;
every effect producer and object consumer is byte-identical. All five
`all_source` builds and strict, wholly source-linked retail checksums pass.
