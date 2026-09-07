# Particle-effects manager (engine DLL 11)

EN v1.0, GC/1.3, 2026-09-07. All 33 functions (14,928 text bytes) and
all 1,260 assigned data bytes match. The unit is `MatchingFor("GSAE01")`.
Its compiler and optimization profile are unchanged.

## Rendering and copying

`dll_0B_renderEffects` uses integer masks for the two texture-frame traversal
limits. A byte cast produces the same frame selection but a different register
assignment in MWCC's unrolled walks.

`dll_0B_spawnEffect` indexes the three geometry buffers directly. Its local
copy cursor keeps the buffer/command index, triangle input pointer, and shared
vertex/sequence element index together. Triangle input and output cursors
advance in retail order. The vertex loop derives its input position from the
element index instead of maintaining a second manual byte cursor.

The sequence copy retains the two evidenced address forms: the input sequence
pointer is read from the command base plus the byte offset and canonical
`offsetof(ModgfxPendingSpawn, param10)`, while the output command pointer is
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
