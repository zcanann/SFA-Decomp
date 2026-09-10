# Shared asset-request record

`src/main/gameloop.c` now models its private request as `AssetLoadRequest` with
named request kinds and typed argument views. The dispatcher and four request
builders no longer pass destination, object, placement, animation-definition or
cache pointers through `int` fields.

## Retail layout

All five original DOLs were verified against their configured SHA-1. The
300-byte dispatcher has the same request-field load offsets and destination
registers in every version. It reads the request kind as a byte at +1 and handles
eight cases. Its common prefix is:

| Offset | Storage | Evidence |
| --- | --- | --- |
| 0 | pending byte | All four builders store 1; no clearing operation was found here. |
| 1 | request-kind byte | Dispatcher uses `lbz` and an eight-entry jump table. |
| 2 | two unused bytes | Preserve the existing gap before the first word. |
| 4 | resource ID word | File, texture, resource, model and animation IDs. |
| 8 | destination pointer | Either an existing file buffer or the address of a result-pointer slot. |

The argument union starts at +0x0C. Its views express the actual calls:

| Kind | Value | Arguments after the common prefix |
| --- | --- | --- |
| allocated file | 0 | none |
| file into buffer | 1 | none |
| file range | 2 | size at +0x0C, file offset at +0x10 |
| texture | 3 | none |
| object | 4 | parent +0x14, placement +0x18, flags +0x1C, object index +0x20, map layer +0x24, unused callee argument +0x28 |
| resource | 5 | argument at +0x0C, masked to 16 bits before the call |
| model | 6 | argument at +0x0C; dispatcher also supplies its existing 16-byte stack scratch buffer |
| animation | 7 | move index +0x0C, cached move +0x20, model/animation definition +0x24 |

The enum names the values while the stored discriminator remains `u8`.
Size and offset assertions cover every recovered field. The object and animation
views preserve their unaccessed interior spans; this does not invent shared
meanings for the different interpretations at +0x20 and +0x24.

The animation ID and move index retain their sign extension to full words when
stored and their signed-16-bit interpretation at the call. The resource request
retains both low-16-bit masks. `ObjAnimDef` is already an alias of
`ModelFileHeader`, so the definition pointer needs no intermediate integer or
structure-pointer cast.

`loadModelInstance` is an eight-byte null-return stub in all five retail binaries.
Its argument and the scratch buffer therefore retain generic names; this code
does not establish a model-flags contract or a scratch-record layout. Likewise,
`Resource_Acquire` currently ignores its second parameter, so the request view
does not assert that it is a size or function count.

## Extent and unresolved ownership

The modeled request still ends at +0x2C. This is the accessed extent already
represented by the source, not a new claim about the four bytes before the next
BSS object. A scan of the generated retail assembly for that gap's symbols in
all five versions finds declarations only. Computed accesses are not excluded
by that negative result, and neither padding nor an extra request field has
been established. The [game-loop BSS layout issue](gameloop_tu_recovery.md)
remains open; no member, alignment override or dummy global was added to hide it.

## Validation

The dispatcher and all four builders remain 100% exact in every version. Every
source object, including the entire game-loop object and all its symbols,
relocations and data, is byte-identical before and after this recovery.
All five targets pass `ninja all_source` and their native strict retail checksum.
This change recovers structure and names; it claims no additional matched code
or completed TU.
