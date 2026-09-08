# DFP object-creator storage and water-hit lifetime

Slot 554 now owns its public API, 28-byte state and recovered placement prefix
in `include/dlls/objects/554_DFP_ObjCrea.h`. This replaces two legacy headers
and competing 0x28/0x30 placement declarations. The canonical header is included
first by the TU and directly by the descriptor registry. Slot 556 no longer
imports the unrelated creator state merely to repeat its size assertion.

EN retail `DFP_ObjCreator_getExtraSize` at `80204970` returns 0x1C. Initialization
at `80204AF4` establishes the following placement prefix:

| Offset | View | EN evidence |
| --- | --- | --- |
| `18` | signed game bit | `lha`, stored to state `0C` |
| `1A` | signed behavior mode | update compares against 7 |
| `1C` | signed spawn period | `lha`, copied to state period and timer |
| `1E` | signed rotation byte / child user data | sign-extended before rotation shift and child `userData1` store |
| `1F` | unknown signed byte | sign-extended into state `12` |
| `20` | unknown unsigned byte | doubled into state `14` |

The explicit union at 0x1E records its two observed uses. The remaining state
shorts stay unnamed where consumers do not establish a role. The state pointer
at offset zero is released by `free` but never assigned by this TU; calling it
`ownedObj` avoids claiming that it is the child created by `update`.

The owner's full EN placement extent is **not established**. The EN extracted
asset directory is empty in this checkout, and no direct owner allocation was
found. Eight creator records in each inspected secondary asset set are 0x24
bytes, which corroborates the prefix but is not promoted to an EN size claim.
`DfpObjCreatorPlacementPrefix` has field-offset assertions and no full-record
size assertion or invented trailing fields.

## The child setup belongs to CFCrate

At `80204A64`, EN calls `Obj_AllocObjectSetup` with size 0x24 and object ID
0x71B. The stored value 0xDC at setup offset 0x1A was incorrectly called an
object-definition ID. CFCrate's corresponding case initializes its signed
lifetime from this halfword, then subtracts `framesThisStep` until freeing the
child. It is a **220-frame lifetime**.

The creator now allocates `sizeof(CFCratePlacement)` and writes the canonical
`lingerFrames`, `gameBitA` and `gameBitB` fields. `lingerFrames` is an explicit
union view of the existing object-specific 0x1A field, also used by the CFCrate
consumer. The shared object ID `CFCRATE_OBJ_DFP_WATER_HI` is owned by CFCrate's
header. Secondary OBJINDEX records map it to definition 0x347, DFP_WaterHi,
DLL 298; existing EN CFCrate dispatch and lifetime accesses establish the code
contract independently. Unrelated particle-effect IDs with the same number
are a different namespace and remain unchanged.

## Validation

The EN TU remains `80204970..80204B54` with its 56-byte descriptor at
`80329898..803298D0`. The descriptor ends the TU. No neighboring slot, generated
path, symbol, split or compiler profile changes. The exact render callback's
apparently redundant signed-byte test is retained because retail emits it.

All nine functions (484 code bytes), descriptor data, relocations and complete
object identities are preserved in EN, EN rev1, JP and PAL rev1. Full source
builds, the complete source-object hash census and objdiff reports are checked
in each version. EN's strict retail checksum passes. Formatting is separately
verified to preserve generated objects. This is storage and source recovery;
no additional match credit is claimed.
