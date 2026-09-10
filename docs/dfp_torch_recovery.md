# DFP torch storage and effect packets

Slot 555 owns its public API and state in
`include/dlls/objects/555_DFP_Torch.h`. The 16-byte state size comes from EN
`DFP_Torch_getExtraSize` at `802057CC`. The placement declaration is a prefix:
EN initialization reads through offset 0x1F, but the complete placement record
size is not established by the available retail evidence.

| Placement offset | Retail access | Meaning |
| --- | --- | --- |
| `18` | sign-extended byte, low six bits shifted ten | X rotation |
| `19` | unsigned byte copied to state `09` | activation mode |
| `1A` | signed halfword | positive motion-rate numerator divided by 8192; otherwise 0.1 |
| `1C` | signed halfword | full-width zero test before initial effect spawn; truncated byte stored at state `0D` |
| `1E` | signed halfword stored as a word | lit-state game bit, -1 sentinel |

The signed full-width color test and later truncation are distinct operations.
The recovered state retains the two signed countdowns and unsigned status
bytes. The TU-owned sequence byte retains its signed casts where retail uses
sign-extended comparisons. No predicates or resource acquisition/release calls
are normalized as part of storage recovery.

## Two effect argument shapes

The flicker particle call passes a 24-byte `PartFxSpawnParams` packet, with
position (0, 5, 0) at offsets 0x0C/0x10/0x14. The particle dispatcher handles
ID 0x1F7 in engine slot 28; that case consumes `posY`. The other packet fields
are not initialized by this caller.

The flame effect calls into modgfx slot 105 use a shorter stack record: only
the float at offset 0x10 is initialized to -2. EN `dll_69_spawnEffect` at
`800EFD44`, offset 0x310, loads that field as its initial Y position. Its extra
XYZ reads occur only when flags bit zero is set and the source object is null.
Both torch calls pass flags 0x10004 and their object, so that path is not taken.
This establishes the Y-offset meaning without inventing an initialized full
particle packet or widening the caller's storage.

The render path traces from 32 units toward the camera from the torch to
20 units short of the camera. `voxmaps_worldToGrid` writes three signed
halfwords; `voxmaps_traceLine` reads and writes the corresponding `VoxPos`
coordinates. The source now uses three real `VoxPos` locals. MWCC naturally
reserves the original eight-byte stack slots for them; no fourth coordinate,
explicit padding or reinterpretation cast is needed. The vectors and flicker
packet remain grouped in `DfpTorchRenderWork`, which preserves the direction
vector's stack storage across calls.

## Boundaries and verification

EN text occupies `802057CC..80205F40` (nine functions, 1908 bytes). The descriptor
ends the source and occupies `803299A0..803299D8`. The parameter template is
`802C2510..802C2520`, the sequence-byte section is `803DDCE8..803DDCF0`, and the
constant pool is `803E63C8..803E63F8`. Generated source paths, neighboring slots,
section claims, symbol names and compiler profiles are unchanged.

The complete source-object census and fresh objdiff reports are unchanged in
EN, EN rev1, JP and PAL rev1. All nine functions and 128 data bytes remain
exact. Full source builds pass for all four versions, and EN passes its strict
retail checksum. Formatting is committed separately and verified to preserve
raw objects. This is source and type recovery; no additional match credit is
claimed.
