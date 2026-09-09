# DFP statue state and sequence control

Slot 563 now owns `include/dlls/objects/563_DFP_Statue1.h`; the legacy header
is removed and the object registry includes the canonical declaration. Its
generated source path, complete TU, function order, and final descriptor stay
unchanged.

The ten-byte extra-state allocation is established by retail
`DFP_Statue1_getExtraSize`. The recovered fields are:

| Offset | Field | Evidence |
| --- | --- | --- |
| `0x00` | Opaque signed halfword | Copied from placement `+0x1E`; no semantic reader in this TU. |
| `0x02` | `activationGameBit` | Read and cleared through the game-bit API; sequence events also write the bit five IDs later. |
| `0x04` | `effectTimer` | Set to 150 by the variant event, decremented through a float conversion, then used to clear the variant bit. The same interval keeps sound `SFXTRIG_treadlpc` alive. |
| `0x06` | `sequenceActive` | Set after sequence 0 starts and cleared after sequence 1 starts. Initialization also sets it when the activation bit is already set. |
| `0x07` | Opaque byte | Copied from placement `+0x19`; no semantic reader in this TU. |
| `0x08` | `deactivationPending` | Set by the deactivate event and cleared after sequence 1 starts. |
| `0x09` | Opaque byte | Allocation-backed trailing storage; no access is recovered. |

The old sound-ID and effect-count names overstated the evidence. The timer's
signed narrowing, the signed activation request, event consumption, and all
initialization behavior remain unchanged. State size and every field offset
are asserted beside their definitions.

The placement type is explicitly a reader prefix. EN loads a signed rotation
byte at `+0x18`, a byte at `+0x19`, and signed halfwords at `+0x1E` and `+0x20`.
The rotation is stored in the canonical object's `rotX` field. Available EN
revision 1 and JP romlists each contain eight 0x24-byte statue records, but no
EN allocation extent has been established; the prefix must not size allocations
or copies. Unknown storage remains opaque rather than receiving borrowed roles
from the neighboring ring object.

Both statue transitions are gated by game bit `0xEDF`. Slot 562 sets this bit
when its ring sequence starts, and clears it on completion or timeout reset.
Its existing `DFP_ROTATEP_GAMEBIT_RING_ACTIVE` definition now lives in that
slot's canonical header and is shared by the statue's two reads. The complete
source/header search found no additional direct game-bit consumers. The neighboring
TU changes only by removing its private duplicate definition.

The active EN span is `0x80208098..0x8020848C`: eleven functions and 1,012 code
bytes. Its descriptor occupies `0x80329AD8..0x80329B10`, followed in this TU's
assigned sections by the eight-byte integer-to-double conversion constant at
`0x803E6480`. Verified EN revision 1, JP, and PAL revision 1 DOLs contain the
same address-normalized function bodies, allocation result, placement accesses,
and descriptor callbacks. There is no split or compiler-profile change.

All 1,004 EN source objects and 988 objects in each verified secondary version
remain byte-identical after the recovery, including the ring controller and
shared registry. Each complete objdiff report is unchanged; the statue retains
11/11 exact functions, 1,012 matched code bytes, and 64 matched data bytes.
All four `all_source` builds and the strict EN retail checksum pass within their
30-second limits. Generated source paths for slots 562 and 563 pass the audit.
