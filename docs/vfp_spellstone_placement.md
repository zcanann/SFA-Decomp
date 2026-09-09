# Fire SpellStone placement ownership

Slot 552 now owns its state and public API in `include/dlls/objects/552.h`.
The generated `src/dlls/objects/552/552.c` path remains unchanged.

`VfpSpellPlaceState` follows the six-byte allocation returned by retail
`VFP_SpellPlace_getExtraSize`: signed completion and activation game-bit IDs
at offsets zero and two, an unsigned completion latch at four, and one opaque
trailing byte. The canonical header asserts the size and every field offset.
The init callback accepts `VfpSpellPlacePlacementPrefix*` directly, removing
the byte-pointer argument and intermediate cast. The prefix models the signed
rotation byte at `0x18`, five unknown bytes, and signed game-bit IDs at `0x1E`
and `0x20`. Two EN revision 1 and two JP serialized placements have size 0x24;
EN allocation size remains unproven, so this reader prefix must not size an
allocation or copy.

The two map acts check use of the first and second fire SpellStone through
`GameUI_isItemBeingUsed`. The source now uses the existing canonical IDs
`GAMEBIT_ITEM_FireSpellStone1_Got` (`0x123`) and
`GAMEBIT_ITEM_FireSpellStone2_Got` (`0x83B`). Successful use sets completion,
clears activation, latches the result and disables interaction. The map act
keeps its evidenced unsigned-byte type. Repeated state loads, signed game-bit
accesses, rotation narrowing and flag operations are preserved.

With both this object and the [water SpellStone placement](dfp_spellstone_placement.md)
using their own headers, the legacy laser header no longer declares spellstone
state, placement records or sequence-ID aliases. Its unused release-interface
overlay is also removed after a complete consumer search. The header now
contains only the unsupported slot 566's declarations and identification
constants. Slot 566 still returns zero extra-state bytes.

The registry includes the canonical slot 552 header and removes its incorrect
`ResourceDescriptor` extern. The descriptor is an `ObjectDescriptor`; the
explicit cast now occurs only at the generic registry entry. Matching-prototype
descriptor callbacks use function designators directly, while casts remain for
the deliberately different signatures. The final descriptor's position, symbol
name and all ten callback slots stay unchanged.

EN owns nine functions at `0x801FDEEC..0x801FE118` (556 bytes) and its 56-byte
descriptor at `0x80329280`. Independent audits of checksum-verified EN, EN
revision 1, JP and PAL revision 1 DOLs agree on the normalized function bodies,
six-byte allocation, placement loads, item IDs and descriptor callbacks.
No source boundary, compiler profile or matching flag changes.

All 1,004 EN source objects and 988 in each verified secondary version remain
byte-identical, including the object registry and unsupported laser TU. All
four complete objdiff reports are unchanged: this object retains nine exact
functions, 556 matched code bytes and 56 matched data bytes. The four
`all_source` builds and strict EN retail checksum pass within 30-second bounds;
the generated path audit also passes.
