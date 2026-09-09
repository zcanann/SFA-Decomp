# Ocean Force Point spellstone placement

Slot 567 now owns `include/dlls/objects/567_DFPSpPl.h`. Its state, placement
reader and descriptor no longer borrow laser names from the shared legacy
header. The descriptor is `gDFPSpPlObjDescriptor`, with the same layout,
callback order and registry position. Its symbol name is updated consistently
in every version config; addresses, sizes and splits do not change.

Retail `DFPSpPl_getExtraSize` returns six bytes. `DfpSpellPlaceState` models
the two signed game-bit IDs at offsets zero and two, the completion latch at
four, and the unaccessed trailing byte at five. Size and every field offset are
asserted in the owning header. `DfpSpellPlacePlacementPrefix` describes the
signed rotation byte at `0x18` and signed game-bit IDs at `0x1E` and `0x20`.
It does not claim a complete EN allocation. EN revision 1 and JP each have two
0x24-byte serialized records, which corroborate the reader layout but do not
establish the missing EN allocation extent.

The interaction is an item-use check, not a sequence-completion callback:

- Map act 1 checks `GAMEBIT_ITEM_WaterSpellStone1_Got` (`0x2E8`).
- Map act 2 checks `GAMEBIT_ITEM_WaterSpellStone2_Got` (`0x83C`).
- `GameUI_isItemBeingUsed` compares the argument with the activated C-menu item
  ID, clears `gCMenuCloseSfx` on a match, and returns one.
- A successful check sets the placement's completion bit, clears its activation
  bit, latches completion and disables interaction. The second stone also sets
  map slot 7 to act 8 and slot 13 to act 2. Both available MAPINFO tables name
  those slots ThornTail Hollow and Walled City.

The source uses the canonical water SpellStone item IDs and names the local
map acts and transitions. It preserves the byte narrowing of the current act,
signed game-bit loads, interaction flag operations, repeated state loads and
all initialization behavior. No new gameplay behavior is introduced.

This recovery initially retained the legacy types and constants used by slot
552, plus slot 566's unsupported laser API. The subsequent
[fire SpellStone recovery](vfp_spellstone_placement.md) removes the remaining
spellstone declarations from that header. The shared registry changes for
slot 567 remain limited to its canonical include and descriptor rename.

The EN TU is `0x802090A8..0x8020930C`, containing nine functions and 612 code
bytes. Its only assigned data is the 56-byte descriptor at `0x80329C48`.
Checksum-verified EN, EN revision 1, JP and PAL revision 1 DOLs agree on the
address-normalized function bodies, state allocation, placement reads, item IDs,
map-act changes and descriptor callbacks. The item-use predicate also has the
same normalized body in all four. This audit establishes no PAL revision 0
binary match; that config receives only the consistent symbol rename.

All four objdiff reports remain unchanged: nine exact functions, 612 matched
code bytes and 56 matched data bytes. Every other source object remains
byte-identical (1,002 in EN and 986 per secondary version), including slots
552 and 566. The two changed objects contain only the descriptor symbol rename
and the registry relocation at byte offset 2,268, exactly slot 567. Every
function byte, allocated section, named layout and resolved relocation is
preserved. All four `all_source` builds and the strict EN retail checksum pass
within their 30-second bounds; generated paths pass the slots 566–567 audit.
