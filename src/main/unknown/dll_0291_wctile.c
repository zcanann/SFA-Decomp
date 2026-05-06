// Non-built exploratory packet for the retail-backed WCTile object family.
//
// Source evidence:
// - DLL 0x0291 is "WCTile" in retail XML.
// - Object def 0x013C ("WCTile") resolves to this family.
//
// Current EN descriptor:
// - gWCTileObjDescriptor @ 0x8032B1B0
//
// Runtime notes:
// - init copies object-def byte +0x19 into object byte +0xAD, clamps it against model
//   data, saves object-def halfword +0x1A into extra +8, and installs the default
//   model callback.
// - update registers itself with object group 9 on first tick and uses the level
//   controller's path/grid callbacks to drive the tile through idle, moving, fading,
//   reset, and locked states.
// - object byte +0xAD selects which half of the controller callbacks is used; game bits
//   0x808/0x809/0x812/0x813 can force tile state transitions.
//
// Descriptor slots:
// - 0: wctile_initialise (0x80227BB4)
// - 1: wctile_release (0x80227BB0)
// - 3: wctile_init (0x80227B24)
// - 4: wctile_update (0x8022771C)
// - 5: wctile_hitDetect (0x80227718)
// - 6: wctile_render (0x802276E8)
// - 7: wctile_free (0x802276E4)
// - 8: wctile_func08 (0x802276B4)
// - 9: wctile_getExtraSize (0x802276AC)
