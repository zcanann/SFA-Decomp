// Non-built exploratory packet for the retail-backed WCTile object family.
//
// Source evidence:
// - DLL 0x0291 is "WCTile" in retail XML.
// - Object def 0x013C ("WCTile") resolves to this family.
//
// Current EN descriptor:
// - gWCTileObjDescriptor @ 0x8032B1B0
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
