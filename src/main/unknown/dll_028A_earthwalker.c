// Non-built exploratory packet for the retail-backed EarthWalker object family.
//
// Source evidence:
// - DLL 0x028A is "EarthWalker" in retail XML.
// - Known retail object defs using this family include WCKingEarth, WCEarthWalk,
//   and WM_deaddino.
//
// Current EN descriptor:
// - gEarthWalkerObjDescriptor @ 0x8032AED4
//
// Descriptor slots:
// - 0: earthwalker_initialise (0x802239A0)
// - 1: earthwalker_release (0x8022399C)
// - 3: earthwalker_init (0x8022387C)
// - 4: earthwalker_update (0x802231E4)
// - 5: earthwalker_hitDetect (0x80223184)
// - 6: earthwalker_render (0x8022312C)
// - 7: earthwalker_free (0x80223128)
// - 8: earthwalker_func08 (0x80223120)
// - 9: earthwalker_getExtraSize (0x80223118)
