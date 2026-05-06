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
// Runtime notes:
// - EarthWalker is shared by WCKingEarth, WCEarthWalk, and WM_deaddino object defs.
// - init installs callback 0x80223004, initializes the anim/control block at extra +0,
//   and copies object-def byte +0x19 into extra +0x65B as the mode selector.
// - update drives a large mode table from extra +0x65B, previous mode +0x65C, world state
//   DAT_803DCAAC, and game bits including 0x7FC, 0x9AD, 0xC36, 0xC55, 0xC90, and 0xC92.
// - render draws the model normally and then asks the EarthWalker control block helper at
//   0x80114DEC to render/submit the extra state.
// - hitDetect special-cases object state 0x203 and pushes hit data through ObjHits.
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
