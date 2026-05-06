// Non-built exploratory packet for the retail-backed WCTemple object family.
//
// Source evidence:
// - DLL 0x0294 is "WCTemple" in retail XML.
// - Known retail object defs using this family include WCMoonTempl and WCSunTemple.
//
// Current EN descriptor:
// - gWCTempleObjDescriptor @ 0x8032B2A0
//
// Runtime notes:
// - update uses extra float +0 as a countdown/timer clamped at zero and extra byte +4 as
//   the current visible/animated state.
// - when the object is touched/activated (object +0xAF bit 0), update toggles sequence
//   slot 0/1 and flips extra byte +4, matching the WCMoonTempl/WCSunTemple lift objects.
//
// Descriptor slots:
// - 0: wctemple_initialise (0x80228C64)
// - 1: wctemple_release (0x80228C60)
// - 3: wctemple_init (0x80228C48)
// - 4: wctemple_update (0x80228B80)
// - 5: wctemple_hitDetect (0x80228B7C)
// - 6: wctemple_render (0x80228B4C)
// - 7: wctemple_free (0x80228B48)
// - 8: wctemple_func08 (0x80228B40)
// - 9: wctemple_getExtraSize (0x80228B38)
