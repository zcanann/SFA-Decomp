// Non-built exploratory packet for the retail-backed WCTempleDia object family.
//
// Source evidence:
// - DLL 0x0296 is "WCTempleDia" in retail XML.
// - This family follows the same WC temple corridor as SunTemple / WCTemple.
//
// Current EN descriptor:
// - gWCTempleDiaObjDescriptor @ 0x8032B360
//
// Runtime notes:
// - init copies object-def byte +0x18 into the primary angle field, clamps object byte
//   +0xAD, selects one of the two three-entry angle target tables, and mirrors three
//   puzzle bits into the extra byte +8 mask.
// - wctempledia_syncPartVisibility walks the model parts and toggles part visibility from
//   the three-bit puzzle mask, so already-set gems stay visible across reloads.
// - update eases the current angle toward the next target, drives sound ids 0x409/0x487/
//   0x7E, clears earlier bits on out-of-order activation, and raises object-def bit +0x1E
//   once all three mask bits are set.
// - wctempledia_interactCallback is installed at object +0xBC and damps the current angle
//   while suppressing interaction/collision flags in the incoming payload.
//
// Descriptor slots:
// - 0: wctempledia_initialise (0x80229998)
// - 1: wctempledia_release (0x80229994)
// - 3: wctempledia_init (0x8022980C)
// - 4: wctempledia_update (0x802295A8)
// - 5: wctempledia_hitDetect (0x802295A4)
// - 6: wctempledia_render (0x80229574)
// - 7: wctempledia_free (0x80229570)
// - 8: wctempledia_func08 (0x80229568)
// - 9: wctempledia_getExtraSize (0x80229560)
// - internal: wctempledia_syncPartVisibility (0x802293F8)
// - callback: wctempledia_interactCallback (0x802294CC)
