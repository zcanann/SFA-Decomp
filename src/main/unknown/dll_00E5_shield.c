// Non-built exploratory packet for the retail-backed Shield object family.
//
// Source evidence:
// - DLL 0x00E5 is "Shield" in retail XML.
// - Object defs 0x0010 ("fox_shield") and 0x0014 ("omni_shield") resolve here.
//
// Current EN descriptor:
// - gShieldObjDescriptor @ 0x80320A68
//
// Descriptor slots:
// - 0: shield_initialise (0x801712FC)
// - 1: shield_release (0x801712F8)
// - 3: shield_init (0x80171298)
// - 4: shield_update (0x80170F70)
// - 5: shield_hitDetect (0x80170F6C)
// - 6: shield_render (0x80170AF0)
// - 7: shield_free (0x80170A8C)
// - 8: shield_func08 (0x80170A84)
// - 9: shield_getExtraSize (0x80170A7C)
