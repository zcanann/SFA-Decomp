// Non-built exploratory packet for the retail-backed WM_Galleon object family.
//
// Source evidence:
// - DLL 0x01F8 is "WM_Galleon" in retail XML.
// - Object def 0x039F is "WM_Galleon" and uses various0030 class 0x0030.
// - Object def 0x0139 is an alias of the same retail family.
//
// Current EN descriptor:
// - gWM_GalleonObjDescriptor @ 0x803286E8
//
// Descriptor slots:
// - 0: WM_Galleon_initialise (0x801F06D4)
// - 1: WM_Galleon_release (0x801F06D0)
// - 3: WM_Galleon_init (0x801F05D4)
// - 4: WM_Galleon_update (0x801F02F0)
// - 5: WM_Galleon_hitDetect (0x801F02EC)
// - 6: WM_Galleon_render (0x801F022C)
// - 7: WM_Galleon_free (0x801F01CC)
// - 8: WM_Galleon_func08 (0x801F01C4)
// - 9: WM_Galleon_getExtraSize (0x801F01BC)
