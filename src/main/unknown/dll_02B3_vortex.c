// Non-built exploratory packet for the retail-backed Vortex object family.
//
// Source evidence:
// - DLL 0x02B3 is "Vortex" in retail XML.
// - Object defs in this family include SkyVortS, SkyVortC, WndLiftS,
//   WndLiftC, and DIM_PitVort.
//
// Current EN descriptor:
// - gVortexObjDescriptor @ 0x8032BE50
//
// Descriptor slots:
// - 0: vortex_initialise (0x802383DC)
// - 1: vortex_release (0x802383D8)
// - 3: vortex_init (0x8023812C)
// - 4: vortex_update (0x80237FF4)
// - 5: vortex_hitDetect (0x80237FF0)
// - 6: vortex_render (0x80237848)
// - 7: vortex_free (0x80237818)
// - 8: vortex_func08 (0x80237810)
// - 9: vortex_getExtraSize (0x80237808)
