// Non-built exploratory packet for the retail-backed VFP_lavapool object family.
//
// Source evidence:
// - DLL 0x0226 is "VFP_lavapool" in retail XML.
// - Object def 0x0318 is "VFP_lavapoo" and uses various0030 class 0x0030.
//
// Current EN descriptor:
// - gVFP_lavapoolObjDescriptor @ 0x80329210
//
// Descriptor slots:
// - 0: VFP_lavapool_initialise_nop (0x801FDBB8)
// - 1: VFP_lavapool_release_nop (0x801FDBB4)
// - 3: VFP_lavapool_init (0x801FDAC0)
// - 4: VFP_lavapool_update (0x801FDAA0)
// - 5: VFP_lavapool_hitDetect_nop (0x801FDA9C)
// - 6: VFP_lavapool_render (0x801FDA24)
// - 7: VFP_lavapool_free_nop (0x801FDA20)
// - 8: VFP_lavapool_func08_ret_0 (0x801FDA18)
// - 9: VFP_lavapool_getExtraSize_ret_24 (0x801FDA10)
