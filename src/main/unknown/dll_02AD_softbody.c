// Non-built exploratory packet for the retail-backed SoftBody object family.
//
// Source evidence:
// - DLL 0x02AD is "SoftBody" in retail XML.
// - Multiple foliage-style object defs resolve to this family, including
//   LINKSnowGra, WM_drape, DFSH_Spirit, BullRush, LongGrassCl,
//   SnowGrass, HangingPlan, and WaterLillyL.
//
// Current EN descriptor:
// - gSoftBodyObjDescriptor @ 0x8032BB70
//
// Descriptor slots:
// - 0: softbody_initialise (0x80235024)
// - 1: softbody_release (0x80235020)
// - 3: softbody_init (0x80234EFC)
// - 4: softbody_update (0x80234E24)
// - 5: softbody_hitDetect (0x80234E20)
// - 6: softbody_render (0x80234DF0)
// - 7: softbody_free (0x80234DD8)
// - 8: softbody_func08 (0x80234DD0)
// - 9: softbody_getExtraSize (0x80234DC8)
