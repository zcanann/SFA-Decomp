// Non-built exploratory packet for the retail-backed DR_BarrelGr object family.
//
// Source evidence:
// - DLL 0x0283 is "DR_BarrelGr" in retail XML.
// - Object def 0x042F ("DR_BarrelGr") resolves to this family.
//
// Current EN descriptor:
// - gDrBarrelGrObjDescriptor @ 0x8032AE88
//
// Runtime notes:
// - init defaults object-def byte +0x19 to 10 and timer +0x1A to 100, then seeds
//   extra state 5, previous state -3, and the held-object pointer at extra +8.
// - update searches object group 0x19 for a nearby barrel/object, checks line of sight,
//   and moves through states that attach, carry, release, or reset the held object.
// - while carrying, render keeps the held object at the cached carry position and draws it
//   unless the state machine is in state 4.
// - free releases any still-held object through the gasvent/small-object helper at 0x801A0B90
//   and clears extra flag bit 7.
//
// Descriptor slots:
// - 0: drbarrelgr_initialise (0x80223000)
// - 1: drbarrelgr_release (0x80222FFC)
// - 3: drbarrelgr_init (0x80222EE4)
// - 4: drbarrelgr_update (0x802229CC)
// - 5: drbarrelgr_hitDetect (0x802229C8)
// - 6: drbarrelgr_render (0x80222844)
// - 7: drbarrelgr_free (0x802227FC)
// - 8: drbarrelgr_func08 (0x802227F4)
// - 9: drbarrelgr_getExtraSize (0x802227EC)
