// Non-built exploratory packet for the retail-backed BarrelGener object family.
//
// Source evidence:
// - DLL 0x0282 is "BarrelGener" in retail XML.
// - Object def 0x0503 ("BarrelGener") resolves to this family.
//
// Current EN descriptor:
// - gBarrelGenerObjDescriptor @ 0x8032AE50
//
// Runtime notes:
// - init registers the generator in object group 0x3A and clears the held object pointer.
// - barrelgener_getLinkId returns object-def byte +0x19, used by other objects to find the
//   matching generator through group 0x3A.
// - barrelgener_queueObjectRelease stores a linked object in extra +0, clears the active flag,
//   and arms the release timer at extra +8.
// - update can fire trigger callback bit 0xADB when the player comes within range, then later
//   releases the queued object at the generator position and moves it into object group 0x19.
//
// Descriptor slots:
// - 0: barrelgener_initialise (0x80221974)
// - 1: barrelgener_release (0x80221970)
// - 3: barrelgener_init (0x8022192C)
// - 4: barrelgener_update (0x80221744)
// - 5: barrelgener_hitDetect (0x80221740)
// - 6: barrelgener_render (0x80221710)
// - 7: barrelgener_free (0x802216EC)
// - 8: barrelgener_func08 (0x802216E4)
// - 9: barrelgener_getExtraSize (0x802216DC)
