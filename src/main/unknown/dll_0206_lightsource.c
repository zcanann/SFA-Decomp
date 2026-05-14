// Non-built exploratory packet for the retail-backed LightSource object family.
//
// Source evidence:
// - DLL 0x0206 is "LightSource" in retail XML.
// - Object defs 0x03B9, 0x05A3, 0x05A4, 0x05A5, 0x01D7, and 0x05A6 share this DLL family.
//
// Current EN descriptor:
// - gLightSourceObjDescriptor @ 0x80328B08
//
// Descriptor slots:
// - 0: lightsource_initialise (0x801F3C28)
// - 1: lightsource_release (0x801F3C24)
// - 3: lightsource_init (0x801F37CC)
// - 4: lightsource_update (0x801F34AC)
// - 5: lightsource_hitDetect (0x801F34A8)
// - 6: lightsource_render (0x801F3410)
// - 7: lightsource_free (0x801F33C4)
// - 8: lightsource_func08 (0x801F33BC)
// - 9: lightsource_getExtraSize (0x801F33B4)
