// Non-built exploratory packet for the retail-backed SpiritPrize object family.
//
// Source evidence:
// - DLL 0x017A is "SpiritPrize" in retail XML.
// - Object defs 0x03FF and 0x0406 are "SpiritPrize" and use AnimatedObj class 0x0010.
// - Object def 0x0407 is "ECSH_Spirit" and uses AnimatedObj class 0x0010.
// - Object defs 0x01D9, 0x01DF, and 0x01E0 are aliases of the same retail family.
//
// Current EN descriptor:
// - gSpiritPrizeObjDescriptor @ 0x80326048
//
// Descriptor slots:
// - 0: SpiritPrize_initialise (0x801C3B64)
// - 1: SpiritPrize_release (0x801C3B60)
// - 3: SpiritPrize_init (0x801C3974)
// - 4: SpiritPrize_update (0x801C3710)
// - 5: SpiritPrize_hitDetect (0x801C370C)
// - 6: SpiritPrize_render (0x801C3684)
// - 7: SpiritPrize_free (0x801C3628)
// - 8: SpiritPrize_func08 (0x801C3620)
// - 9: SpiritPrize_getExtraSize (0x801C3618)
