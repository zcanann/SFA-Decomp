// Non-built exploratory packet for the retail-backed MoonSeedBush object family.
//
// Source evidence:
// - DLL 0x017F is "MoonSeedBush" in retail XML.
// - Object def 0x050E is "MSBush" and uses Door53 class 0x0053.
// - Object def 0x050F is "MSVine" and uses Door53 class 0x0053.
// - Object defs 0x0523 and 0x0524 are aliases of the same retail family.
//
// Current EN descriptor:
// - gMoonSeedBushObjDescriptor @ 0x80323198
//
// Descriptor slots:
// - 0: MoonSeedBush_initialise (0x801A6F48)
// - 1: MoonSeedBush_release (0x801A6F44)
// - 3: MoonSeedBush_init (0x801A6E70)
// - 4: MoonSeedBush_update (0x801A6DA4)
// - 5: MoonSeedBush_hitDetect (0x801A6DA0)
// - 6: MoonSeedBush_render (0x801A6D70)
// - 7: MoonSeedBush_free (0x801A6D6C)
// - 8: MoonSeedBush_func08 (0x801A6D64)
// - 9: MoonSeedBush_getExtraSize (0x801A6D5C)
