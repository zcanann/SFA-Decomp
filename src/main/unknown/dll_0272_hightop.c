// Non-built exploratory packet for the retail-backed HighTop object family.
//
// Source evidence:
// - DLL 0x0272 is "HighTop" in retail XML.
// - Object def 0x0434 ("DR_HighTop") resolves to this family.
//
// Current EN descriptor:
// - gHighTopObjDescriptor @ 0x8032ABC0
//
// Descriptor slots:
// - 0: hightop_initialise (0x8021F2B0)
// - 1: hightop_release (0x8021F2AC)
// - 3: hightop_init (0x8021EFD4)
// - 4: hightop_update (0x8021ED28)
// - 5: hightop_hitDetect (0x8021EB18)
// - 6: hightop_render (0x8021E9AC)
// - 7: hightop_free (0x8021E95C)
// - 8: hightop_func08 (0x8021E954)
// - 9: hightop_getExtraSize (0x8021E94C)
// - 10: hightop_setScale (0x8021E944)
// - 11: hightop_func0B (0x8021E93C)
// - 12: hightop_modelMtxFn (0x8021E91C)
// - 13: hightop_render2 (0x8021E914)
