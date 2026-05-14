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
// - 14: hightop_func0E (0x8021E90C)
// - 15: hightop_func0F (0x8021E864)
// - 16: hightop_func10 (0x8021E85C)
// - 17: hightop_func11 (0x8021E84C)
// - 18: hightop_func12 (0x8021E838)
// - 19: hightop_func13 (0x8021E828)
// - 20: hightop_func14 (0x8021E820)
// - 21: hightop_func15 (0x8021E81C)
// - 22: hightop_renderGroundMarker (0x8021E748)
// - 23: hightop_getLookTargetYaw (0x8021E66C)
//
// Runtime state evidence:
// - hightop_initialise fills gHighTopStateHandlers with 11 state handlers.
// - gHighTopDefaultStateHandler is installed as the fallback state callback.
