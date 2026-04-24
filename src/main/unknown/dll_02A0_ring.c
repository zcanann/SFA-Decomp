// Non-built exploratory packet for the retail-backed Ring object family.
//
// Source evidence:
// - DLL 0x02A0 is "Ring" in retail XML.
// - Object defs 0x0148, 0x0149, 0x0238, 0x0530, and 0x0531 resolve to this family:
//   WCSunRing, WCMoonRing, ANDSilverRi, ARWGoldRing, and ARWSilverRi.
//
// Current EN descriptor:
// - gRingObjDescriptor @ 0x8032B798
//
// Descriptor slots:
// - 0: ring_initialise (0x802308B0)
// - 1: ring_release (0x802308AC)
// - 3: ring_init (0x802306C4)
// - 4: ring_update (0x8022FED4)
// - 5: ring_hitDetect (0x8022FED0)
// - 6: ring_render (0x8022FE50)
// - 7: ring_free (0x8022FE10)
// - 8: ring_func08 (0x8022FE08)
// - 9: ring_getExtraSize (0x8022FE00)
