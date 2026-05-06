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
// Runtime notes:
// - init maps object ids 0x060B/0x060C/0x07FB/0x07FC/0x0819 into ring mode byte +0
//   and uses object-def byte +0x19 as the route/reward selector byte +1.
// - update has a pull-in/orbit state at extra byte +0x15 == 2, then restores position
//   from the object definition and hides the model while waiting for ARW shot/contact
//   checks.
// - ring collection dispatches back into the arwing controller through FUN_8022D520 and
//   the 0x8022FA00/0x8022FB5C/0x8022FCD8 helper group, with WCSunRing/WCMoonRing using
//   the same family as ARWGoldRing/ARWSilverRi.
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
