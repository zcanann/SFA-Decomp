// Non-built exploratory packet for the retail-backed ARWBlocker object family.
//
// Source evidence:
// - DLL 0x02A8 is "ARWBlocker" in retail XML.
// - Object defs 0x0532 and 0x0533 ("ARWBlocker" and "ARWBlockerS")
//   resolve to this family.
//
// Current EN descriptor:
// - gARWBlockerObjDescriptor @ 0x8032B958
//
// Descriptor slots:
// - 0: arwblocker_initialise (0x80233B08)
// - 1: arwblocker_release (0x80233B04)
// - 3: arwblocker_init (0x80233A98)
// - 4: arwblocker_update (0x80233964)
// - 5: arwblocker_hitDetect (0x80233960)
// - 6: arwblocker_render (0x8023393C)
// - 7: arwblocker_free (0x80233938)
// - 8: arwblocker_func08 (0x80233930)
// - 9: arwblocker_getExtraSize (0x80233928)
