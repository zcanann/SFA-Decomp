// Non-built exploratory packet for the retail-backed DR_EarthCal object family.
//
// Source evidence:
// - DLL 0x0281 is "DR_EarthCal" in retail XML.
// - Object def 0x0481 ("DR_EarthCal") resolves to this family.
//
// Current EN descriptor:
// - gDrEarthCalObjDescriptor @ 0x8032AE10
//
// Runtime notes:
// - update branches on fn_802972A8, which appears to gate the active EarthCall phase.
// - inactive phase marks object byte +0xAF bit 3, checks the player's membership in the
//   object list at object manager +0x100, and sets bit 4 when no nearby target is found.
// - active phase clears bits 3/4 and fires the DAT_803DCA54 trigger callback when
//   ObjTrigger_IsSet reports the object trigger.
// - status flag 0x800 spawns a small effect through objParticleFn_80097734.
//
// Descriptor slots:
// - 0: drearthcal_initialise (0x8022166C)
// - 1: drearthcal_release (0x80221668)
// - 3: drearthcal_init (0x80221640)
// - 4: drearthcal_update (0x80221454)
// - 5: drearthcal_hitDetect (0x80221450)
// - 6: drearthcal_render (0x8022144C)
// - 7: drearthcal_free (0x80221448)
// - 8: drearthcal_func08 (0x80221440)
// - 9: drearthcal_getExtraSize (0x80221438)
// - 10: drearthcal_setScale (0x80221430)
