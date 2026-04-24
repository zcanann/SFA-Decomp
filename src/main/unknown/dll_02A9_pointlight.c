// Non-built exploratory packet for the retail-backed PointLight object family.
//
// Source evidence:
// - DLL 0x02A9 is "PointLight" in retail XML.
// - Object defs 0x0106 and 0x0551 ("CF_WallTorc" and "LGTPointLig")
//   resolve to this family.
//
// Current EN descriptor:
// - gPointLightObjDescriptor @ 0x8032B990
//
// Descriptor slots:
// - 0: pointlight_initialise (0x80234048)
// - 1: pointlight_release (0x80234044)
// - 3: pointlight_init (0x80233D90)
// - 4: pointlight_update (0x80233BE4)
// - 5: pointlight_hitDetect (0x80233BE0)
// - 6: pointlight_render (0x80233B98)
// - 7: pointlight_free (0x80233B50)
// - 8: pointlight_func08 (0x80233B48)
// - 9: pointlight_getExtraSize (0x80233B40)
