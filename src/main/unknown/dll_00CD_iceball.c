// Non-built exploratory packet for the retail-backed IceBall object family.
//
// Source evidence:
// - DLL 0x00CD is "IceBall" in retail XML.
// - Object defs 0x004F-0x0051 resolve to this family:
//   IceBall, IceBallSmal, and ChukaChuck.
//
// Current EN descriptor:
// - gIceBallObjDescriptor @ 0x8031FFD0
//
// Descriptor slots:
// - 0: iceball_initialise (0x801601C0)
// - 1: iceball_release (0x801601BC)
// - 3: iceball_init (0x80160180)
// - 4: iceball_update (0x8015FFC8)
// - 5: iceball_hitDetect (0x8015FFC4)
// - 6: iceball_render (0x8015FF94)
// - 7: iceball_free (0x8015FF74)
// - 8: iceball_func08 (0x8015FF6C)
// - 9: iceball_getExtraSize (0x8015FF64)
