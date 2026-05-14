// Non-built exploratory packet for the retail-backed RollingBarrel object family.
//
// Source evidence:
// - DLL 0x017D is "RollingBarrel" in retail XML.
// - Object def 0x0183 is "DIM2_barrel" and uses various0030 class 0x0030.
// - Object def 0x025C is "MMP_barrel" and uses various0030 class 0x0030.
// - Object defs 0x072A and 0x02C5 are aliases of the same retail family.
//
// Current EN descriptor:
// - gRollingBarrelObjDescriptor @ 0x80323128
//
// Descriptor slots:
// - 0: RollingBarrel_initialise (0x801A662C)
// - 1: RollingBarrel_release (0x801A6628)
// - 3: RollingBarrel_init (0x801A651C)
// - 4: RollingBarrel_update (0x801A6054)
// - 5: RollingBarrel_hitDetect (0x801A6050)
// - 6: RollingBarrel_render (0x801A600C)
// - 7: RollingBarrel_free (0x801A5F80)
// - 8: RollingBarrel_func08 (0x801A5F78)
// - 9: RollingBarrel_getExtraSize (0x801A5F70)
//
// Reference-only object parameter hints:
// - 0x1A: signed 16-bit value
// - 0x1C: curveTimeScale, signed 16-bit value
