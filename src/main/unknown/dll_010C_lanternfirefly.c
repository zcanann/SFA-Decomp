// Non-built exploratory packet for the retail-backed LanternFireFly object family.
//
// Source evidence:
// - DLL 0x010C is "LanternFireFly" in retail XML.
// - Object def 0x049B is "LanternFire" and uses various0030 class 0x0030.
// - Object def 0x043C is an alias of the same retail family.
//
// Current EN descriptor:
// - gLanternFireFlyObjDescriptor @ 0x80321830
//
// Descriptor slots:
// - 0: LanternFireFly_initialise (0x801871C4)
// - 1: LanternFireFly_release (0x801871C0)
// - 3: LanternFireFly_init (0x801870B0)
// - 4: LanternFireFly_update (0x80186BC8)
// - 5: LanternFireFly_hitDetect (0x80186BC4)
// - 6: LanternFireFly_render (0x80186B94)
// - 7: LanternFireFly_free (0x80186AEC)
// - 8: LanternFireFly_func08 (0x80186AE4)
// - 9: LanternFireFly_getExtraSize (0x80186ADC)
// - 10: LanternFireFly_setScale (0x80186878)
// - 11: LanternFireFly_func0B (0x80186718)
// - 12: LanternFireFly_modelMtxFn (0x80186704)
//
// Reference-only object parameter hints:
// - 0x19: color or sprite index
// - 0x1A: life in frames
// - 0x1C: orbit radius
// - 0x1E: vertical movement amount
