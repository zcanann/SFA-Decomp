// Non-built exploratory packet for the retail-backed SB_CloudRunner object family.
//
// Source evidence:
// - DLL 0x0259 is "SB_CloudRunner" in retail XML.
// - Object def 0x02F9 is "SB_Cloudrun" and uses various0030 class 0x0030.
// - Object def 0x008C is an alias of the same retail family.
//
// Current EN descriptor:
// - gSB_CloudRunnerObjDescriptor @ 0x80328618
//
// Descriptor slots:
// - 0: SB_CloudRunner_initialise (0x801EF35C)
// - 1: SB_CloudRunner_release (0x801EF358)
// - 3: SB_CloudRunner_init (0x801EF2B0)
// - 4: SB_CloudRunner_update (0x801EF024)
// - 5: SB_CloudRunner_hitDetect (0x801EF020)
// - 6: SB_CloudRunner_render (0x801EEEE0)
// - 7: SB_CloudRunner_free (0x801EEE4C)
// - 8: SB_CloudRunner_func08 (0x801EEE44)
// - 9: SB_CloudRunner_getExtraSize (0x801EEE3C)
