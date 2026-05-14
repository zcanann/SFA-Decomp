// Non-built exploratory packet for the retail-backed FireFly object family.
//
// Source evidence:
// - DLL 0x020B is "FireFly" in retail XML.
// - Object def 0x04F6 ("FireFly") resolves here.
//
// Current EN descriptor:
// - gFireFlyObjDescriptor @ 0x80328C30
//
// Descriptor slots:
// - 0: firefly_initialise (0x801F5688)
// - 1: firefly_release (0x801F5684)
// - 3: firefly_init (0x801F55FC)
// - 4: firefly_update (0x801F5428)
// - 5: firefly_hitDetect (0x801F5424)
// - 6: firefly_render (0x801F5420)
// - 7: firefly_free (0x801F53D8)
// - 8: firefly_func08 (0x801F53D0)
// - 9: firefly_getExtraSize (0x801F53C8)
//
// Reference-only object parameter hints:
// - 0x1A: unnamed s16; normally set to 0x7F
// - 0x20: unnamed s16; normally set to -1
