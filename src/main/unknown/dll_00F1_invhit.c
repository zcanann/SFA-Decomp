// Non-built exploratory packet for the retail-backed InvHit object family.
//
// Source evidence:
// - DLL 0x00F1 is "InvHit" in retail XML.
// - Object def 0x04B5 ("InvHit") resolves here.
//
// Current EN descriptor:
// - gInvHitObjDescriptor @ 0x80320DF0
//
// Descriptor slots:
// - 0: invhit_initialise (0x80177E24)
// - 1: invhit_release (0x80177E20)
// - 3: invhit_init (0x80177C18)
// - 4: invhit_update (0x80177818)
// - 5: invhit_hitDetect (0x80177814)
// - 6: invhit_render (0x801777F0)
// - 7: invhit_free (0x801777AC)
// - 8: invhit_func08 (0x801777A4)
// - 9: invhit_getExtraSize (0x8017779C)
