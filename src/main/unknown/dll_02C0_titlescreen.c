// Non-built exploratory packet for the retail-backed TitleScreen object family.
//
// Source evidence:
// - DLL 0x02C0 is "TitleScreen" in retail XML.
// - Front-end object defs in this family include FrontFox, FrontPeppy,
//   FrontSlippy, FrontRob, FrontFalco, FrontPilots, and FrontPlanet.
//
// Current EN descriptor:
// - gTitleScreenObjDescriptor @ 0x8031CF64
//
// Descriptor slots:
// - 0: titlescreen_initialise (0x8013695C)
// - 1: titlescreen_release (0x801368E0)
// - 3: titlescreen_init (0x801367A8)
// - 4: titlescreen_update (0x80135CC8)
// - 5: titlescreen_hitDetect (0x80135CC4)
// - 6: titlescreen_render (0x80135C2C)
// - 7: titlescreen_free (0x80135BF0)
// - 8: titlescreen_func08 (0x80135BCC)
// - 9: titlescreen_getExtraSize (0x80135BC4)
