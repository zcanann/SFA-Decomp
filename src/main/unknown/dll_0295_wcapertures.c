// Non-built exploratory packet for the retail-backed WCApertureS object family.
//
// Source evidence:
// - DLL 0x0295 is "WCApertureS" in retail XML.
// - Object def 0x013F ("WCApertureS") resolves to this family.
//
// Current EN descriptor:
// - gWCApertureSObjDescriptor @ 0x8032B310
//
// Runtime notes:
// - init copies object-def byte +0x18 into the primary angle field, installs
//   wcapertures_interactCallback at object +0xBC, and seeds extra byte +6 from the
//   armed/open bits at object-def +0x20/+0x1E.
// - init also creates the linked visual effect in extra +0, colors it from object byte
//   +0xAD, and uses object byte +0x36 as the aperture fade/alpha value.
// - update waits for object-def bit +0x20, then checks the held item/player state and
//   raises object-def bit +0x1E once the aperture accepts the interaction.
// - hitDetect can fire effect/sound 0x805 while the aperture is opened and updates the
//   linked effect when extra +0 is present.
//
// Descriptor slots:
// - 0: wcapertures_initialise (0x802293F4)
// - 1: wcapertures_release (0x802293F0)
// - 3: wcapertures_init (0x80229288)
// - 4: wcapertures_update (0x802290F0)
// - 5: wcapertures_hitDetect (0x80229048)
// - 6: wcapertures_render (0x80228F80)
// - 7: wcapertures_free (0x80228F50)
// - 8: wcapertures_func08 (0x80228F20)
// - 9: wcapertures_getExtraSize (0x80228F18)
// - callback: wcapertures_interactCallback (0x80228EDC)
