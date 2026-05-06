// Non-built exploratory packet for the retail-backed ARWLevelCon object family.
//
// Source evidence:
// - DLL 0x02A1 is "ARWLevelCon" in retail XML.
// - Object def 0x0536 ("ARWLevelCon") resolves to this family.
//
// Current EN descriptor:
// - gARWLevelConObjDescriptor @ 0x8032B7D0
//
// Runtime notes:
// - init installs arwlevelcon_ringEventCallback at object +0xBC, seeds the HUD/route
//   params in extra +0..+0x20, and maps object byte +0xAC variants 0x3A..0x3E to
//   ring/route ids 0x6DF..0x6E3.
// - update initializes the ARW HUD and cinematic state once, clears route bits
//   0x9D6/0x9D7/0x9D8, and later raises 0x9D7 or 0x9D8 depending on the arwing route
//   result when the player passes the altitude checkpoint.
// - arwlevelcon_ringEventCallback reacts to payload command 1 by triggering sequence
//   slot 0x56, reacts to command 4 by committing the current route index, and installs
//   arwlevelcon_commitRingChoice as the payload follow-up callback.
// - arwlevelcon_commitRingChoice raises either game bit 2 or 0xF3 based on extra byte
//   +0x1B, then advances the ARW level state through FUN_8011F354.
//
// Descriptor slots:
// - 0: arwlevelcon_initialise (0x80230E28)
// - 1: arwlevelcon_release (0x80230E24)
// - 3: arwlevelcon_init (0x80230CC8)
// - 4: arwlevelcon_update (0x80230A78)
// - 5: arwlevelcon_hitDetect (0x80230A74)
// - 6: arwlevelcon_render (0x80230A50)
// - 7: arwlevelcon_free (0x80230A20)
// - 8: arwlevelcon_func08 (0x80230A18)
// - 9: arwlevelcon_getExtraSize (0x80230A10)
// - callback: arwlevelcon_commitRingChoice (0x802308B4)
// - callback: arwlevelcon_ringEventCallback (0x80230904)
