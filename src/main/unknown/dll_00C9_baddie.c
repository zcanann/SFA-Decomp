// Non-built exploratory packet for the retail-backed Baddie object family.
//
// Source evidence:
// - DLL 0x00C9 is "Baddie" in retail XML.
// - This family backs many enemies, including GuardClaw, Vambat, Firebat,
//   Mikaladon, Rachnop, PinPon, Weevil, RedEye, and BossGeneral.
//
// Current EN descriptor:
// - gBaddieObjDescriptor @ 0x8031DC30
//
// Descriptor slots:
// - 0: enemy_initialise (0x8014E1A4)
// - 1: enemy_release (0x8014E170)
// - 3: enemy_init (0x8014D9E4)
// - 4: enemy_update (0x8014D4F0)
// - 5: enemy_hitDetect (0x8014D430)
// - 6: enemy_render (0x8014D29C)
