// Non-built exploratory packet for the retail-backed ARWArwing object family.
//
// Source evidence:
// - DLL 0x029A is "ARWArwing" in retail XML.
// - Object def 0x0523 ("ARWArwing") resolves to this family.
//
// Current EN descriptor:
// - gARWArwingObjDescriptor @ 0x8032B520
//
// Runtime notes:
// - init builds the flight model/controller at extra +0xC0, registers object group 0x26,
//   and maps object byte +0xAC variants 0x3A..0x3E onto route/formation selector bytes
//   in extra +0x47B/+0x471/+0x47E.
// - update runs the flight input/state machine, updates wing/engine child transforms, and
//   drives shot spawning through helper 0x8022B998.  Spawned ARW projectile objects use
//   arwprojectile_createLinkedEffect, arwprojectile_setLifetime, and
//   arwprojectile_placeForward to initialize their effect, lifetime, and forward offset.
//
// Descriptor slots:
// - 0: arwarwing_initialise (0x8022E414)
// - 1: arwarwing_release (0x8022E410)
// - 3: arwarwing_init (0x8022E260)
// - 4: arwarwing_update (0x8022D9DC)
// - 5: arwarwing_hitDetect (0x8022D908)
// - 6: arwarwing_render (0x8022D7C8)
// - 7: arwarwing_free (0x8022D780)
// - 8: arwarwing_func08 (0x8022D778)
// - 9: arwarwing_getExtraSize (0x8022D770)
