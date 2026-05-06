// Non-built exploratory packet for the retail-backed ArwingAndrossStuff object family.
//
// Source evidence:
// - DLL 0x029B is "ArwingAndrossStuff" in retail XML.
// - Known retail object defs using this family include rapidFireLa, ANDAsteroid,
//   ANDSuckAste, AndrossRing, and both ARWArwingLa variants.
//
// Current EN descriptor:
// - gArwingAndrossStuffObjDescriptor @ 0x8032B608
//
// Runtime notes:
// - init handles several projectile/prop aliases.  Object 0x0604 seeds two colored
//   ARW shot variants from object byte +0xAD, object 0x06AE uses the Andross-laser
//   palette, and object 0x07E4 is the AndrossRing path.
// - update decrements the lifetime float at extra +4, culls the object when the player
//   arwing is inactive, and triggers delayed impact/explosion behavior through extra
//   +0x10.
// - arwprojectile_createLinkedEffect creates the linked visual effect at extra +0x14 and
//   colors it from object id / object byte +0xAD.
// - arwprojectile_setLifetime stores the countdown in extra +4, while
//   arwprojectile_placeForward computes the spawn position ahead of the source rotation
//   and flips the projectile angles to face outward.
//
// Descriptor slots:
// - 0: arwingandrossstuff_initialise (0x8022ECDC)
// - 1: arwingandrossstuff_release (0x8022ECD8)
// - 3: arwingandrossstuff_init (0x8022EB68)
// - 4: arwingandrossstuff_update (0x8022E94C)
// - 5: arwingandrossstuff_hitDetect (0x8022E6B0)
// - 6: arwingandrossstuff_render (0x8022E680)
// - 7: arwingandrossstuff_free (0x8022E640)
// - 8: arwingandrossstuff_func08 (0x8022E638)
// - 9: arwingandrossstuff_getExtraSize (0x8022E630)
// - helper: arwprojectile_createLinkedEffect (0x8022E418)
// - helper: arwprojectile_placeForward (0x8022E54C)
// - helper: arwprojectile_setLifetime (0x8022E600)
