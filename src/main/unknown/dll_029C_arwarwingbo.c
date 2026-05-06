// Non-built exploratory packet for the retail-backed ARWArwingBo object family.
//
// Source evidence:
// - DLL 0x029C is "ARWArwingBo" in retail XML.
// - Object def 0x0527 ("ARWArwingBo") resolves to this family.
//
// Current EN descriptor:
// - gARWArwingBoObjDescriptor @ 0x8032B640
//
// Runtime notes:
// - update counts down extra float +0 until detonation, then plays sound 0x2A5, spawns
//   effect 0x79E, hides the model, and runs an explosion timer at extra +8 before culling.
// - the player arwing update uses arwarwingbo_setActiveVisible to show or hide the linked
//   bomb/secondary object stored from the arwing extra block.
// - arwarwingbo_setActiveVisible writes extra byte +0, toggles model visibility flag
//   0x4000, and optionally enables collision/visibility through FUN_8002B884.
//
// Descriptor slots:
// - 0: arwarwingbo_initialise (0x8022F144)
// - 1: arwarwingbo_release (0x8022F140)
// - 3: arwarwingbo_init (0x8022F0EC)
// - 4: arwarwingbo_update (0x8022EE30)
// - 5: arwarwingbo_hitDetect (0x8022EE2C)
// - 6: arwarwingbo_render (0x8022EDFC)
// - 7: arwarwingbo_free (0x8022EDB4)
// - 8: arwarwingbo_func08 (0x8022EDAC)
// - 9: arwarwingbo_getExtraSize (0x8022EDA4)
// - helper: arwarwingbo_setActiveVisible (0x8022F148)
