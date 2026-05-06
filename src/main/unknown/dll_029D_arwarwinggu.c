// Non-built exploratory packet for the retail-backed ARWArwingGu object family.
//
// Source evidence:
// - DLL 0x029D is "ARWArwingGu" in retail XML.
// - Object defs 0x0538 and 0x0539 ("ARWArwingGu") resolve to this family.
// - Object def 0x053A ("ARWArwingRo") shares this DLL family in retail.
//
// Current EN descriptor:
// - gARWArwingGuObjDescriptor @ 0x8032B678
//
// Runtime notes:
// - update handles the gun/rotor variants by object id: 0x0606 writes part transforms
//   into the model, 0x0611 fades object byte +0x36 by extra byte +0, and 0x0610/0x0615
//   count down extra float +0 before hiding the object.
// - arwarwinggu_setActiveVisible is used by ARW shot spawning to reveal a left/right gun
//   object, reset object byte +0x36 to 0xFF, and arm the short extra float +0 timer.
//
// Descriptor slots:
// - 0: arwarwinggu_initialise (0x8022F528)
// - 1: arwarwinggu_release (0x8022F524)
// - 3: arwarwinggu_init (0x8022F4FC)
// - 4: arwarwinggu_update (0x8022F368)
// - 5: arwarwinggu_hitDetect (0x8022F364)
// - 6: arwarwinggu_render (0x8022F360)
// - 7: arwarwinggu_free (0x8022F35C)
// - 8: arwarwinggu_func08 (0x8022F354)
// - 9: arwarwinggu_getExtraSize (0x8022F300)
// - helper: arwarwinggu_setActiveVisible (0x8022F1D8)
