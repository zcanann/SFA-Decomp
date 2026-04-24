// Non-built exploratory packet for the retail-backed ARWBombColl object family.
//
// Source evidence:
// - DLL 0x029F is "ARWBombColl" in retail XML.
// - Object defs 0x052A-0x052F resolve to this family:
//   ARWBombColl, ARWLaserCol, ARWContaine, ARWSporeCol, ARWDinoEggC, ARWMoonSeed.
//
// Current EN descriptor:
// - gARWBombCollObjDescriptor @ 0x8032B6E8
//
// Descriptor slots:
// - 0: arwbombcoll_initialise (0x8022F9FC)
// - 1: arwbombcoll_release (0x8022F9F8)
// - 3: arwbombcoll_init (0x8022F9D8)
// - 4: arwbombcoll_update (0x8022F5C4)
// - 5: arwbombcoll_hitDetect (0x8022F5C0)
// - 6: arwbombcoll_render (0x8022F59C)
// - 7: arwbombcoll_free (0x8022F598)
// - 8: arwbombcoll_func08 (0x8022F590)
// - 9: arwbombcoll_getExtraSize (0x8022F588)
