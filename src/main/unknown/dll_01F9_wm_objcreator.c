// Non-built exploratory packet for the retail-backed WM_ObjCreator object family.
//
// Source evidence:
// - DLL 0x01F9 is "WM_ObjCreator" in retail XML.
// - Object def 0x03A0 is "WM_ObjCreat" and uses ObjCreator class 0x0037.
// - Object def 0x00FB is an alias of the same retail family.
//
// Current EN descriptor:
// - gWM_ObjCreatorObjDescriptor @ 0x80328688
//
// Descriptor slots:
// - 0: WM_ObjCreator_initialise (0x801EFF78)
// - 1: WM_ObjCreator_release (0x801EFF74)
// - 3: WM_ObjCreator_init (0x801EFF34)
// - 4: WM_ObjCreator_update (0x801EF3A8)
// - 5: WM_ObjCreator_hitDetect (0x801EF3A4)
// - 6: WM_ObjCreator_render (0x801EF374)
// - 7: WM_ObjCreator_free (0x801EF370)
// - 8: WM_ObjCreator_func08 (0x801EF368)
// - 9: WM_ObjCreator_getExtraSize (0x801EF360)
