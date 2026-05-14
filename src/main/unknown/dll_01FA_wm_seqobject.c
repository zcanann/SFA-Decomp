// Non-built exploratory packet for the retail-backed WM_seqobject object family.
//
// Source evidence:
// - DLL 0x01FA is "WM_seqobject" in retail XML.
// - Object def 0x039E is "WM_seqobjec" and uses various0030 class 0x0030.
// - Object def 0x013B is an alias of the same retail family.
//
// Current EN descriptor:
// - gWM_seqobjectObjDescriptor @ 0x80328748
//
// Descriptor slots:
// - 0: WM_seqobject_initialise (0x801F08FC)
// - 1: WM_seqobject_release (0x801F08F8)
// - 3: WM_seqobject_init (0x801F08CC)
// - 4: WM_seqobject_update (0x801F076C)
// - 5: WM_seqobject_hitDetect (0x801F0768)
// - 6: WM_seqobject_render (0x801F0738)
// - 7: WM_seqobject_free (0x801F0734)
// - 8: WM_seqobject_func08 (0x801F072C)
// - 9: WM_seqobject_getExtraSize (0x801F0724)
