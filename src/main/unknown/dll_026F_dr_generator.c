// Non-built exploratory packet for the retail-backed DR_Generator object family.
//
// Source evidence:
// - DLL 0x026F is "DR_Generator" in retail XML.
// - Object defs 0x0440 ("DR_Generato") and 0x0441 ("DR_WallGene") resolve to this family.
//
// Current EN descriptor:
// - gDrGeneratorObjDescriptor @ 0x8032AC58
//
// Descriptor slots:
// - 0: drgenerator_initialise (0x8021F8C8)
// - 1: drgenerator_release (0x8021F8C4)
// - 3: drgenerator_init (0x8021F754)
// - 4: drgenerator_update (0x8021F5AC)
// - 5: drgenerator_hitDetect (0x8021F440)
// - 6: drgenerator_render (0x8021F410)
// - 7: drgenerator_free (0x8021F3EC)
// - 8: drgenerator_func08 (0x8021F3E4)
// - 9: drgenerator_getExtraSize (0x8021F3DC)
