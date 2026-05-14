// Non-built exploratory packet for the retail-backed Collectible object family.
//
// Source evidence:
// - DLL 0x00ED is "Collectible" in retail XML.
// - This family backs many pickup/key object defs such as Power Crystals, keys,
//   Spellstone, EnergyEgg, Apple, and other collectible props.
//
// Current EN descriptor:
// - gCollectibleObjDescriptor @ 0x80320C64
//
// Descriptor slots:
// - 0: collectible_initialise (0x80173220)
// - 1: collectible_release (0x8017321C)
// - 3: collectible_init (0x80172F14)
// - 4: collectible_update (0x80172C24)
// - 5: collectible_hitDetect (0x80172C20)
// - 6: collectible_render (0x80172B1C)
// - 7: collectible_free (0x80172AD4)
// - 8: collectible_func08 (0x80172ACC)
// - 9: collectible_getExtraSize (0x80172AC4)
// - A: collectible_setScale (0x80171E54)
// - B: collectible_func0B (0x80171DF8)
// - C: collectible_modelMtxFn (0x80171DA8)
// - D: collectible_render2 (0x80171D70)
// - E: collectible_func0E (0x80171D98)
// - F: collectible_func0F (0x80171D8C)
// - 10: collectible_func10 (0x80171D14)
