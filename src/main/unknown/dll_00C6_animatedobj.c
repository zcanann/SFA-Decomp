// Non-built exploratory packet for the retail-backed AnimatedObj object family.
//
// Source evidence:
// - DLL 0x00C6 is "AnimatedObj" in retail XML.
// - This family backs many animated scene and character object defs, including
//   AnimDummy, AnimTricky, AnimKyte, Rarelogo, N64logo, and many area-specific anim props.
//
// Current EN descriptor:
// - gAnimatedObjDescriptor @ 0x80320730
//
// Descriptor slots:
// - 3: animatedobj_init (0x8016C338)
// - 4: animatedobj_update (0x8016C0E4)
// - 6: animatedobj_render (0x8016BF3C)
// - 7: animatedobj_free (0x8016BE78)
// - 9: animatedobj_getExtraSize (0x8016BE70)
