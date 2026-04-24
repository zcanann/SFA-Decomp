// Non-built exploratory packet for the retail-backed AndrossHand object family.
//
// Source evidence:
// - DLL 0x02BD is "AndrossHand" in retail XML.
// - Object defs 0x0231 and 0x0232 ("Androssleft" and "Androssrigh")
//   resolve to this family.
//
// Current EN descriptor:
// - gAndrossHandObjDescriptor @ 0x8032C28C
//
// Descriptor slots:
// - 3: androsshand_init (0x8023FBF4)
// - 4: androsshand_update (0x8023F468)
// - 5: androsshand_hitDetect (0x8023F464)
// - 6: androsshand_render (0x8023F440)
// - 7: androsshand_free (0x8023F43C)
// - 8: androsshand_func08 (0x8023F434)
// - 9: androsshand_getExtraSize (0x8023F42C)
