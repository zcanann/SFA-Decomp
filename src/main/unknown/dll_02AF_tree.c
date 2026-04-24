// Non-built exploratory packet for the retail-backed Tree object family.
//
// Source evidence:
// - DLL 0x02AF is "Tree" in retail XML.
// - Multiple foliage-style object defs resolve to this family, including
//   SH_FernTree, FernTree, smallfern, JungleTree, SnowTree1-4, and SnowFruitTr.
//
// Current EN descriptor:
// - gTreeObjDescriptor @ 0x8032BC90
//
// Descriptor slots:
// - 3: tree_init (0x80235E90)
// - 4: tree_update (0x802359CC)
// - 6: tree_render (0x80235904)
// - 9: tree_getExtraSize (0x802358FC)
