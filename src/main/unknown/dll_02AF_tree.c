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

// Helpers:
// - tree_spawnAmbientEffect (0x802356CC): creates one of the three ambient tree
//   effect handles from the tree's stored attachment positions.
// - tree_updateAmbientEffects (0x802357E8): maintains three ambient effect
//   handles, respawning expired slots after randomized delays and following the
//   stored attachment positions while the effect is active.

// Runtime shape:
// - init seeds decorative tree rotation/scale, initializes ambient-effect,
//   hit-reaction, and radius flags from object-def bytes +0x1C..+0x1E, and maps
//   model ids to effect profile indices.
// - render draws the base model and, when the ambient-effect flag is set, draws
//   three stored attachment markers/effects.
// - update handles ambient effects, hit/shake reactions, knock/drop effects,
//   and proximity-triggered decorative effects using the per-model profile.
