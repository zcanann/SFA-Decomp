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

// Helpers:
// - androsshand_spawnShot (0x8023F05C): spawns an Andross hand shot object from
//   a model attachment point, aiming it toward the linked Andross/player target.
// - androsshand_handleDamage (0x8023F1FC): applies hit damage, updates the
//   hand's hit flash/health state, emits fatal explosion feedback, and signals
//   the linked Andross object when depleted.
// - androsshand_setState (0x8023F39C): state setter used by the main Andross
//   controller to command left/right hand attack and recovery states.

// Runtime shape:
// - update follows commands from Andross, transitions between idle, attack,
//   hit, and recovery states, spawns shots, and signals the linked boss object
//   through andross_setPartSignal.
