// Non-built exploratory packet for the retail-backed MCLightning object family.
//
// Source evidence:
// - DLL 0x02BA is "MCLightning" in retail XML.
// - Object def 0x04A2 ("MCLightning") resolves to this family.
//
// Current EN descriptor:
// - gMCLightningObjDescriptor @ 0x8032BFE8
//
// Descriptor slots:
// - 3: mclightning_init (0x802397E4)
// - 4: mclightning_update (0x80239778)
// - 6: mclightning_render (0x80239520)
// - 7: mclightning_free (0x802394E0)
// - 9: mclightning_getExtraSize (0x802394D8)

// Helpers:
// - mclightning_handleScriptEvents (0x8023938C): installed in obj->funcBC;
//   consumes script/hit-event parameters and advances the lightning state
//   machine, including radius, travel time, target id, and clear/done states.

// Runtime shape:
// - init installs mclightning_handleScriptEvents, registers the object in type
//   0x48 lookup lists, copies object-def flags from byte +0x1A, and hides the
//   object until a scripted event arms it.
// - render connects this object to a target MCLightning with a beam/effect,
//   starts optional endpoint effects, advances beam progress, and clears the
//   hidden flag while active.
// - update removes any active beam handle, resets the state nybble, and hides
//   the object again.
