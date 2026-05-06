// Non-built exploratory packet for the retail-backed MCUpgrade object family.
//
// Source evidence:
// - DLL 0x02B7 is "MCUpgrade" in retail XML.
// - Object def 0x049F ("MCUpgrade") resolves to this family.
//
// Current EN descriptor:
// - gMCUpgradeObjDescriptor @ 0x8032BF40
//
// Descriptor slots:
// - 3: mcupgrade_init (0x80239044)
// - 4: mcupgrade_update (0x80238FA4)

// Runtime shape:
// - update waits for the completion switch at object-def +0x1E; until then it
//   polls pickup/use interaction and fires the switch plus level-controller
//   callback when collected.
// - once the switch is already set, update hides the object through object flag
//   bit 0x08.
