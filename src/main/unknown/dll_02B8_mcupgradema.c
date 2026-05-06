// Non-built exploratory packet for the retail-backed MCUpgradeMa object family.
//
// Source evidence:
// - DLL 0x02B8 is "MCUpgradeMa" in retail XML.
// - Object def 0x04A0 ("MCUpgradeMa") resolves to this family.
//
// Current EN descriptor:
// - gMCUpgradeMaObjDescriptor @ 0x8032BF78
//
// Descriptor slots:
// - 3: mcupgradema_init (0x802391B4)
// - 4: mcupgradema_update (0x80239114)

// Runtime shape:
// - mirrors MCUpgrade but uses object-def switch +0x1A for the collected state.
// - update polls pickup/use interaction, fires the switch and level-controller
//   callback on collection, and hides itself once already collected.
