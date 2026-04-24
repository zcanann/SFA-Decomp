// Non-built exploratory packet for the retail-backed Lock object family.
//
// Source evidence:
// - DLL 0x0111 is "Lock" in retail XML.
// - Retail callback names expose the shared DoorLock API.
//
// Current EN descriptor:
// - gDoorLockObjDescriptor @ 0x80321130
//
// Descriptor slots:
// - 3: doorlock_init (0x8017C178)
// - 4: doorlock_update (0x8017BE28)
// - 6: doorlock_render (0x8017BDD8)
// - 7: doorlock_free (0x8017BDB4)
// - 9: doorlock_getExtraSize (0x8017BDAC)
