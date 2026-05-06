// Non-built exploratory packet for the retail-backed ARWBlocker object family.
//
// Source evidence:
// - DLL 0x02A8 is "ARWBlocker" in retail XML.
// - Object defs 0x0532 and 0x0533 ("ARWBlocker" and "ARWBlockerS")
//   resolve to this family.
//
// Current EN descriptor:
// - gARWBlockerObjDescriptor @ 0x8032B958
//
// Descriptor slots:
// - 0: arwblocker_initialise (0x80233B08)
// - 1: arwblocker_release (0x80233B04)
// - 3: arwblocker_init (0x80233A98)
// - 4: arwblocker_update (0x80233964)
// - 5: arwblocker_hitDetect (0x80233960)
// - 6: arwblocker_render (0x8023393C)
// - 7: arwblocker_free (0x80233938)
// - 8: arwblocker_func08 (0x80233930)
// - 9: arwblocker_getExtraSize (0x80233928)

// Helpers:
// - arwblocker_getBlockState (0x802338F0): installed in obj->funcBC by init;
//   returns block/collision state 1 when extra byte +0 is the active blocker
//   mode and extra byte +1 has not disabled it.

// Runtime shape:
// - init sets the object's yaw to 0x8000, derives pitch from object-def byte
//   +0x18, installs arwblocker_getBlockState as obj->funcBC, and copies
//   object-def byte +0x19 into extra byte +0 as the blocker mode.
// - update fades object alpha in as the player approaches, enables hits/model
//   display, and calls the Arwing level controller once to notify whether this
//   blocker uses mode 0 or mode 1.
