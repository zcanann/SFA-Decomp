// Non-built exploratory packet for the retail-backed Andross object family.
//
// Source evidence:
// - DLL 0x02BC is "Andross" in retail XML.
// - Object def 0x0230 ("Andross") resolves to this family.
//
// Current EN descriptor:
// - gAndrossObjDescriptor @ 0x8032C0F4
//
// Descriptor slots:
// - 3: andross_init (0x8023EF3C)
// - 4: andross_update (0x8023AA64)
// - 5: andross_hitDetect (0x8023AA60)
// - 6: andross_render (0x8023AA3C)
// - 7: andross_free (0x8023AA18)
// - 8: andross_func08 (0x8023AA10)
// - 9: andross_getExtraSize (0x8023AA08)

// Helpers:
// - andross_setPartSignal (0x8023A688): sets signal bits in the linked Andross
//   extra byte +0xAD. Called by hands/brain when child parts complete attacks,
//   take fatal damage, or need to notify the main boss state machine.
// - andross_updateModelAlpha (0x8023A974): installed in obj->funcBC by init;
//   refreshes per-model alpha data from the Andross extra alpha scalar.

// Runtime shape:
// - init caches spawn/origin coordinates from object-def fields, seeds phase and
//   animation timers, installs andross_updateModelAlpha, disables child model
//   part visibility, clears switch 0x0D, and enables the main camera/HUD state.
