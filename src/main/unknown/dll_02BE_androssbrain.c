// Non-built exploratory packet for the retail-backed AndrossBrain object family.
//
// Source evidence:
// - DLL 0x02BE is "AndrossBrain" in retail XML.
// - Object def 0x0233 ("AndrossBrai") resolves to this family.
//
// Current EN descriptor:
// - gAndrossBrainObjDescriptor @ 0x8032C2F0
//
// Descriptor slots:
// - 3: androssbrain_init (0x8023FFE0)
// - 4: androssbrain_update (0x8023FD38)
// - 5: androssbrain_hitDetect (0x8023FD34)
// - 6: androssbrain_render (0x8023FD10)
// - 7: androssbrain_free (0x8023FD0C)
// - 8: androssbrain_func08 (0x8023FD04)
// - 9: androssbrain_getExtraSize (0x8023FCFC)

// Runtime shape:
// - update uses andross_setPartSignal to notify the linked Andross object when
//   the brain completes scripted states or reaches damage thresholds.
