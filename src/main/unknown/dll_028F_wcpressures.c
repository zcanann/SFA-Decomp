// Non-built exploratory packet for the retail-backed WCPressureS object family.
//
// Source evidence:
// - DLL 0x028F is "WCPressureS" in retail XML.
// - Object def 0x0128 ("WCPressureS") resolves to this family.
//
// Current EN descriptor:
// - gWCPressureSObjDescriptor @ 0x8032B1E8
//
// Runtime notes:
// - init copies object-def byte +0x19 into object byte +0xAD, clamps it against model
//   data, registers with object group 0x31, clears ten tracked tile/object slots in extra
//   +4..+0x28, and installs wcpressures_tileStateCallback at object +0xBC.
// - update scans nearby model children, tracks up to ten linked tiles, and raises a short
//   countdown when any tracked tile remains at its saved X/Z position.
// - the pressure state at extra byte +1 moves between lowered, rising, raised, and falling
//   states while object-def bit +0x1A stores the solved/raised state.
// - wcpressures_tileStateCallback handles external commands through byte +0x80: command 1
//   snapshots tracked tile X/Z positions and command 2 clears tracked slots, resets the
//   switch transform from the object definition, and clears the solved bit.
//
// Descriptor slots:
// - 0: wcpressures_initialise (0x802281C8)
// - 1: wcpressures_release (0x802281C4)
// - 3: wcpressures_init (0x802280A8)
// - 4: wcpressures_update (0x80227D60)
// - 5: wcpressures_hitDetect (0x80227D5C)
// - 6: wcpressures_render (0x80227D2C)
// - 7: wcpressures_free (0x80227D08)
// - 8: wcpressures_func08 (0x80227CDC)
// - 9: wcpressures_getExtraSize (0x80227CD4)
// - callback: wcpressures_tileStateCallback (0x80227BB8)
