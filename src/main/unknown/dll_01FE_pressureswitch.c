// Non-built exploratory packet for the retail-backed PressureSwitch object family.
//
// Source evidence:
// - DLL 0x01FE is "PressureSwitch" in retail XML.
// - Object defs 0x040B ("ECSH_Pressu"), 0x00A2 ("CFPressureS"),
//   0x03A4 ("WM_Pressure"), and 0x0365 ("DFP_PuzzleP") resolve here.
// - Reference object parameters identify a pressed GameBit16 at offset 0x1C.
//
// Current EN descriptor:
// - gPressureSwitchObjDescriptor @ 0x803287F0
//
// Descriptor slots:
// - 0: pressureswitch_initialise (0x801F1BC4)
// - 1: pressureswitch_release (0x801F1BC0)
// - 3: pressureswitch_init (0x801F1ABC)
// - 4: pressureswitch_update (0x801F166C)
// - 5: pressureswitch_hitDetect (0x801F1668)
// - 6: pressureswitch_render (0x801F1638)
// - 7: pressureswitch_free (0x801F1634)
// - 8: pressureswitch_func08 (0x801F162C)
// - 9: pressureswitch_getExtraSize (0x801F1624)
