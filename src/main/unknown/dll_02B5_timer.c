// Non-built exploratory packet for the retail-backed Timer object family.
//
// Source evidence:
// - DLL 0x02B5 is "Timer" in retail XML.
// - Object defs 0x0084 and 0x030F ("Timer" and "CNTstopwatc")
//   resolve to this family.
//
// Current EN descriptor:
// - gTimerObjDescriptor @ 0x8032BEC0
//
// Descriptor slots:
// - 3: timer_init (0x80238A1C)
// - 4: timer_update (0x80238710)
// - 6: timer_render (0x8023867C)
// - 7: timer_free (0x80238634)
// - 9: timer_getExtraSize (0x8023862C)
