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

// Helpers:
// - timer_addDuration (0x8023852C): external callers can add ticks while the
//   timer is active; UI mode also refreshes the displayed remaining time.
// - timer_clearManualFlags (0x802385C8): clears the forced-start and expired
//   flags in extra byte +0x0D.
// - timer_forceStart (0x802385EC): sets the forced-start flag so update starts
//   without waiting for the input switch.
// - timer_isEffectMode (0x80238604): returns true for timer mode 2.
// - timer_hasExpired (0x8023861C): returns the expired flag from extra byte
//   +0x0D.

// Runtime shape:
// - extra +0x00: countdown timer storage used by the engine timer helpers.
// - extra +0x04: optional effect handle for mode 2.
// - extra +0x08: effect spin accumulator.
// - extra +0x0C: timer mode from object-def byte +0x19.
// - update starts from switch +0x20 or forced-start, runs for object-def seconds
//   +0x1A, fires switch +0x1E on expiry, and tears down UI/effect state.
