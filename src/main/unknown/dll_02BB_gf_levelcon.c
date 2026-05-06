// Non-built exploratory packet for the retail-backed GF_LevelCon object family.
//
// Source evidence:
// - DLL 0x02BB is "GF_LevelCon" in retail XML.
// - Object def 0x0249 ("GF_LevelCon") resolves to this family.
//
// Current EN descriptor:
// - gGF_LevelConObjDescriptor @ 0x8032C020
//
// Descriptor slots:
// - 0: gf_levelcon_initialise (0x80239DD4)
// - 1: gf_levelcon_release (0x80239DD0)
// - 3: gf_levelcon_init (0x80239D90)
// - 4: gf_levelcon_update (0x80239D80)
// - 5: gf_levelcon_hitDetect (0x80239D7C)
// - 6: gf_levelcon_render (0x80239D4C)
// - 7: gf_levelcon_free (0x80239D28)
// - 8: gf_levelcon_func08 (0x80239D20)
// - 9: gf_levelcon_getExtraSize (0x80239D18)

// Helpers:
// - gf_levelcon_findLinkedObjects (0x80239858): scans the live object list and
//   caches three linked scene/light objects by object ids 0x477E3, 0x4A946,
//   and 0x4A947.
// - gf_levelcon_handleScriptEvents (0x80239934): scripted event callback for
//   the GF level controller; dispatches event ids for colored full-screen
//   effects, pointlight enable/disable, camera/HUD setup, music/scene actions,
//   and timed rumble/audio feedback.

// Runtime shape:
// - free re-enables the global state disabled by init.
// - render draws a translucent colored effect while visible.
// - init disables a global state flag and starts a timed controller action.
// - extra +0x00/+0x04/+0x08 cache linked object pointers; extra +0x0C is a
//   countdown for repeating sfx 0x476 after scripted event 8.
