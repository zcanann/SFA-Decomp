// Non-built exploratory packet for the retail-backed PointLight object family.
//
// Source evidence:
// - DLL 0x02A9 is "PointLight" in retail XML.
// - Object defs 0x0106 and 0x0551 ("CF_WallTorc" and "LGTPointLig")
//   resolve to this family.
//
// Current EN descriptor:
// - gPointLightObjDescriptor @ 0x8032B990
//
// Descriptor slots:
// - 0: pointlight_initialise (0x80234048)
// - 1: pointlight_release (0x80234044)
// - 3: pointlight_init (0x80233D90)
// - 4: pointlight_update (0x80233BE4)
// - 5: pointlight_hitDetect (0x80233BE0)
// - 6: pointlight_render (0x80233B98)
// - 7: pointlight_free (0x80233B50)
// - 8: pointlight_func08 (0x80233B48)
// - 9: pointlight_getExtraSize (0x80233B40)

// Helpers:
// - pointlight_setEffectState (0x80233B0C): called by Arwing level control and
//   cutscene/script code to forward a 0/1 state into the pointlight particle
//   effect handle stored at extra +0.

// Runtime shape:
// - free removes the active pointlight effect handle and unregisters the object
//   from the type-0x35 pointlight lookup list.
// - render refreshes the backing light/effect when the handle is live and the
//   effect object is currently active.
// - update tracks object yaw/pitch against the backing light, toggles the
//   effect state from an object-def bit, and optionally inherits color from
//   runtime lighting.
// - init creates the effect/light handle, applies scale, primary/secondary
//   colors, angle/falloff, flicker/pulse parameters, hit activation mode, and
//   registers the object in the type-0x35 lookup list.
