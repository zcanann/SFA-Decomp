// Non-built exploratory packet for the retail-backed ARWProximit object family.
//
// Source evidence:
// - DLL 0x02A7 is "ARWProximit" in retail XML.
// - Object defs 0x0541 and 0x0542 ("ARWProximit" and "ARWTimedMin")
//   resolve to this family.
//
// Current EN descriptor:
// - gARWProximitObjDescriptor @ 0x8032B920
//
// Descriptor slots:
// - 0: arwproximit_initialise (0x802338EC)
// - 1: arwproximit_release (0x802338E8)
// - 3: arwproximit_init (0x802337F8)
// - 4: arwproximit_update (0x80233284)
// - 5: arwproximit_hitDetect (0x80233280)
// - 6: arwproximit_render (0x80233200)
// - 7: arwproximit_free (0x802331C0)
// - 8: arwproximit_func08 (0x802331B8)
// - 9: arwproximit_getExtraSize (0x802331B0)

// Runtime shape:
// - extra +0x00: randomized yaw seed used while the mine is armed.
// - extra +0x04: particle/effect handle, faded out during explode/cleanup paths.
// - extra +0x0C/+0x10: short countdown timers for arming/explosion transitions.
// - extra +0x14: behavior variant from object-def byte +0x31.
// - extra +0x18: state byte. 0 waits for player proximity, 1 arms and fades in,
//   2 waits on an arming timer, 3 waits on the detonation timer, 4 cleans up.
//
// update:
// - variant 1 can clear itself when the player comes within the close warning
//   radius and plays message/sfx 0x0B.
// - state 0 creates a green mine particle effect when the player enters the
//   outer radius, hides object collision/model state, and enters state 1.
// - states 1/2 drift object yaw/pitch toward the randomized seed, check direct
//   hits, and detonate or clear the effect handle on collision.
// - state 2 flips the effect red after the inner radius is crossed, starts the
//   detonation timer, and can play variant-specific warning sfx 0x0C/0x0F.
// - state 3 detonates after its timer, emits the explosion, enables damage, and
//   enters state 4.
