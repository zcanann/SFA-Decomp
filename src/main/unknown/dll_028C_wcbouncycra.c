// Non-built exploratory packet for the retail-backed WCBouncyCra object family.
//
// Source evidence:
// - DLL 0x028C is "WCBouncyCra" in retail XML.
// - Object def 0x011B ("WCBouncyCra") resolves to this family.
//
// Current EN descriptor:
// - gWCBouncyCraObjDescriptor @ 0x8032AF78
//
// Runtime notes:
// - init stores the home Y position from object-def +0x0C into extra +0 and starts
//   a 0x28-frame cooldown at extra +8.
// - update waits for the cooldown, checks object group 3 for a nearby object, then applies
//   an upward velocity and enters a bounce simulation with damped rebounds.
// - extra byte +0x0A is the active/bouncing flag; extra byte +0x0B counts rebounds and
//   returns the crate to rest after more than 10 bounces.
//
// Descriptor slots:
// - 0: wcbouncycra_initialise (0x802242A4)
// - 1: wcbouncycra_release (0x802242A0)
// - 3: wcbouncycra_init (0x80224288)
// - 4: wcbouncycra_update (0x802240D4)
// - 5: wcbouncycra_hitDetect (0x802240D0)
// - 6: wcbouncycra_render (0x802240A0)
// - 7: wcbouncycra_free (0x8022409C)
// - 8: wcbouncycra_func08 (0x80224094)
// - 9: wcbouncycra_getExtraSize (0x8022408C)
