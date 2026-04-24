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
