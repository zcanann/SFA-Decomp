// Non-built exploratory packet for the retail-backed CNThitObjec object family.
//
// Source evidence:
// - DLL 0x02B6 is "CNThitObjec" in retail XML.
// - Object defs 0x0310, 0x0311, and 0x043A resolve to this family:
//   CNThitObjec, CNTColideOb, and DR_TowerSwi.
//
// Current EN descriptor:
// - gCNThitObjecObjDescriptor @ 0x8032BF04
//
// Descriptor slots:
// - 0: cnthitobjec_initialise (0x80238F4C)
// - 1: cnthitobjec_release (0x80238F48)
// - 3: cnthitobjec_init (0x80238E34)
// - 4: cnthitobjec_update (0x80238D68)
// - 5: cnthitobjec_hitDetect (0x80238BC0)
// - 6: cnthitobjec_render (0x80238B78)
// - 7: cnthitobjec_free (0x80238B74)
// - 8: cnthitobjec_func08 (0x80238B6C)
// - 9: cnthitobjec_getExtraSize (0x80238B64)

// Helpers:
// - cnthitobjec_emitHitEvents (0x80238AB0): installed in obj->funcBC; emits the
//   effect/event ids listed in the hit context and returns false.

// Runtime shape:
// - init picks one of three hit-data profiles, arms object hits from switch
//   +0x20, optionally disables hits when completion switch +0x1E is already set,
//   and installs cnthitobjec_emitHitEvents.
// - hitDetect subtracts damage from the remaining hit count, plays hit feedback,
//   fires completion switch +0x1E at zero, and optionally emits a completion
//   effect.
// - update disables hits once completion switch +0x1E is set and re-arms from
//   switch +0x20 when idle.
