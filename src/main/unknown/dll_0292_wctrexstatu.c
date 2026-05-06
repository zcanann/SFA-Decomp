// Non-built exploratory packet for the retail-backed WCTrexStatu object family.
//
// Source evidence:
// - DLL 0x0292 is "WCTrexStatu" in retail XML.
// - Object def 0x012B ("WCTrexStatu") resolves to this family.
//
// Current EN descriptor:
// - gWCTrexStatuObjDescriptor @ 0x8032B230
//
// Runtime notes:
// - init installs wctrexstatu_interactCallback at object +0xBC, copies object-def byte
//   +0x19 into object byte +0xAD, clamps it against model data, and seeds model variant
//   state from object-def byte +0x18.
// - if object-def bit +0x1E is already raised, init writes interaction result 0x100 and
//   marks object +0xF4 as active/triggered.
// - hitDetect fires effect/sound 0x73F or 0x740 depending on object byte +0xAD, gated by
//   object +0xF4 and a nearby-object query.
// - wctrexstatu_interactCallback scans the interaction payload for command byte 1, writes
//   result 0x100, marks the statue triggered, and clears the current actor context.
//
// Descriptor slots:
// - 0: wctrexstatu_initialise (0x80228474)
// - 1: wctrexstatu_release (0x80228470)
// - 3: wctrexstatu_init (0x80228378)
// - 4: wctrexstatu_update (0x80228374)
// - 5: wctrexstatu_hitDetect (0x802282C0)
// - 6: wctrexstatu_render (0x80228290)
// - 7: wctrexstatu_free (0x8022828C)
// - 8: wctrexstatu_func08 (0x8022825C)
// - 9: wctrexstatu_getExtraSize (0x80228254)
// - callback: wctrexstatu_interactCallback (0x802281CC)
