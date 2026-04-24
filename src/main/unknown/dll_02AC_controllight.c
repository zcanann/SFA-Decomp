// Non-built exploratory packet for the retail-backed ControlLight object family.
//
// Source evidence:
// - DLL 0x02AC is "ControlLight" in retail XML.
// - Object def 0x0554 ("LGTControlL") resolves to this family.
//
// Current EN descriptor:
// - gControlLightObjDescriptor @ 0x8032BB38
//
// Descriptor slots:
// - 0: controllight_initialise (0x80234DC4)
// - 1: controllight_release (0x80234DC0)
// - 3: controllight_init (0x80234D5C)
// - 4: controllight_update (0x80234C2C)
// - 5: controllight_hitDetect (0x80234C28)
// - 6: controllight_render (0x80234C24)
// - 7: controllight_free (0x80234C20)
// - 8: controllight_func08 (0x80234C18)
// - 9: controllight_getExtraSize (0x80234C10)
