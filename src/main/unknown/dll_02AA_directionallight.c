// Non-built exploratory packet for the retail-backed DirectionalLight object family.
//
// Source evidence:
// - DLL 0x02AA is "DirectionalLight" in retail XML.
// - Object def 0x0552 ("LGTDirectio") resolves to this family.
//
// Current EN descriptor:
// - gDirectionalLightObjDescriptor @ 0x8032B9C8
//
// Descriptor slots:
// - 0: directionallight_initialise (0x80234744)
// - 1: directionallight_release (0x80234740)
// - 3: directionallight_init (0x802345BC)
// - 4: directionallight_update (0x80234430)
// - 5: directionallight_hitDetect (0x8023442C)
// - 6: directionallight_render (0x80234408)
// - 7: directionallight_free (0x802343D8)
// - 8: directionallight_func08 (0x802343D0)
// - 9: directionallight_getExtraSize (0x802343C8)
