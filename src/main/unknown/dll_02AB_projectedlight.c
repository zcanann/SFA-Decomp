// Non-built exploratory packet for the retail-backed ProjectedLight object family.
//
// Source evidence:
// - DLL 0x02AB is "ProjectedLight" in retail XML.
// - Object def 0x0553 ("LGTProjecte") resolves to this family.
//
// Current EN descriptor:
// - gProjectedLightObjDescriptor @ 0x8032BB00
//
// Descriptor slots:
// - 0: projectedlight_initialise (0x80234C0C)
// - 1: projectedlight_release (0x80234C08)
// - 3: projectedlight_init (0x802348A0)
// - 4: projectedlight_update (0x802347A8)
// - 5: projectedlight_hitDetect (0x802347A4)
// - 6: projectedlight_render (0x802347A0)
// - 7: projectedlight_free (0x80234758)
// - 8: projectedlight_func08 (0x80234750)
// - 9: projectedlight_getExtraSize (0x80234748)

// Runtime shape:
// - extra +0x00: projected light/effect handle.
// - extra +0x04: texture/model resource handle used by the projection.
// - free removes both the light/effect handle and the projection resource.
// - update eases yaw, pitch, and roll toward object-def angle fields.
// - init creates a projected light handle, applies color, clip/falloff,
//   texture/projection resource, rectangular or cone projection parameters,
//   layer flags, active state, pulse/flicker, and secondary color.
