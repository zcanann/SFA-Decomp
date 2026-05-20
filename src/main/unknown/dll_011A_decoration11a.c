// Non-built exploratory packet for the retail-backed Decoration11A object family.
//
// Source evidence:
// - DLL 0x011A is "Decoration11A" in retail XML.
//
// Current EN descriptor:
// - gDecoration11AObjDescriptor @ 0x803219F0
//
// Descriptor slots:
// - 3: decoration11a_init (0x80188814)
// - 4: decoration11a_update (0x80188794)
// - 5: decoration11a_hitDetect (0x801885C0)
// - 6: decoration11a_render (0x80188590)
// - 7: decoration11a_free (0x8018858C)
// - 9: decoration11a_getExtraSize (0x80188584)

// EN callback behavior:
// - decoration11a_free and decoration11a_update are empty callbacks.
// - decoration11a_getExtraSize returns 0x1C, matching the debris bounds state below.
// - decoration11a_render only calls objRenderFn_8003b8f4 when visible.
// - decoration11a_init copies placement bytes 0x18, 0x19, and 0x1A into the
//   object's first three s16 fields shifted left by eight bits.
// - placement byte 0x1B is a scale; when present it is divided by 128.0f,
//   clamped away from zero to 1.0f, then multiplied by the model scale field.

// Hit-detect is only active for the DragRock debris remap IDs:
// - 0x07A1: DRDebrisGir, retail def 0x007F, model 0x035C
// - 0x07A2: DRDebrisPip, retail def 0x0081, model 0x035D
// - 0x07A3: DRDebrisPip, retail def 0x0082, model 0x035E
//
// For those objects, init derives model bounds into object state:
// - state+0x00..0x08: one Vec3 bound corner
// - state+0x0C..0x14: opposing Vec3 bound corner
// - state+0x18: radius from the larger scaled bound-vector length
//
// decoration11a_hitDetect walks ObjGroup 2 candidates, transforms each
// candidate point into this object's local space, measures squared distance
// outside the stored bounds, and compares it with the candidate half-height
// squared. Passing candidates get this object stored at candidateState+0x50
// and candidateState+0xAD set to 1.
