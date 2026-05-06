// Non-built exploratory packet for the retail-backed WaterFlowWe object family.
//
// Source evidence:
// - DLL 0x02AE is "WaterFlowWe" in retail XML.
// - Object def 0x028E ("WaterFlowWe") resolves to this family.
//
// Current EN descriptor:
// - gWaterFlowWeObjDescriptor @ 0x8032BBA8
//
// Descriptor slots:
// - 0: waterflowwe_initialise (0x802356B4)
// - 1: waterflowwe_release (0x802356B0)
// - 3: waterflowwe_init (0x802355E8)
// - 4: waterflowwe_update (0x802354CC)
// - 5: waterflowwe_hitDetect (0x802354C8)
// - 6: waterflowwe_render (0x80235498)
// - 7: waterflowwe_free (0x80235480)
// - 8: waterflowwe_func08 (0x80235478)
// - 9: waterflowwe_getExtraSize (0x80235470)

// Helpers:
// - waterflowwe_calcCurrentVector (0x8023503C): samples nearby soft-body
//   foliage and type-0x50 actors to accumulate a smoothed X/Z current vector.

// Runtime shape:
// - init seeds model rotation from object-def bytes +0x18/+0x19/+0x1A, scales
//   the local current radius from byte +0x1B, enables the model env effect flag,
//   and starts the water animation phase.
// - update calls waterflowwe_calcCurrentVector, points the model along the
//   computed current, advances the shared water animation phases on the primary
//   instance, and drives the water material animation with the idle/current
//   variant selected by whether the vector is zero.
