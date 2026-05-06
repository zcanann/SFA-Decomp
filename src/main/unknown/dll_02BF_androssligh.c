// Non-built exploratory packet for the retail-backed AndrossLigh object family.
//
// Source evidence:
// - DLL 0x02BF is "AndrossLigh" in retail XML.
// - Object def 0x0234 ("AndrossLigh") resolves to this family.
//
// Current EN descriptor:
// - gAndrossLighObjDescriptor @ 0x8032C328
//
// Descriptor slots:
// - 3: androssligh_init (0x80240348)
// - 4: androssligh_update (0x80240294)
// - 5: androssligh_hitDetect (0x80240290)
// - 6: androssligh_render (0x80240260)
// - 7: androssligh_free (0x8024025C)
// - 8: androssligh_func08 (0x80240254)
// - 9: androssligh_getExtraSize (0x8024024C)

// Helpers:
// - androssligh_updateBeam (0x80240010): creates/advances the beam effect
//   between two offsets from the tracked Andross light object.
// - androssligh_setState (0x80240218): state setter used by AndrossBrain to
//   command the light object while preserving the terminal state unless forced.

// Runtime shape:
// - update finds and tracks the linked Andross light anchor object id 0x47DD9,
//   copies its position, and runs androssligh_updateBeam in active state 1.
// - render advances the active beam handle when present.
