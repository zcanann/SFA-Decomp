// Non-built exploratory packet for the retail-backed WCTempleBri object family.
//
// Source evidence:
// - DLL 0x0297 is "WCTempleBri" in retail XML.
// - Object def 0x0143 ("WCTempleBri") resolves to this family.
//
// Current EN descriptor:
// - gWCTempleBriObjDescriptor @ 0x8032B398
//
// Runtime notes:
// - init copies object-def byte +0x18 into the primary angle field, clamps object byte
//   +0xAD, installs wctemplebri_interactCallback at object +0xBC, sorts the bridge part
//   offsets, and seeds the active/solved state from object-def bit +0x1E.
// - wctemplebri_updateModelWarp advances the model part spin counters and the extra
//   rotation angles used by both update and the interaction callback.
// - update bends the bridge model parts from the current warp radius, hides/deactivates
//   the object when inactive, and raises bit 0xEDB plus the object-def +0x1E solved bit
//   once the interaction path has activated.
// - wctemplebri_interactCallback accepts command byte 1 from the interaction payload,
//   marks the bridge active, fades object byte +0x36 toward zero, and suppresses payload
//   interaction/collision flags while the bridge deformation is handled.
//
// Descriptor slots:
// - 0: wctemplebri_initialise (0x8022A294)
// - 1: wctemplebri_release (0x8022A290)
// - 3: wctemplebri_init (0x8022A084)
// - 4: wctemplebri_update (0x80229DC4)
// - 5: wctemplebri_hitDetect (0x80229DC0)
// - 6: wctemplebri_render (0x80229D7C)
// - 7: wctemplebri_free (0x80229D78)
// - 8: wctemplebri_func08 (0x80229D48)
// - 9: wctemplebri_getExtraSize (0x80229D40)
// - internal: wctemplebri_updateModelWarp (0x8022999C)
// - callback: wctemplebri_interactCallback (0x80229AAC)
