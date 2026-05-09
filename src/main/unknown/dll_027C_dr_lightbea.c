// Non-built exploratory packet for the retail-backed DR_LightBea object family.
//
// Source evidence:
// - DLL 0x027C is "DR_LightBea" in retail XML.
// - Object def 0x0478 ("DR_LightBea") resolves to this family.
//
// Current EN descriptor:
// - gDrLightBeaObjDescriptor @ 0x8032AD30
//
// Runtime notes:
// - extra +0 stores the active beam/effect handle freed through mm_free.
// - extra flag bit 7 mirrors object-def +0x20; render creates the beam when the bit is set.
// - object-def byte +0x19 optionally redirects the beam endpoint through fn_80114184;
//   otherwise it tracks the player position with a Y offset.
// - extra flag bit 6 marks a self-removal request after a beam expires when object-def +0x14 is -1.
//
// Descriptor slots:
// - 0: drlightbea_initialise (0x80220ACC)
// - 1: drlightbea_release (0x80220AC8)
// - 3: drlightbea_init (0x80220AA0)
// - 4: drlightbea_update (0x80220A6C)
// - 5: drlightbea_hitDetect (0x80220A68)
// - 6: drlightbea_render (0x80220858)
// - 7: drlightbea_free (0x80220818)
// - 8: drlightbea_func08 (0x80220810)
// - 9: drlightbea_getExtraSize (0x80220808)
