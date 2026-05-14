/*
 * Non-built exploratory packet for the retail-backed StaticCamera object family.
 *
 * Source evidence:
 * - DLL 0x025A is "StaticCamera" in retail XML.
 * - Object def 0x04D3 ("StaticCamer") resolves here.
 *
 * Current EN descriptor:
 * - gStaticCameraObjDescriptor @ 0x80320658
 *
 * Descriptor slots:
 * - 0: StaticCamera_initialise (0x8016B998)
 * - 1: StaticCamera_release (0x8016B994)
 * - 3: StaticCamera_init (0x8016B904)
 * - 4: StaticCamera_update (0x8016B900)
 * - 5: StaticCamera_hitDetect (0x8016B8FC)
 * - 6: StaticCamera_render (0x8016B8CC)
 * - 7: StaticCamera_free (0x8016B8A8)
 * - 8: StaticCamera_func08 (0x8016B8A0)
 * - 9: StaticCamera_getExtraSize (0x8016B898)
 *
 * Reference-only objparam fields:
 * - 0x18: id (u8)
 * - 0x1A: fov (u8)
 * - 0x1B: flags (u8)
 * - 0x1C: rotX (s16)
 * - 0x1E: rotY (s16)
 * - 0x20: rotZ (s16)
 */
