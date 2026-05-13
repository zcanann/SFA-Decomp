/*
 * Exploratory class packet for the retail-backed StaticCamera class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x0012
 * Reference class name: StaticCamera
 * Suggested packet name: StaticCamera
 * Output path: src/main/unknown/classes/class_0012_staticcamera.c
 * Retail placements: 48
 * Retail object defs: 1
 * DLL IDs: 0x025A
 * Descriptor-backed DLL IDs: 0x025A
 * Retail root placement widths: 9w
 *
 * Retail object defs:
 * - 0x04D3 StaticCamer: dll=0x025A, placements=48, widths=9w x48
 *
 * Descriptor slot maps:
 * - DLL 0x025A: lbl_80320658 @ 0x80320658 (slots=10, mask=1101111111)
 *   slot 00: 0x8016B998 StaticCamera_initialise
 *   slot 01: 0x8016B994 StaticCamera_release
 *   slot 03: 0x8016B904 StaticCamera_init
 *   slot 04: 0x8016B900 StaticCamera_update
 *   slot 05: 0x8016B8FC StaticCamera_hitDetect
 *   slot 06: 0x8016B8CC StaticCamera_render
 *   slot 07: 0x8016B8A8 StaticCamera_free
 *   slot 08: 0x8016B8A0 StaticCamera_func08
 *   slot 09: 0x8016B898 StaticCamera_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_0012_StaticCamera_defs {
    STATICCAMERA_STATICCAMER = 0x04D3,
};
#endif
