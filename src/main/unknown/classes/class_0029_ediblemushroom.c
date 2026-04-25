/*
 * Exploratory class packet for the retail-backed edibleMushroom class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x0029
 * Reference class name: edibleMushroom
 * Suggested packet name: edibleMushroom
 * Output path: src/main/unknown/classes/class_0029_ediblemushroom.c
 * Retail placements: 180
 * Retail object defs: 3
 * DLL IDs: 0x01A7
 * Descriptor-backed DLL IDs: 0x01A7
 * Retail root placement widths: 8w
 *
 * Retail object defs:
 * - 0x04DF BlueMushroo: dll=0x01A7, placements=171, widths=8w x171
 * - 0x02B0 SH_whitemus: dll=0x01A7, placements=6, widths=8w x6
 * - 0x01D1 LINK_BlueMu: dll=0x01A7, placements=3, widths=8w x3
 *
 * Descriptor slot maps:
 * - DLL 0x01A7: gEdibleMushroomObjDescriptor @ 0x80326C14 (slots=10, mask=0001110101)
 *   slot 03: 0x801D1978 ediblemushroom_init
 *   slot 04: 0x801D16EC ediblemushroom_update
 *   slot 05: 0x801D15A0 ediblemushroom_hitDetect
 *   slot 07: 0x801D1564 ediblemushroom_free
 *   slot 09: 0x801D155C ediblemushroom_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_0029_edibleMushroom_defs {
    EDIBLEMUSHROOM_BLUEMUSHROO = 0x04DF,
    EDIBLEMUSHROOM_SH_WHITEMUS = 0x02B0,
    EDIBLEMUSHROOM_LINK_BLUEMU = 0x01D1,
};
#endif
