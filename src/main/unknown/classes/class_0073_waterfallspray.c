/*
 * Exploratory class packet for the retail-backed WaterFallSpray class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x0073
 * Reference class name: WaterFallSpray
 * Suggested packet name: WaterFallSpray
 * Output path: src/main/unknown/classes/class_0073_waterfallspray.c
 * Retail placements: 53
 * Retail object defs: 1
 * DLL IDs: 0x0132
 * Descriptor-backed DLL IDs: 0x0132
 * Retail root placement widths: 10w
 *
 * Retail object defs:
 * - 0x05A9 WaterFallSp: dll=0x0132, placements=53, widths=10w x53
 *
 * Descriptor slot maps:
 * - DLL 0x0132: gWaterFallSprayObjDescriptor @ 0x803230C0 (slots=10, mask=0001101101)
 *   slot 03: 0x8019866C waterfallspray_init
 *   slot 04: 0x80198384 waterfallspray_update
 *   slot 06: 0x80198380 waterfallspray_render
 *   slot 07: 0x80198350 waterfallspray_free
 *   slot 09: 0x80198324 waterfallspray_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_0073_WaterFallSpray_defs {
    WATERFALLSPRAY_WATERFALLSP = 0x05A9,
};
#endif
