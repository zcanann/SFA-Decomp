/*
 * Exploratory class packet for the retail-backed checkpoint4 class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x0005
 * Reference class name: checkpoint4
 * Suggested packet name: checkpoint4
 * Output path: src/main/unknown/classes/class_0005_checkpoint4.c
 * Retail placements: 181
 * Retail object defs: 1
 * DLL IDs: 0x00E8
 * Descriptor-backed DLL IDs: 0x00E8
 * Retail root placement widths: 16w
 *
 * Retail object defs:
 * - 0x0492 checkpoint4: dll=0x00E8, placements=181, widths=16w x181
 *
 * Descriptor slot maps:
 * - DLL 0x00E8: gCheckpoint4ObjDescriptor @ 0x803217C0 (slots=11, mask=11011111111)
 *   slot 00: 0x80172054 checkpoint4_initialise
 *   slot 01: 0x80172050 checkpoint4_release
 *   slot 03: 0x80171ED0 checkpoint4_init
 *   slot 04: 0x80171ECC checkpoint4_update
 *   slot 05: 0x80171EC8 checkpoint4_hitDetect
 *   slot 06: 0x80171EA4 checkpoint4_render
 *   slot 07: 0x80171EA0 checkpoint4_free
 *   slot 08: 0x80171E98 checkpoint4_func08
 *   slot 09: 0x80171E90 checkpoint4_getExtraSize
 *   slot 10: 0x80171E8C checkpoint4_setScale
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_0005_checkpoint4_defs {
    CHECKPOINT4_CHECKPOINT4 = 0x0492,
};
#endif
