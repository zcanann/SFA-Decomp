/*
 * Exploratory class packet for the retail-backed enemyMushroom class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x002A
 * Reference class name: enemyMushroom
 * Suggested packet name: enemyMushroom
 * Output path: src/main/unknown/classes/class_002A_enemymushroom.c
 * Retail placements: 36
 * Retail object defs: 1
 * DLL IDs: 0x01A8
 * Descriptor-backed DLL IDs: 0x01A8
 * Retail root placement widths: 9w
 *
 * Retail object defs:
 * - 0x02B1 SH_killermu: dll=0x01A8, placements=36, widths=9w x36
 *
 * Descriptor slot maps:
 * - DLL 0x01A8: gEnemyMushroomObjDescriptor @ 0x80326CBC (slots=10, mask=1101111111)
 *   slot 00: 0x801D2868 enemymushroom_initialise
 *   slot 01: 0x801D2864 enemymushroom_release
 *   slot 03: 0x801D27B8 enemymushroom_init
 *   slot 04: 0x801D1E24 enemymushroom_update
 *   slot 05: 0x801D1E20 enemymushroom_hitDetect
 *   slot 06: 0x801D1DBC enemymushroom_render
 *   slot 07: 0x801D1D74 enemymushroom_free
 *   slot 08: 0x801D1D60 enemymushroom_func08
 *   slot 09: 0x801D1D58 enemymushroom_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_002A_enemyMushroom_defs {
    ENEMYMUSHROOM_SH_KILLERMU = 0x02B1,
};
#endif
