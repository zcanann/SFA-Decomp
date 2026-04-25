/*
 * Exploratory class packet for the retail-backed ProjectileSwitch class family.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a class-level recovery packet for early file-boundary work.
 *
 * Class ID: 0x0051
 * Reference class name: ProjectileSwitch
 * Suggested packet name: ProjectileSwitch
 * Output path: src/main/unknown/classes/class_0051_projectileswitch.c
 * Retail placements: 89
 * Retail object defs: 3
 * DLL IDs: 0x00F9 0x00FA
 * Descriptor-backed DLL IDs: 0x00F9 0x00FA
 * Retail root placement widths: 9w
 *
 * Retail object defs:
 * - 0x0500 ProjectileS: dll=0x00F9, placements=59, widths=9w x59
 * - 0x0490 InvisibleHi: dll=0x00FA, placements=23, widths=9w x23
 * - 0x042C DRProjectil: dll=0x00F9, placements=7, widths=9w x7
 *
 * Descriptor slot maps:
 * - DLL 0x00F9: gProjectileSwitchObjDescriptor @ 0x80321C68 (slots=10, mask=1101111111)
 *   slot 00: 0x8017AE2C projectileswitch_initialise
 *   slot 01: 0x8017AE28 projectileswitch_release
 *   slot 03: 0x8017AC40 projectileswitch_init
 *   slot 04: 0x8017AB28 projectileswitch_update
 *   slot 05: 0x8017A95C projectileswitch_hitDetect
 *   slot 06: 0x8017A8D0 projectileswitch_render
 *   slot 07: 0x8017A8CC projectileswitch_free
 *   slot 08: 0x8017A89C projectileswitch_func08
 *   slot 09: 0x8017A894 projectileswitch_getExtraSize
 * - DLL 0x00FA: gInvisibleHitSwitchObjDescriptor @ 0x80321CA0 (slots=10, mask=0001100001)
 *   slot 03: 0x8017B064 invisiblehitswitch_init
 *   slot 04: 0x8017AE38 invisiblehitswitch_update
 *   slot 09: 0x8017AE30 invisiblehitswitch_getExtraSize
 */

#if 0
/*
 * Reference-only class packet enums. Verify against EN before promoting names into live code.
 */
enum class_0051_ProjectileSwitch_defs {
    PROJECTILESWITCH_PROJECTILES = 0x0500,
    PROJECTILESWITCH_INVISIBLEHI = 0x0490,
    PROJECTILESWITCH_DRPROJECTIL = 0x042C,
};
#endif
