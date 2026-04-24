/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x01D4
 * Suggested family name: WORLDAsteroids
 * Output path: src/main/unknown/dll_01D4_worldasteroids.c
 * EN descriptor: 0x8032A140 gWorldAsteroidsObjDescriptor
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x8020C5E8 worldasteroids_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x8020C5E4 worldasteroids_release stub=blr ref=release (stub)
 * - slot 03: 0x8020C44C worldasteroids_init ref=init
 * - slot 04: 0x8020C2C0 worldasteroids_update ref=update
 * - slot 05: 0x8020C2BC worldasteroids_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x8020C28C worldasteroids_render ref=render
 * - slot 07: 0x8020C288 worldasteroids_free stub=blr ref=free (stub)
 * - slot 08: 0x8020C280 worldasteroids_func08 stub=const 0
 * - slot 09: 0x8020C278 worldasteroids_getExtraSize stub=const 12 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: WORLDAsteroids
 */

#if 0
enum dll_01D4_WORLDAsteroids_slot {
    WORLDASTEROIDS_INITIALISE = 0,
    WORLDASTEROIDS_RELEASE = 1,
    WORLDASTEROIDS_INIT = 3,
    WORLDASTEROIDS_UPDATE = 4,
    WORLDASTEROIDS_HITDETECT = 5,
    WORLDASTEROIDS_RENDER = 6,
    WORLDASTEROIDS_FREE = 7,
    WORLDASTEROIDS_SLOT_08 = 8,
    WORLDASTEROIDS_GETEXTRASIZE = 9,
};
#endif
