/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0261
 * Suggested family name: DR_LaserCannon
 * Output path: src/main/unknown/dll_0261_dr_lasercannon.c
 * EN descriptor: 0x8032A6B0 gDrLaserCannonObjDescriptor
 *
 * Retail object defs:
 * - 0x043F DR_LaserCan: def=0x0417, class=0x0030, placements=5
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x80217F20 drlasercannon_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x80217F1C drlasercannon_release stub=blr ref=release (stub)
 * - slot 03: 0x80217D38 drlasercannon_init ref=init
 * - slot 04: 0x80217630 drlasercannon_update ref=update
 * - slot 05: 0x80217444 drlasercannon_hitDetect ref=hitDetect
 * - slot 06: 0x802173D0 drlasercannon_render ref=render
 * - slot 07: 0x80217364 drlasercannon_free ref=free
 * - slot 08: 0x8021735C drlasercannon_func08 stub=const 0
 * - slot 09: 0x80217354 drlasercannon_getExtraSize stub=const 428 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: DR_LaserCannon
 */

#if 0
enum dll_0261_DR_LaserCannon_slot {
    DRLASERCANNON_INITIALISE = 0,
    DRLASERCANNON_RELEASE = 1,
    DRLASERCANNON_INIT = 3,
    DRLASERCANNON_UPDATE = 4,
    DRLASERCANNON_HITDETECT = 5,
    DRLASERCANNON_RENDER = 6,
    DRLASERCANNON_FREE = 7,
    DRLASERCANNON_SLOT_08 = 8,
    DRLASERCANNON_GETEXTRASIZE = 9,
};
#endif
