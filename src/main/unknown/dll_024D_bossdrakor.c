/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x024D
 * Suggested family name: BossDrakor
 * Output path: src/main/unknown/dll_024D_bossdrakor.c
 * EN descriptor: 0x8032A038 gBossDrakorObjDescriptor
 *
 * Retail object defs:
 * - 0x0079 BossDrakor: def=0x02AB, class=0x0030, placements=0
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x8020BAB0 bossdrakor_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x8020BAAC bossdrakor_release stub=blr ref=release (stub)
 * - slot 03: 0x8020B980 bossdrakor_init ref=init
 * - slot 04: 0x8020B0F0 bossdrakor_update ref=update
 * - slot 05: 0x8020AEFC bossdrakor_hitDetect ref=hitDetect
 * - slot 06: 0x8020ADC8 bossdrakor_render ref=render
 * - slot 07: 0x8020AD50 bossdrakor_free ref=free
 * - slot 09: 0x8020AD48 bossdrakor_getExtraSize stub=const 420 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: BossDrakor
 */

#if 0
enum dll_024D_BossDrakor_slot {
    BOSSDRAKOR_INITIALISE = 0,
    BOSSDRAKOR_RELEASE = 1,
    BOSSDRAKOR_INIT = 3,
    BOSSDRAKOR_UPDATE = 4,
    BOSSDRAKOR_HITDETECT = 5,
    BOSSDRAKOR_RENDER = 6,
    BOSSDRAKOR_FREE = 7,
    BOSSDRAKOR_GETEXTRASIZE = 9,
};
#endif
