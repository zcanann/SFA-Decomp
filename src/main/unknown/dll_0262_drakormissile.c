/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0262
 * Suggested family name: DrakorMissile
 * Output path: src/main/unknown/dll_0262_drakormissile.c
 * EN descriptor: 0x8032A6E8 gDrakorMissileObjDescriptor
 *
 * Retail object defs:
 * - 0x007A DrakorMissi: def=0x070F, class=0x0061, placements=0
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x80218B20 drakormissile_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x80218B1C drakormissile_release stub=blr ref=release (stub)
 * - slot 03: 0x802189C0 drakormissile_init ref=init
 * - slot 04: 0x802185CC drakormissile_update ref=update
 * - slot 05: 0x802185C8 drakormissile_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x80218474 drakormissile_render ref=render
 * - slot 07: 0x8021841C drakormissile_free ref=free
 * - slot 08: 0x80218414 drakormissile_func08 stub=const 2
 * - slot 09: 0x8021840C drakormissile_getExtraSize stub=const 56 ref=getExtraSize (stub)
 * - slot 10: 0x802183F4 drakormissile_setScale ref=setScale
 * - slot 11: 0x802180C8 drakormissile_func0B ref=slot0B
 * - slot 12: 0x80217F40 drakormissile_modelMtxFn ref=modelMtxFn
 * - slot 13: 0x80217F24 drakormissile_render2 ref=render2
 *
 * Reference-only hints:
 * - reference DLL name: DrakorMissile
 */

#if 0
enum dll_0262_DrakorMissile_slot {
    DRAKORMISSILE_INITIALISE = 0,
    DRAKORMISSILE_RELEASE = 1,
    DRAKORMISSILE_INIT = 3,
    DRAKORMISSILE_UPDATE = 4,
    DRAKORMISSILE_HITDETECT = 5,
    DRAKORMISSILE_RENDER = 6,
    DRAKORMISSILE_FREE = 7,
    DRAKORMISSILE_SLOT_08 = 8,
    DRAKORMISSILE_GETEXTRASIZE = 9,
    DRAKORMISSILE_SETSCALE = 10,
    DRAKORMISSILE_SLOT_0B = 11,
    DRAKORMISSILE_MODELMTXFN = 12,
    DRAKORMISSILE_RENDER2 = 13,
};
#endif
