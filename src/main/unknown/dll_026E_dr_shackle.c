/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x026E
 * Suggested family name: DR_Shackle
 * Output path: src/main/unknown/dll_026E_dr_shackle.c
 * EN descriptor: 0x8032A9A8 gDrShackleObjDescriptor
 *
 * Retail object defs:
 * - 0x045D DR_Shackle: def=0x047C, class=0x0030, placements=unknown
 * - 0x045E DR_BigShack: def=0x047D, class=0x0030, placements=unknown
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x8021B354 drshackle_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x8021B350 drshackle_release stub=blr ref=release (stub)
 * - slot 03: 0x8021B28C drshackle_init ref=init
 * - slot 04: 0x8021B178 drshackle_update ref=update
 * - slot 05: 0x8021B0BC drshackle_hitDetect ref=hitDetect
 * - slot 06: 0x8021B008 drshackle_render ref=render
 * - slot 07: 0x8021AFE4 drshackle_free ref=free
 * - slot 08: 0x8021AFDC drshackle_func08 stub=const 0
 * - slot 09: 0x8021AFD4 drshackle_getExtraSize stub=const 32 ref=getExtraSize (stub)
 * - slot 10: 0x8021AD84 drshackle_setScale ref=setScale
 * - slot 11: 0x8021AD74 drshackle_func0B ref=slot0B
 *
 * Reference-only hints:
 * - reference DLL name: DR_Shackle
 */

#if 0
enum dll_026E_DR_Shackle_slot {
    DRSHACKLE_INITIALISE = 0,
    DRSHACKLE_RELEASE = 1,
    DRSHACKLE_INIT = 3,
    DRSHACKLE_UPDATE = 4,
    DRSHACKLE_HITDETECT = 5,
    DRSHACKLE_RENDER = 6,
    DRSHACKLE_FREE = 7,
    DRSHACKLE_SLOT_08 = 8,
    DRSHACKLE_GETEXTRASIZE = 9,
    DRSHACKLE_SETSCALE = 10,
    DRSHACKLE_SLOT_0B = 11,
};
#endif
