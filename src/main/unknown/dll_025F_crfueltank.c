/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x025F
 * Suggested family name: CRFuelTank
 * Output path: src/main/unknown/dll_025F_crfueltank.c
 * EN descriptor: 0x8032A468 gCrFuelTankObjDescriptor
 *
 * Retail object defs:
 * - 0x0109 CRFuelTank: def=0x057F, class=0x0030, placements=unknown
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x802110F4 crfueltank_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x802110F0 crfueltank_release stub=blr ref=release (stub)
 * - slot 03: 0x80211034 crfueltank_init ref=init
 * - slot 04: 0x80210F58 crfueltank_update ref=update
 * - slot 05: 0x80210EA4 crfueltank_hitDetect ref=hitDetect
 * - slot 06: 0x80210EA0 crfueltank_render stub=blr ref=render (stub)
 * - slot 07: 0x80210E9C crfueltank_free stub=blr ref=free (stub)
 * - slot 08: 0x80210E94 crfueltank_func08 stub=const 0
 * - slot 09: 0x80210E8C crfueltank_getExtraSize stub=const 16 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: CRFuelTank
 */

#if 0
enum dll_025F_CRFuelTank_slot {
    CRFUELTANK_INITIALISE = 0,
    CRFUELTANK_RELEASE = 1,
    CRFUELTANK_INIT = 3,
    CRFUELTANK_UPDATE = 4,
    CRFUELTANK_HITDETECT = 5,
    CRFUELTANK_RENDER = 6,
    CRFUELTANK_FREE = 7,
    CRFUELTANK_SLOT_08 = 8,
    CRFUELTANK_GETEXTRASIZE = 9,
};
#endif
