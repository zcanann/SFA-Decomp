/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x026B
 * Suggested family name: DR_Chimmey
 * Output path: src/main/unknown/dll_026B_dr_chimmey.c
 * EN descriptor: 0x8032A930 gDrChimmeyObjDescriptor
 *
 * Retail object defs:
 * - 0x0455 DR_Chimmey: def=0x0470, class=0x0030, placements=unknown
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 03: 0x8021A5D8 drchimmey_init ref=init
 * - slot 04: 0x8021A490 drchimmey_update ref=update
 * - slot 06: 0x8021A460 drchimmey_render ref=render
 * - slot 09: 0x8021A458 drchimmey_getExtraSize stub=const 24 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: DR_Chimmey
 */

#if 0
enum dll_026B_DR_Chimmey_slot {
    DRCHIMMEY_INIT = 3,
    DRCHIMMEY_UPDATE = 4,
    DRCHIMMEY_RENDER = 6,
    DRCHIMMEY_GETEXTRASIZE = 9,
};
#endif
