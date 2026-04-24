/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x026C
 * Suggested family name: DR_CageWith
 * Output path: src/main/unknown/dll_026C_dr_cagewith.c
 * EN descriptor: 0x8032A968 gDrCageWithObjDescriptor
 *
 * Retail object defs:
 * - 0x0457 DR_CageWith: def=0x0472, class=0x0030, placements=unknown
 * - 0x0458 DR_CageNoRo: def=0x086A, class=0x0030, placements=unknown
 * - 0x0459 DR_CageRope: def=0x086B, class=0x0030, placements=unknown
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x8021ACE4 drcagewith_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x8021ACE0 drcagewith_release stub=blr ref=release (stub)
 * - slot 03: 0x8021AB8C drcagewith_init ref=init
 * - slot 04: 0x8021AB88 drcagewith_update stub=blr ref=update (stub)
 * - slot 05: 0x8021A80C drcagewith_hitDetect ref=hitDetect
 * - slot 06: 0x8021A714 drcagewith_render ref=render
 * - slot 07: 0x8021A694 drcagewith_free ref=free
 * - slot 08: 0x8021A68C drcagewith_func08 stub=const 0
 * - slot 09: 0x8021A684 drcagewith_getExtraSize stub=const 52 ref=getExtraSize (stub)
 * - slot 10: 0x8021A62C drcagewith_setScale ref=setScale
 *
 * Reference-only hints:
 * - reference DLL name: DR_CageWith
 */

#if 0
enum dll_026C_DR_CageWith_slot {
    DRCAGEWITH_INITIALISE = 0,
    DRCAGEWITH_RELEASE = 1,
    DRCAGEWITH_INIT = 3,
    DRCAGEWITH_UPDATE = 4,
    DRCAGEWITH_HITDETECT = 5,
    DRCAGEWITH_RENDER = 6,
    DRCAGEWITH_FREE = 7,
    DRCAGEWITH_SLOT_08 = 8,
    DRCAGEWITH_GETEXTRASIZE = 9,
    DRCAGEWITH_SETSCALE = 10,
};
#endif
