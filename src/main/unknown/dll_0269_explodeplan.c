/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0269
 * Suggested family name: ExplodePlan
 * Output path: src/main/unknown/dll_0269_explodeplan.c
 * EN descriptor: 0x8032A8C0 gExplodePlanObjDescriptor
 *
 * Retail object defs:
 * - 0x048D ExplodePlan: def=0x0778, class=0x0030, placements=unknown
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x8021A138 explodeplan_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x8021A134 explodeplan_release stub=blr ref=release (stub)
 * - slot 03: 0x8021A0C0 explodeplan_init ref=init
 * - slot 04: 0x8021A050 explodeplan_update ref=update
 * - slot 05: 0x8021A04C explodeplan_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x8021A01C explodeplan_render ref=render
 * - slot 07: 0x8021A018 explodeplan_free stub=blr ref=free (stub)
 * - slot 08: 0x8021A010 explodeplan_func08 stub=const 0
 * - slot 09: 0x8021A008 explodeplan_getExtraSize stub=const 4 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: ExplodePlan
 */

#if 0
enum dll_0269_ExplodePlan_slot {
    EXPLODEPLAN_INITIALISE = 0,
    EXPLODEPLAN_RELEASE = 1,
    EXPLODEPLAN_INIT = 3,
    EXPLODEPLAN_UPDATE = 4,
    EXPLODEPLAN_HITDETECT = 5,
    EXPLODEPLAN_RENDER = 6,
    EXPLODEPLAN_FREE = 7,
    EXPLODEPLAN_SLOT_08 = 8,
    EXPLODEPLAN_GETEXTRASIZE = 9,
};
#endif
