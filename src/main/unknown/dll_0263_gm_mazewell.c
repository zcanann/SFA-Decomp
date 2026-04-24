/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0263
 * Suggested family name: GM_MazeWell
 * Output path: src/main/unknown/dll_0263_gm_mazewell.c
 * EN descriptor: 0x8032A788 gGmMazeWellObjDescriptor
 *
 * Retail object defs:
 * - 0x0436 GM_MazeWell: def=0x042A, class=0x0030, placements=unknown
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 03: 0x80218E90 gmmazewell_init ref=init
 * - slot 04: 0x80218C28 gmmazewell_update ref=update
 * - slot 06: 0x80218C04 gmmazewell_render ref=render
 * - slot 07: 0x80218BD0 gmmazewell_free ref=free
 * - slot 09: 0x80218BC8 gmmazewell_getExtraSize stub=const 8 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: GM_MazeWell
 */

#if 0
enum dll_0263_GM_MazeWell_slot {
    GMMAZEWELL_INIT = 3,
    GMMAZEWELL_UPDATE = 4,
    GMMAZEWELL_RENDER = 6,
    GMMAZEWELL_FREE = 7,
    GMMAZEWELL_GETEXTRASIZE = 9,
};
#endif
