/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x0265
 * Suggested family name: DR_Creator
 * Output path: src/main/unknown/dll_0265_dr_creator.c
 * EN descriptor: 0x8032A878 gDrCreatorObjDescriptor
 *
 * Retail object defs:
 * - 0x0450 DR_Creator: def=0x043F, class=0x0037, placements=unknown
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x8021A004 drcreator_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x8021A000 drcreator_release stub=blr ref=release (stub)
 * - slot 03: 0x80219F4C drcreator_init ref=init
 * - slot 04: 0x80219C70 drcreator_update ref=update
 * - slot 05: 0x80219C6C drcreator_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x80219C68 drcreator_render stub=blr ref=render (stub)
 * - slot 07: 0x80219C64 drcreator_free stub=blr ref=free (stub)
 * - slot 08: 0x80219C5C drcreator_func08 stub=const 0
 * - slot 09: 0x80219C54 drcreator_getExtraSize stub=const 28 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: DR_Creator
 */

#if 0
enum dll_0265_DR_Creator_slot {
    DRCREATOR_INITIALISE = 0,
    DRCREATOR_RELEASE = 1,
    DRCREATOR_INIT = 3,
    DRCREATOR_UPDATE = 4,
    DRCREATOR_HITDETECT = 5,
    DRCREATOR_RENDER = 6,
    DRCREATOR_FREE = 7,
    DRCREATOR_SLOT_08 = 8,
    DRCREATOR_GETEXTRASIZE = 9,
};
#endif
