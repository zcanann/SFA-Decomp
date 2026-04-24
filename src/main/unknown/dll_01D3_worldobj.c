/*
 * Reference-backed recovery packet.
 *
 * This file is intentionally not wired into the build yet.
 * It exists as a makeshift source-file boundary for object/DLL recovery work.
 *
 * DLL ID: 0x01D3
 * Suggested family name: WORLDobj
 * Output path: src/main/unknown/dll_01D3_worldobj.c
 * EN descriptor: 0x8032A2D8 gWorldObjObjDescriptor
 *
 * EN slot map with reference-backed names by slot index:
 * - slot 00: 0x8020F210 worldobj_initialise stub=blr ref=initialise (stub)
 * - slot 01: 0x8020F20C worldobj_release stub=blr ref=release (stub)
 * - slot 03: 0x8020ECE8 worldobj_init ref=init
 * - slot 04: 0x8020DFA8 worldobj_update ref=update
 * - slot 05: 0x8020DFA4 worldobj_hitDetect stub=blr ref=hitDetect (stub)
 * - slot 06: 0x8020DD9C worldobj_render ref=render
 * - slot 07: 0x8020DD38 worldobj_free ref=free
 * - slot 08: 0x8020DD18 worldobj_func08 ref=slot08
 * - slot 09: 0x8020DD10 worldobj_getExtraSize stub=const 644 ref=getExtraSize (stub)
 *
 * Reference-only hints:
 * - reference DLL name: WORLDobj
 */

#if 0
enum dll_01D3_WORLDobj_slot {
    WORLDOBJ_INITIALISE = 0,
    WORLDOBJ_RELEASE = 1,
    WORLDOBJ_INIT = 3,
    WORLDOBJ_UPDATE = 4,
    WORLDOBJ_HITDETECT = 5,
    WORLDOBJ_RENDER = 6,
    WORLDOBJ_FREE = 7,
    WORLDOBJ_SLOT_08 = 8,
    WORLDOBJ_GETEXTRASIZE = 9,
};
#endif
